import {
  Body,
  Controller,
  Post,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  UploadedFiles,
  ValidationPipe,
  UsePipes,
  BadRequestException,
  UnauthorizedException,
  Req,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { FileInterceptor, FilesInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { UploadFileDto } from '../dto/upload-file.dto';
import { S3ClientUtils } from '../utils/s3-client.utils';
import { ResponseUtil } from '../utils/response.util';
import { randomUUID, createHmac, createHash } from 'crypto';
import { Request } from 'express';

@Controller('api/common')
@UseGuards(JwtAuthGuard)
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
export class CommonUploadController {
  constructor(
    private readonly s3: S3ClientUtils,
    private readonly configService: ConfigService,
  ) {}

  private verifySignature(
    req: Request,
    dto: UploadFileDto,
    file?: Express.Multer.File,
    files?: Express.Multer.File[],
  ) {
    const signature = (req.headers['x-signature'] as string) || '';
    const timestampHeader = (req.headers['x-timestamp'] as string) || '';
    const secret = this.configService.get<string>('APP_KEY') || '';
    if (!signature || !timestampHeader || !secret) {
      throw new UnauthorizedException('Invalid signature');
    }
    const ts =
      timestampHeader.length >= 12
        ? Number(timestampHeader)
        : Number(timestampHeader) * 1000;
    if (!Number.isFinite(ts)) {
      throw new UnauthorizedException('Invalid signature');
    }
    const now = Date.now();
    if (Math.abs(now - ts) > 120000) {
      throw new UnauthorizedException('Signature expired');
    }
    const dtoHash = createHash('sha256')
      .update(
        JSON.stringify({
          folder: dto.folder || '',
        }),
      )
      .digest('hex');
    const fileHashes: string[] = [];
    if (file?.buffer) {
      fileHashes.push(createHash('sha256').update(file.buffer).digest('hex'));
    }
    if (Array.isArray(files)) {
      for (const f of files) {
        if (f?.buffer) {
          fileHashes.push(createHash('sha256').update(f.buffer).digest('hex'));
        }
      }
    }
    const canonical = [
      req.method,
      dto.folder,
      String(ts),
      dtoHash,
      fileHashes.join('.'),
    ].join('\n');
    const expected = createHmac('sha256', secret)
      .update(canonical)
      .digest('hex');
    if (expected !== signature) {
      throw new UnauthorizedException('Invalid signature');
    }
  }

  @Post('upload')
  @UseInterceptors(
    FileInterceptor('file', {
      storage: memoryStorage(),
      limits: { fileSize: 10 * 1024 * 1024 },
      fileFilter: (req, file, cb) => {
        if (!file.mimetype)
          return cb(new BadRequestException('Invalid file'), false);
        cb(null, true);
      },
    }),
  )
  async upload(
    @UploadedFile() file: Express.Multer.File,
    @Body() dto: UploadFileDto,
    @Req() req: Request,
  ) {
    this.verifySignature(req, dto, file);
    if (!file) {
      throw new BadRequestException('File is required');
    }

    const folder = dto.folder?.trim() || 'uploads';
    const original = file.originalname?.trim() || 'file';
    const sanitized = original.replace(/[^a-zA-Z0-9_.-]/g, '_');
    const key = dto.filenameOverride?.trim() || `${randomUUID()}-${sanitized}`;

    try {
      const res = await this.s3.uploadFile({
        key,
        body: file.buffer,
        contentType: file.mimetype,
        path: folder,
        metadata: { filename: original },
      });

      if (!res.success) {
        throw new BadRequestException(res.error || 'Upload failed');
      }

      const signedUrl = dto.generateSignedUrl
        ? await this.s3.generatePresignedUrl(res.key!)
        : null;

      return ResponseUtil.created(
        {
          key: res.key,
          url: signedUrl,
          size: file.size,
          mimeType: file.mimetype,
          filename: original,
        },
        'File uploaded successfully',
      );
    } catch (error) {
      console.log(error, ' image upload failed ');
      throw new BadRequestException(error?.message || 'Upload failed');
    }
  }

  @Post('upload/multi')
  @UseInterceptors(
    FilesInterceptor('files', 20, {
      storage: memoryStorage(),
      limits: { fileSize: 10 * 1024 * 1024 },
      fileFilter: (req, file, cb) => {
        if (!file.mimetype)
          return cb(new BadRequestException('Invalid file'), false);
        cb(null, true);
      },
    }),
  )
  async uploadMany(
    @UploadedFiles() files: Express.Multer.File[],
    @Body() dto: UploadFileDto,
    @Req() req: Request,
  ) {
    this.verifySignature(req, dto, undefined, files);
    if (!files || files.length === 0) {
      throw new BadRequestException('Files are required');
    }

    const folder = dto.folder?.trim() || 'uploads';

    const uploaded: Array<{
      key: string | undefined;
      url: string | null;
      size: number;
      mimeType: string;
      filename: string;
    }> = [];
    const failed: Array<{ filename: string; error: string }> = [];

    for (const file of files) {
      const original = file.originalname?.trim() || 'file';
      const sanitized = original.replace(/[^a-zA-Z0-9_.-]/g, '_');
      const key = `${randomUUID()}-${sanitized}`;

      const res = await this.s3.uploadFile({
        key,
        body: file.buffer,
        contentType: file.mimetype,
        path: folder,
        metadata: { filename: original },
      });

      if (!res.success) {
        failed.push({
          filename: original,
          error: res.error || 'Upload failed',
        });
        continue;
      }

      const signedUrl = dto.generateSignedUrl
        ? await this.s3.generatePresignedUrl(res.key!)
        : null;

      uploaded.push({
        key: res.key,
        url: signedUrl,
        size: file.size,
        mimeType: file.mimetype,
        filename: original,
      });
    }

    if (uploaded.length === 0) {
      throw new BadRequestException(failed[0]?.error || 'All uploads failed');
    }

    return ResponseUtil.created(
      { uploaded, failed },
      'Files uploaded successfully',
    );
  }
}
