import {
  Body,
  Controller,
  Delete,
  Post,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  UploadedFiles,
  ValidationPipe,
  UsePipes,
  BadRequestException,
} from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { FileInterceptor, FilesInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { UploadFileDto } from '../dto/upload-file.dto';
import { S3ClientUtils } from '../utils/s3-client.utils';
import { ResponseUtil } from '../utils/response.util';
import { randomUUID } from 'crypto';
import { DeleteFileDto } from '../dto/delete-file.dto';

@Controller('api/common')
@UseGuards(JwtAuthGuard)
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
export class CommonUploadController {
  constructor(private readonly s3: S3ClientUtils) {}

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
  ) {
    if (!file) {
      throw new BadRequestException('File is required');
    }

    const folder = dto.folder?.trim() || 'uploads';
    const original = file.originalname?.trim() || 'file';
    const sanitized = original.replace(/[^a-zA-Z0-9_.-]/g, '_');
    const key = `${randomUUID()}-${sanitized}`;

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

      return ResponseUtil.created(
        {
          key: res.key,
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
  ) {
    if (!files || files.length === 0) {
      throw new BadRequestException('Files are required');
    }

    const folder = dto.folder?.trim() || 'uploads';

    const uploaded: Array<{
      key: string | undefined;
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

      uploaded.push({
        key: res.key,
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

  @Delete('upload')
  async deleteFile(@Body() dto: DeleteFileDto) {
    const key = dto.key?.trim();
    if (!key) {
      throw new BadRequestException('Key is required');
    }
    const exists = await this.s3.objectExists(key);
    if (!exists) {
      throw new BadRequestException('File not found');
    }
    const res = await this.s3.deleteObject(key);
    if (!res.success) {
      throw new BadRequestException(res.error || 'Delete failed');
    }
    return ResponseUtil.deleted('File deleted successfully');
  }
}
