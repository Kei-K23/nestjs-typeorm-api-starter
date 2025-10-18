import {
  S3Client,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class S3ClientUtils {
  private readonly logger = new Logger(S3ClientUtils.name);
  private readonly s3Client: S3Client;
  private readonly bucketName: string;

  constructor(private readonly configService: ConfigService) {
    const AWS_ACCESS_KEY_ID =
      this.configService.get<string>('AWS_ACCESS_KEY_ID')!;
    const AWS_SECRET_ACCESS_KEY = this.configService.get<string>(
      'AWS_SECRET_ACCESS_KEY',
    )!;
    const AWS_REGION = this.configService.get<string>('AWS_REGION')!;
    const AWS_BUCKET_NAME = this.configService.get<string>('AWS_BUCKET_NAME')!;

    this.bucketName = AWS_BUCKET_NAME;

    this.s3Client = new S3Client({
      region: AWS_REGION,
      credentials: {
        accessKeyId: AWS_ACCESS_KEY_ID,
        secretAccessKey: AWS_SECRET_ACCESS_KEY,
      },
    });
  }

  async generatePresignedUrl(
    key: string,
    expiresIn: number = 3600,
  ): Promise<string | null> {
    try {
      const command = new GetObjectCommand({
        Bucket: this.bucketName,
        Key: key,
      });

      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call
      const url = await getSignedUrl(this.s3Client, command, { expiresIn });
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return url;
    } catch (error: unknown) {
      const err = error as Error;
      this.logger.error(
        `Failed to generate download URL for ${key}: ${err.message}`,
        err.stack,
      );
      return null;
    }
  }

  async objectExists(key: string): Promise<boolean> {
    try {
      const command = new HeadObjectCommand({
        Bucket: this.bucketName,
        Key: key,
      });

      await this.s3Client.send(command);
      return true;
    } catch (error) {
      const err = error as Error;
      this.logger.error(
        `Failed to generate download URL for ${key}: ${err.message}`,
        err.stack,
      );
      return false;
    }
  }

  async uploadFile({
    key,
    body,
    contentType,
    path,
    metadata,
  }: {
    key: string;
    body: Buffer | Uint8Array | string;
    contentType?: string;
    path?: string;
    metadata?: Record<string, string>;
  }): Promise<{ success: boolean; key?: string; error?: string }> {
    try {
      const command = new PutObjectCommand({
        Bucket: this.bucketName,
        Key: `${path}/${key}`,
        Body: body,
        ContentType: contentType,
        Metadata: metadata,
      });

      await this.s3Client.send(command);

      this.logger.log(`Successfully uploaded file: ${key}`);
      return { success: true, key: `${path}/${key}` };
    } catch (error: unknown) {
      const err = error as Error;
      this.logger.error(
        `Failed to upload file ${key}: ${err.message}`,
        err.stack,
      );
      return { success: false, error: err.message, key: `${path}/${key}` };
    }
  }
  async deleteObject(
    key: string,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      const command = new DeleteObjectCommand({
        Bucket: this.bucketName,
        Key: key,
      });

      await this.s3Client.send(command);

      this.logger.log(`Successfully deleted file: ${key}`);
      return { success: true };
    } catch (error: unknown) {
      const err = error as Error;
      this.logger.error(
        `Failed to delete file ${key}: ${err.message}`,
        err.stack,
      );
      return { success: false, error: err.message };
    }
  }
}
