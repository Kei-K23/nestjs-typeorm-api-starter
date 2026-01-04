import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsOptional, IsString } from 'class-validator';

export class UploadFileDto {
  @IsOptional()
  @IsString()
  @ApiProperty({
    description: 'Folder path to upload the file',
    required: false,
  })
  folder?: string;

  @IsOptional()
  @IsString()
  @ApiProperty({
    description: 'Override the filename of the uploaded file',
    required: false,
  })
  filenameOverride?: string;

  @IsOptional()
  @IsBoolean()
  @ApiProperty({
    description: 'Generate a signed URL for the uploaded file',
    required: false,
  })
  generateSignedUrl?: boolean;
}
