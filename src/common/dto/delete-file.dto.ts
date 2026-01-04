import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class DeleteFileDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty({ description: 'File key to delete' })
  key: string;

  @IsOptional()
  @IsString()
  @ApiProperty({ description: 'Folder path to delete the file from' })
  folder?: string;
}
