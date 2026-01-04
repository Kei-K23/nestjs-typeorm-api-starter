import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsNotEmpty,
  MinLength,
  MaxLength,
  IsOptional,
  IsArray,
} from 'class-validator';

export class CreateRoleDto {
  @IsString({ message: 'Role name must be a string' })
  @IsNotEmpty({ message: 'Role name is required' })
  @MinLength(2, { message: 'Role name must be at least 2 characters long' })
  @MaxLength(50, { message: 'Role name must not exceed 50 characters' })
  @ApiProperty({ description: 'Role name' })
  name: string;

  @IsOptional()
  @IsString({ message: 'Description must be a string' })
  @MaxLength(255, { message: 'Description must not exceed 255 characters' })
  @ApiProperty({ description: 'Role description', required: false })
  description?: string;

  @IsArray({ message: 'Permission IDs must be an array' })
  @IsString({ each: true, message: 'Permission ID must be a string' })
  @ApiProperty({ description: 'Array of permission IDs', type: [String] })
  permissionIds: string[];
}
