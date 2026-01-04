import {
  IsEmail,
  IsString,
  IsNotEmpty,
  MinLength,
  MaxLength,
  IsOptional,
  IsUUID,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  @ApiProperty({ description: 'User email address' })
  email: string;

  @IsString({ message: 'Full name must be a string' })
  @IsNotEmpty({ message: 'Full name is required' })
  @MinLength(2, { message: 'Full name must be at least 2 characters long' })
  @MaxLength(100, { message: 'Full name must not exceed 100 characters' })
  @ApiProperty({ description: 'User full name' })
  fullName: string;

  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @ApiProperty({ description: 'User password' })
  password: string;

  @IsOptional()
  @IsString({ message: 'Phone must be a string' })
  @ApiProperty({ description: 'User phone number', required: false })
  phone?: string;

  @IsOptional()
  @IsUUID('4', { message: 'Role ID must be a valid UUID' })
  @IsNotEmpty({ message: 'Role ID is required' })
  @ApiProperty({ description: 'User role ID', required: false })
  roleId?: string;

  @IsOptional()
  @IsString({ message: 'Profile image URL must be a string' })
  @ApiProperty({ description: 'User profile image URL', required: false })
  profileImageUrl?: string;
}
