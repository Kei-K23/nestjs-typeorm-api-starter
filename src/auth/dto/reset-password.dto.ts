import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class ResetPasswordDto {
  @IsString({ message: 'Access Token must be a string' })
  @IsNotEmpty({ message: 'Access Token is required' })
  @ApiProperty({ description: 'Access token' })
  accessToken: string;

  @IsString({ message: 'New password must be a string' })
  @IsNotEmpty({ message: 'New password is required' })
  @MinLength(6, { message: 'New password must be at least 6 characters long' })
  @ApiProperty({ description: 'New password' })
  newPassword: string;
}
