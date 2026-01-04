import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsUUID } from 'class-validator';

export class VerifyPasswordResetOTPCodeDto {
  @IsUUID()
  @IsString()
  @IsNotEmpty({ message: 'User ID is required' })
  @ApiProperty({ description: 'User ID' })
  userId: string;

  @IsString({ message: 'Verification code must be a string' })
  @IsNotEmpty({ message: 'Verification code is required' })
  @ApiProperty({ description: 'Verification code' })
  code: string;
}
