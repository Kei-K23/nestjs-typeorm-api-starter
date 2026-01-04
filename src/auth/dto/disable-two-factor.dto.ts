import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class DisableTwoFactorDto {
  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required to disable 2FA' })
  @ApiProperty({ description: 'User password' })
  password: string;
}
