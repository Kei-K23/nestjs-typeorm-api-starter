import { PartialType } from '@nestjs/swagger';
import { CreateUserDto } from 'src/user/dto/create-user.dto';

export class UpdateProfileDto extends PartialType(CreateUserDto) {}
