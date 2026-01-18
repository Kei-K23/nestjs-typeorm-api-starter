import {
  Controller,
  ValidationPipe,
  UsePipes,
  UseGuards,
  Post,
  Body,
  Get,
  Query,
  Param,
  Patch,
  Delete,
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { JwtAuthGuard } from 'src/v1/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/v1/auth/guards/permissions.guard';
import { UserService } from '../services/user.service';
import { RequirePermissions } from 'src/v1/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/v1/auth/entities/permission.entity';
import { LogActivity } from 'src/v1/activity-log/decorators/log-activity.decorator';
import { ActivityAction } from 'src/v1/activity-log/entities/user-activity-log.entity';
import { User } from '../entities/user.entity';
import { CreateUserDto } from '../dto/create-user.dto';
import { ResponseUtil } from 'src/common/utils/response.util';
import { FilterUserDto } from '../dto/filter-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { S3ClientUtils } from 'src/common/utils/s3-client.utils';
import { randomUUID } from 'crypto';

@Controller('api/v1/users')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class UserController {
  constructor(
    private readonly userService: UserService,
    private readonly s3ClientUtils: S3ClientUtils,
  ) {}

  @Post()
  @RequirePermissions({
    module: PermissionModule.USERS,
    permission: 'create',
  })
  @LogActivity({
    action: ActivityAction.CREATE,
    description: 'User created successfully',
    resourceType: 'user',
    getResourceId: (result: User) => result.id?.toString(),
  })
  @UseInterceptors(
    FileInterceptor('profileImage', {
      storage: memoryStorage(),
      limits: { fileSize: 10 * 1024 * 1024 },
      fileFilter: (_req, file, cb) => {
        if (!file?.mimetype) return cb(null, false);
        cb(null, true);
      },
    }),
  )
  async create(
    @UploadedFile() file: Express.Multer.File,
    @Body() createUserDto: CreateUserDto,
  ) {
    if (file) {
      const original = file.originalname?.trim() || 'profile';
      const sanitized = original.replace(/[^a-zA-Z0-9_.-]/g, '_');
      const key = `${randomUUID()}-${sanitized}`;
      const res = await this.s3ClientUtils.uploadFile({
        key,
        body: file.buffer,
        contentType: file.mimetype,
        path: 'users/profile',
        metadata: { filename: original },
      });
      if (res.success && res.key) {
        createUserDto.profileImageUrl = res.key;
      }
    }
    const user = await this.userService.create(createUserDto);
    return ResponseUtil.created(user, 'User created successfully');
  }

  @Get()
  async findAll(@Query() filters: FilterUserDto) {
    const result = await this.userService.findAll(filters);

    if (filters.getAll) {
      return ResponseUtil.success(
        result.data,
        'All users retrieved successfully',
      );
    }

    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'Users retrieved successfully',
    );
  }

  @Get('/:id')
  async findOne(@Param('id') id: string) {
    const user = await this.userService.findOne(id);
    return ResponseUtil.success(
      user,
      `User retrieved by ID ${id} successfully`,
    );
  }

  @Patch('/:id')
  @RequirePermissions({
    module: PermissionModule.USERS,
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'User updated successfully',
    resourceType: 'user',
    getResourceId: (result: User) => result.id?.toString(),
  })
  @UseInterceptors(
    FileInterceptor('profileImage', {
      storage: memoryStorage(),
      limits: { fileSize: 10 * 1024 * 1024 },
      fileFilter: (_req, file, cb) => {
        if (!file?.mimetype) return cb(null, false);
        cb(null, true);
      },
    }),
  )
  async update(
    @Param('id') id: string,
    @UploadedFile() file: Express.Multer.File,
    @Body() updateUserDto: UpdateUserDto,
  ) {
    if (file) {
      const original = file.originalname?.trim() || 'profile';
      const sanitized = original.replace(/[^a-zA-Z0-9_.-]/g, '_');
      const key = `${randomUUID()}-${sanitized}`;
      const res = await this.s3ClientUtils.uploadFile({
        key,
        body: file.buffer,
        contentType: file.mimetype,
        path: 'users/profile',
        metadata: { filename: original },
      });
      if (res.success && res.key) {
        updateUserDto.profileImageUrl = res.key;
      }
    }
    const user = await this.userService.update(id, updateUserDto);
    return ResponseUtil.updated(user, 'User updated successfully');
  }

  @Delete('/:id')
  @RequirePermissions({
    module: PermissionModule.USERS,
    permission: 'delete',
  })
  @LogActivity({
    action: ActivityAction.DELETE,
    description: 'User deleted successfully',
    resourceType: 'user',
    getResourceId: (params: { id: string }) => params.id,
  })
  async remove(@Param('id') id: string) {
    const result = await this.userService.remove(id);
    return ResponseUtil.success(result, 'User deleted successfully');
  }
}
