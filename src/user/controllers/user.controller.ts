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
} from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/auth/guards/permissions.guard';
import { UserService } from '../services/user.service';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { LogActivity } from 'src/activity-log/decorators/log-activity.decorator';
import { ActivityAction } from 'src/activity-log/entities/user-activity-log.entity';
import { User } from '../entities/user.entity';
import { CreateUserDto } from '../dto/create-user.dto';
import { ResponseUtil } from 'src/common/utils/response.util';
import { FilterUserDto } from '../dto/filter-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';

@Controller('api/users')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class UserController {
  constructor(private readonly userService: UserService) {}

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
  async create(@Body() createUserDto: CreateUserDto) {
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
  async update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
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
