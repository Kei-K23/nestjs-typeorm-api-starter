import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { ActivityLogService } from '../services/activity-log.service';
import { FilterActivityLogDto } from '../dto/filter-activity-log.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { RequirePermissions } from 'src/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';

@Controller('/api/activity-logs')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ActivityLogController {
  constructor(private readonly activityLogService: ActivityLogService) {}

  @Get()
  @RequirePermissions({
    module: PermissionModule.ACTIVITY_LOGS,
    permission: 'read',
  })
  async findAll(@Query() filterDto: FilterActivityLogDto) {
    const result = await this.activityLogService.findAll(filterDto);

    if (filterDto.getAll) {
      return ResponseUtil.success(
        result.data,
        'All activity logs retrieved successfully',
      );
    }

    return ResponseUtil.paginated(
      result.data,
      result.total,
      filterDto.page || 1,
      filterDto.limit || 10,
      'Activity logs retrieved successfully',
    );
  }
}
