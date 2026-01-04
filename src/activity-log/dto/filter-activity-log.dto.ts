import {
  IsOptional,
  IsEnum,
  IsString,
  IsDateString,
  IsBoolean,
} from 'class-validator';
import { ActivityAction } from '../entities/user-activity-log.entity';
import { PaginationFilterDto } from 'src/common/dto/pagination-filter.dto';
import { Transform } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';

export class FilterActivityLogDto extends PaginationFilterDto {
  @IsOptional()
  @IsString()
  @ApiProperty({ description: 'User ID', required: false })
  userId?: string;

  @IsOptional()
  @IsEnum(ActivityAction)
  @ApiProperty({
    description: 'Activity action',
    enum: ActivityAction,
    required: false,
  })
  action?: ActivityAction;

  @IsOptional()
  @IsBoolean()
  @Transform(({ value }) => {
    if (value === undefined || value === null) return undefined;
    if (value === 'true' || value === '1' || value === true) return true;
    if (value === 'false' || value === '0' || value === false) return false;
    return undefined;
  })
  @ApiProperty({
    description:
      'Filter by activity log. When true, return activity logs. When false, return audit logs.',
    required: false,
  })
  isActivityLog?: boolean;

  @IsOptional()
  @IsString()
  @ApiProperty({ description: 'Resource type', required: false })
  resourceType?: string;

  @IsOptional()
  @IsString()
  @ApiProperty({ description: 'Resource ID', required: false })
  resourceId?: string;

  @IsOptional()
  @IsString()
  @ApiProperty({ description: 'IP address', required: false })
  ipAddress?: string;

  @IsOptional()
  @IsString()
  @ApiProperty({ description: 'Device', required: false })
  device?: string;

  @IsOptional()
  @IsString()
  @ApiProperty({ description: 'Location', required: false })
  location?: string;

  @IsOptional()
  @IsDateString()
  @ApiProperty({ description: 'Start date', required: false })
  startDate?: string;

  @IsOptional()
  @IsDateString()
  @ApiProperty({ description: 'End date', required: false })
  endDate?: string;

  @IsOptional()
  @IsString()
  @ApiProperty({ description: 'Sort by', required: false })
  sortBy?: string = 'createdAt';

  @IsOptional()
  @IsString()
  @ApiProperty({ description: 'Sort order', required: false })
  sortOrder?: 'ASC' | 'DESC' = 'DESC';
}
