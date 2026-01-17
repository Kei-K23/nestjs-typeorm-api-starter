import {
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import { CreateUserDto } from '../dto/create-user.dto';
import { FilterUserDto } from '../dto/filter-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { S3ClientUtils } from 'src/common/utils/s3-client.utils';
import { Role } from 'src/auth/entities/role.entity';

@Injectable()
export class UserService {
  private readonly logger = new Logger(UserService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    private s3ClientUtils: S3ClientUtils,
  ) {}

  async create(createUserDto: CreateUserDto) {
    // Check if user with same email already exists
    const existingUser = await this.userRepository.findOne({
      where: { email: createUserDto.email },
    });

    if (existingUser) {
      throw new ConflictException(
        `User with email '${createUserDto.email}' already exists`,
      );
    }

    // Check if roleId is provided and exists
    if (createUserDto.roleId) {
      const role = await this.roleRepository.findOne({
        where: { id: createUserDto.roleId },
      });
      if (!role) {
        throw new NotFoundException(
          `Role with ID '${createUserDto.roleId}' not found`,
        );
      }
    }

    const user = this.userRepository.create({
      ...createUserDto,
    });
    const savedUser = await this.userRepository.save(user);
    this.logger.log(`User created with ID: ${savedUser.id}`);

    return savedUser;
  }

  async findAll(filter: FilterUserDto) {
    const { getAll, limit, page } = filter;
    const skip = (page - 1) * limit;

    const qb = this.userRepository
      .createQueryBuilder('user')
      .leftJoinAndSelect('user.role', 'role')
      .orderBy('user.createdAt', 'DESC');

    if (!getAll) {
      qb.skip(skip).take(limit);
    }

    if (filter.search) {
      qb.andWhere('(user.fullName ILIKE :term OR user.email ILIKE :term)', {
        term: `%${filter.search}%`,
      });
    }

    if (filter.roleId) {
      qb.andWhere('user.roleId = :roleId', { roleId: filter.roleId });
    }

    if (filter.isBanned !== undefined) {
      qb.andWhere('user.isBanned = :isBanned', { isBanned: filter.isBanned });
    }

    const [data, total] = await qb.getManyAndCount();

    // Add presigned URL to each user
    const usersWithPresignedUrl = await Promise.all(
      data.map(async (user) => {
        user.profileImageUrl =
          (await this.s3ClientUtils.generatePresignedUrl(
            user.profileImageUrl || '',
          )) || '';
        return user;
      }),
    );

    return {
      data: usersWithPresignedUrl,
      total,
      page,
      limit,
    };
  }

  async findOne(id: string) {
    const user = await this.userRepository.findOne({
      where: { id },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
      ],
    });
    if (!user) {
      throw new NotFoundException(`User with ID '${id}' not found`);
    }

    // Add presigned URL to user
    user.profileImageUrl =
      (await this.s3ClientUtils.generatePresignedUrl(
        user.profileImageUrl || '',
      )) || '';

    return user;
  }

  async update(id: string, updateUserDto: UpdateUserDto) {
    // Check if user exists
    const existingUser = await this.userRepository.findOne({ where: { id } });

    if (!existingUser) {
      throw new NotFoundException(`User with ID '${id}' not found`);
    }

    // If email is being updated, check for duplicates
    if (updateUserDto.email && updateUserDto.email !== existingUser.email) {
      const duplicateUser = await this.userRepository.findOne({
        where: { email: updateUserDto.email },
      });
      if (duplicateUser) {
        this.logger.warn(
          `User with email '${updateUserDto.email}' already exists`,
        );
        throw new ConflictException(
          `User with email '${updateUserDto.email}' already exists`,
        );
      }
    }

    // Check if roleId is provided and exists
    if (updateUserDto.roleId) {
      const role = await this.roleRepository.findOne({
        where: { id: updateUserDto.roleId },
      });
      if (!role) {
        this.logger.warn(`Role with ID '${updateUserDto.roleId}' not found`);
        throw new NotFoundException(
          `Role with ID '${updateUserDto.roleId}' not found`,
        );
      }
    }

    if (updateUserDto.profileImageUrl) {
      const updatedUserImageKey = this.s3ClientUtils.getKeyFromPresignedUrl(
        updateUserDto.profileImageUrl || '',
      );

      if (updatedUserImageKey) {
        if (updatedUserImageKey !== existingUser.profileImageUrl) {
          if (existingUser.profileImageUrl) {
            await this.s3ClientUtils.deleteObject(existingUser.profileImageUrl);
          }
        }
        updateUserDto.profileImageUrl = updatedUserImageKey || '';
      }
    }
    // Update the user
    const updatedUser = await this.userRepository.preload({
      id,
      ...updateUserDto,
    });

    if (!updatedUser) {
      this.logger.warn(`User with ID '${id}' not found`);
      throw new NotFoundException(`User with ID '${id}' not found`);
    }

    if (updateUserDto.password) {
      updatedUser.password = updateUserDto.password;
    }

    const savedUser = await this.userRepository.save(updatedUser);
    this.logger.log(`User updated with ID: ${savedUser.id}`);

    return savedUser;
  }

  async remove(id: string) {
    const user = await this.findOne(id);
    if (user.profileImageUrl) {
      await this.s3ClientUtils.deleteObject(user.profileImageUrl);
    }

    await this.userRepository.remove(user);
    this.logger.log(`User with ID '${id}' has been successfully deleted`);

    return {
      message: `User with ID '${id}' has been successfully deleted`,
    };
  }
}
