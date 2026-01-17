import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { ConfigService } from '@nestjs/config';
import { User } from 'src/user/entities/user.entity';
import { RefreshToken } from '../entities/refresh-token.entity';
import { JwtPayload } from '../interfaces/user.interface';
import {
  ActivityAction,
  UserActivityLog,
} from 'src/activity-log/entities/user-activity-log.entity';
import { Request } from 'express';
import { parseUserAgent } from 'src/common/utils/user-agent.util';
import { TwoFactorService } from './two-factor.service';
import { LoginDto } from '../dto/login.dto';
import { UpdateProfileDto } from '../dto/update-profile.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { S3ClientUtils } from 'src/common/utils/s3-client.utils';
import { ForgotPasswordSendOTPDto } from '../dto/forgot-password-send-otp.dto';
import { EmailServiceUtils } from 'src/common/utils/email-service.utils';
import * as crypto from 'crypto';
import {
  CacheKey,
  CacheKeyService,
  CacheKeyStatus,
} from '../entities/cache-key.entity';
import { VerifyPasswordResetOTPCodeDto } from '../dto/verify-password-reset-otp-code.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(RefreshToken)
    private refreshTokenRepository: Repository<RefreshToken>,
    @InjectRepository(UserActivityLog)
    private userActivityLogRepository: Repository<UserActivityLog>,
    @InjectRepository(CacheKey)
    private cacheKeyRepository: Repository<CacheKey>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private twoFactorService: TwoFactorService,
    private s3ClientUtils: S3ClientUtils,
    private emailServiceUtils: EmailServiceUtils,
  ) {}

  async validateUser(email: string, plainPassword: string) {
    const user = await this.userRepository.findOne({
      where: { email },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
      ],
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    if (!(await bcrypt.compare(plainPassword, user.password))) {
      throw new UnauthorizedException('Invalid password');
    }
    const { password, ...result } = user;
    void password;
    return result;
  }

  async validateUserById(id: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: { id },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
      ],
    });
  }

  async login(loginDto: LoginDto, request: Request) {
    const user = await this.validateUser(loginDto.email, loginDto.password);

    // Check if 2FA is enabled for this user
    const is2FAEnabled = await this.twoFactorService.isTwoFactorEnabled(
      user.id,
    );

    if (is2FAEnabled) {
      await this.twoFactorService.sendVerificationCode(user.id);

      return {
        requiresTwoFactor: true,
        userId: user.id,
        message: 'Two-factor authentication code sent to your email',
      };
    }

    const fullUser = await this.userRepository.findOne({
      where: { id: user.id },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
      ],
    });

    if (!fullUser) {
      this.logger.warn(`User with ID '${user.id}' not found`);
      throw new UnauthorizedException(`User with ID '${user.id}' not found`);
    }

    return this.completeLogin(fullUser, request);
  }

  async verifyTwoFactorAndLogin(
    userId: string,
    code: string,
    request: Request,
  ) {
    // Validate the 2FA code
    const isValidCode = await this.twoFactorService.validateLoginCode(
      userId,
      code,
    );

    if (!isValidCode) {
      this.logger.warn(
        `Invalid or expired verification code for user with ID '${userId}'`,
      );
      throw new UnauthorizedException(
        `Invalid or expired verification code for user with ID '${userId}'`,
      );
    }

    const user = await this.userRepository.findOne({
      where: { id: userId },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
      ],
    });

    if (!user) {
      this.logger.warn(`User with ID '${userId}' not found`);
      throw new UnauthorizedException(`User with ID '${userId}' not found`);
    }

    // Complete the login process
    return this.completeLogin(user, request);
  }

  private async completeLogin(user: User, request: Request) {
    const payload: JwtPayload = {
      sub: user.id,
      userId: user.id,
      roleId: user.role.id,
    };

    const accessToken = this.jwtService.sign(payload);
    // Revoke all previous refresh token here
    await this.revokeAllUserTokens(user.id);

    const refreshToken = await this.generateRefreshToken(user.id);

    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      isActivityLog: true,
      action: ActivityAction.LOGIN,
      description: `User logged in successfully`,
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
    });
    await this.userActivityLogRepository.save(userActivityLog);

    await this.userRepository.update(user.id, {
      lastLoginAt: new Date().toISOString(),
    });

    return {
      accessToken,
      refreshToken,
      accessTokenExpiresAt: this.configService.get<number>(
        'JWT_EXPIRATION',
        172800000,
      ),
      refreshTokenExpiresAt: this.configService.get<number>(
        'JWT_REFRESH_EXPIRATION',
        2592000000,
      ),
      user: {
        id: user.id,
      },
    };
  }

  async refreshAccessToken(refreshTokenString: string) {
    const refreshToken = await this.refreshTokenRepository.findOne({
      where: { token: refreshTokenString, isRevoked: false },
      relations: [
        'user',
        'user.role',
        'user.role.rolePermissions',
        'user.role.rolePermissions.permission',
      ],
    });

    if (!refreshToken) {
      this.logger.warn(
        `Invalid refresh token '${refreshTokenString}' provided`,
      );
      throw new UnauthorizedException(
        `Invalid refresh token '${refreshTokenString}' provided`,
      );
    }

    if (refreshToken.expiresAt < new Date()) {
      // Revoke the refresh token
      refreshToken.isRevoked = true;
      await this.refreshTokenRepository.save(refreshToken);

      throw new UnauthorizedException(
        `Expired refresh token for user with ID '${refreshToken.user.id}'! Please login again`,
      );
    }

    const payload: JwtPayload = {
      sub: refreshToken.user.id,
      userId: refreshToken.user.id,
      roleId: refreshToken.user?.role?.id,
    };

    const accessToken = this.jwtService.sign(payload);
    this.logger.log(
      `User with ID '${refreshToken.user.id}' logged in successfully`,
    );

    return {
      accessToken,
      accessTokenExpiresAt: this.configService.get<number>(
        'JWT_EXPIRATION',
        172800000,
      ),
      user: {
        id: refreshToken.user.id,
      },
    };
  }

  async logout(refreshTokenString: string) {
    const refreshToken = await this.refreshTokenRepository.findOne({
      where: { token: refreshTokenString },
    });

    if (refreshToken) {
      refreshToken.isRevoked = true;
      await this.refreshTokenRepository.save(refreshToken);
    }
  }

  async revokeAllUserTokens(userId: string) {
    await this.refreshTokenRepository.update(
      { userId, isRevoked: false },
      { isRevoked: true },
    );
  }

  private async generateRefreshToken(userId: string): Promise<string> {
    const token = this.jwtService.sign(
      { sub: userId },
      {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get<number>(
          'JWT_REFRESH_EXPIRATION',
          2592000000,
        ),
      },
    );

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    const refreshToken = this.refreshTokenRepository.create({
      token,
      userId,
      expiresAt,
    });

    await this.refreshTokenRepository.save(refreshToken);
    return token;
  }

  async updateProfile(
    userId: string,
    updateProfileDto: UpdateProfileDto,
    request: Request,
  ) {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
      ],
    });

    if (!user) {
      this.logger.warn(`User with ID '${userId}' not found`);
      throw new NotFoundException(`User with ID '${userId}' not found`);
    }

    // Delete previous profile image from S3
    if (
      updateProfileDto.profileImageUrl &&
      updateProfileDto.profileImageUrl !== user.profileImageUrl
    ) {
      if (
        user.profileImageUrl &&
        (await this.s3ClientUtils.objectExists(user.profileImageUrl))
      ) {
        await this.s3ClientUtils.deleteObject(user.profileImageUrl);
      }
    }

    // Update user fields

    const updatedUser = await this.userRepository.preload({
      id: userId,
      ...updateProfileDto,
    });
    if (!updatedUser) {
      this.logger.warn(`User with ID '${userId}' not found`);
      throw new BadRequestException(`User with ID '${userId}' not found`);
    }

    if (updateProfileDto.password) {
      updatedUser.password = updateProfileDto.password;
    }

    const savedUser = await this.userRepository.save(updatedUser);

    // Log activity
    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.UPDATE,
      description: 'User profile updated successfully',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });
    await this.userActivityLogRepository.save(userActivityLog);

    const { password, ...result } = savedUser;
    void password;

    this.logger.log(`User with ID '${user.id}' profile updated successfully`);
    return result;
  }

  async changePassword(
    userId: string,
    changePasswordDto: ChangePasswordDto,
    request: Request,
  ): Promise<void> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      this.logger.warn(`User with ID '${userId}' not found`);
      throw new NotFoundException(`User with ID '${userId}' not found`);
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(
      changePasswordDto.currentPassword,
      user.password,
    );

    if (!isCurrentPasswordValid) {
      this.logger.warn(
        `User with ID '${userId}' provided incorrect current password`,
      );
      throw new BadRequestException(`Incorrect current password`);
    }

    // Update password
    user.password = changePasswordDto.newPassword;
    await this.userRepository.save(user);

    // Revoke all refresh tokens for security
    await this.revokeAllUserTokens(userId);

    // Log activity
    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.UPDATE,
      description: 'User password changed successfully',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });

    this.logger.log(`User with ID '${user.id}' password changed successfully`);
    await this.userActivityLogRepository.save(userActivityLog);
  }

  async deleteProfile(userId: string, request: Request): Promise<void> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      relations: ['refreshTokens', 'twoFactorAuth'],
    });

    if (!user) {
      this.logger.warn(`User with ID '${userId}' not found`);
      throw new NotFoundException(`User with ID '${userId}' not found`);
    }

    // Log activity before deletion
    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.DELETE,
      description: 'User account deleted successfully',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });
    await this.userActivityLogRepository.save(userActivityLog);

    // Revoke all refresh tokens
    await this.revokeAllUserTokens(userId);

    // Delete user profile image from S3 if it exists
    if (user.profileImageUrl) {
      if (
        user.profileImageUrl &&
        (await this.s3ClientUtils.objectExists(user.profileImageUrl))
      ) {
        await this.s3ClientUtils.deleteObject(user.profileImageUrl);
      }
    }

    // Delete user
    this.logger.log(`User with ID '${user.id}' account deleted successfully`);
    await this.userRepository.remove(user);
  }

  async passwordResetOTPSend(
    forgotPasswordSendOTP: ForgotPasswordSendOTPDto,
    request: Request,
  ) {
    const user = await this.userRepository.findOne({
      where: { email: forgotPasswordSendOTP.email },
    });

    if (!user) {
      this.logger.warn(
        `User with email '${forgotPasswordSendOTP.email}' not found`,
      );
      throw new NotFoundException(
        `User with email '${forgotPasswordSendOTP.email}' not found`,
      );
    }

    // Log activity
    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.FORGOT_PASSWORD_SEND_OTP,
      description: 'User send forgot password request',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });
    await this.userActivityLogRepository.save(userActivityLog);

    // Generate verification code
    const code = this.generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Create cache key record
    const cacheKey = this.cacheKeyRepository.create({
      userId: user.id,
      service: CacheKeyService.RESET_PASSWORD,
      code,
      expiresAt,
      status: CacheKeyStatus.PENDING,
      attempts: 0,
      maxAttempts: 3,
    });
    await this.cacheKeyRepository.save(cacheKey);

    // Send Forgot password reset code
    await this.emailServiceUtils.sendForgotPasswordResetCode({
      code,
      email: user.email,
      userName: user.fullName,
      fromUsername: this.configService.get<string>('EMAIL_FROM_NAME', ''),
      expiresIn: 10,
    });

    this.logger.log(
      `User with ID '${user.id}' send forgot password request successfully`,
    );
    return {
      userId: user.id,
    };
  }

  async verifyPasswordResetOTPCode(
    verifyPasswordResetOTPCode: VerifyPasswordResetOTPCodeDto,
  ) {
    const otpVerification = await this.cacheKeyRepository.findOne({
      where: {
        userId: verifyPasswordResetOTPCode.userId,
        service: CacheKeyService.RESET_PASSWORD,
        status: CacheKeyStatus.PENDING,
      },
    });

    if (!otpVerification) {
      this.logger.warn(
        `No pending otp verification found for user ID '${verifyPasswordResetOTPCode.userId}'`,
      );
      throw new BadRequestException('No pending otp verification found');
    }

    // Check if code has expired
    if (new Date() > otpVerification.expiresAt) {
      otpVerification.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(otpVerification);
      this.logger.warn(
        `Verification code for user ID '${verifyPasswordResetOTPCode.userId}' has expired`,
      );
      throw new BadRequestException('Verification code has expired');
    }

    // Check if max attempts reached
    if (otpVerification.attempts >= otpVerification.maxAttempts) {
      otpVerification.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(otpVerification);
      this.logger.warn(
        `Maximum verification attempts exceeded for user ID '${verifyPasswordResetOTPCode.userId}'`,
      );
      throw new BadRequestException('Maximum verification attempts exceeded');
    }

    // Increment attempts
    otpVerification.attempts += 1;

    // Verify code
    if (otpVerification.code !== verifyPasswordResetOTPCode.code) {
      await this.cacheKeyRepository.save(otpVerification);
      this.logger.warn(
        `Invalid verification code for user ID '${verifyPasswordResetOTPCode.userId}'`,
      );
      throw new BadRequestException('Invalid verification code');
    }

    // Mark as active
    otpVerification.status = CacheKeyStatus.VERIFIED;
    await this.cacheKeyRepository.save(otpVerification);

    const payload = {
      sub: verifyPasswordResetOTPCode.userId,
      userId: verifyPasswordResetOTPCode.userId,
      type: CacheKeyService.RESET_PASSWORD,
    };

    const accessToken = this.jwtService.sign(payload);

    this.logger.log(
      `User with ID '${verifyPasswordResetOTPCode.userId}' verified reset password request successfully`,
    );
    return {
      userId: verifyPasswordResetOTPCode.userId,
      accessToken,
    };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto, request: Request) {
    // Validate and decode access token
    try {
      await this.jwtService.verifyAsync(resetPasswordDto.accessToken);
    } catch {
      throw new UnauthorizedException('Access token verification failed');
    }

    const { userId, type } = this.jwtService.decode(
      resetPasswordDto.accessToken,
    );

    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      this.logger.warn(
        `User with ID '${userId}' not found after token verification`,
      );
      throw new NotFoundException(
        `User with ID '${userId}' not found after token verification`,
      );
    }

    if (type !== CacheKeyService.RESET_PASSWORD) {
      this.logger.warn(`Invalid access token type for user ID '${userId}'`);
      throw new BadRequestException(
        `Invalid access token type for user ID '${userId}'`,
      );
    }

    // Update password
    user.password = resetPasswordDto.newPassword;
    await this.userRepository.save(user);

    // Log activity
    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.CHANGE_PASSWORD,
      description: 'User password changed successfully',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });
    this.logger.log(`User with ID '${user.id}' changed password successfully`);
    await this.userActivityLogRepository.save(userActivityLog);
  }

  private generateVerificationCode(): string {
    return crypto.randomInt(100000, 999999).toString();
  }
}
