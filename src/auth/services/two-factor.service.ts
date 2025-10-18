import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  TwoFactorAuth,
  TwoFactorAuthType,
  TwoFactorAuthStatus,
} from '../entities/two-factor-auth.entity';
import { User } from 'src/user/entities/user.entity';
import * as crypto from 'crypto';
import { EmailServiceUtils } from 'src/common/utils/email-service.utils';

@Injectable()
export class TwoFactorService {
  private readonly logger = new Logger(TwoFactorService.name);

  constructor(
    @InjectRepository(TwoFactorAuth)
    private twoFactorRepository: Repository<TwoFactorAuth>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private emailServiceUtils: EmailServiceUtils,
  ) {}

  async enableTwoFactor(userId: string, email: string): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (user.email !== email) {
      throw new BadRequestException('Email does not match user account');
    }

    // Check if 2FA is already enabled
    const existing = await this.twoFactorRepository.findOne({
      where: {
        userId,
        type: TwoFactorAuthType.EMAIL,
        status: TwoFactorAuthStatus.VERIFIED,
      },
    });

    if (existing) {
      throw new BadRequestException(
        'Two-factor authentication is already enabled',
      );
    }

    // Generate verification code
    const code = this.generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Create 2FA record
    const twoFactor = this.twoFactorRepository.create({
      userId,
      type: TwoFactorAuthType.EMAIL,
      code,
      expiresAt,
      status: TwoFactorAuthStatus.PENDING,
      attempts: 0,
      maxAttempts: 3,
    });

    await this.twoFactorRepository.save(twoFactor);

    // Send verification email
    await this.emailServiceUtils.sendTwoFactorCode(
      email,
      code,
      user.fullName || user.email,
    );

    this.logger.log(`2FA verification code sent to user ${userId}`);
  }

  async verifyTwoFactor(userId: string, code: string): Promise<boolean> {
    const twoFactor = await this.twoFactorRepository.findOne({
      where: {
        userId,
        type: TwoFactorAuthType.EMAIL,
        status: TwoFactorAuthStatus.PENDING,
      },
      order: { createdAt: 'DESC' },
    });

    if (!twoFactor) {
      throw new BadRequestException(
        'No pending two-factor authentication found',
      );
    }

    // Check if code has expired
    if (new Date() > twoFactor.expiresAt) {
      twoFactor.status = TwoFactorAuthStatus.EXPIRED;
      await this.twoFactorRepository.save(twoFactor);
      throw new BadRequestException('Verification code has expired');
    }

    // Check if max attempts reached
    if (twoFactor.attempts >= twoFactor.maxAttempts) {
      twoFactor.status = TwoFactorAuthStatus.EXPIRED;
      await this.twoFactorRepository.save(twoFactor);
      throw new BadRequestException('Maximum verification attempts exceeded');
    }

    // Increment attempts
    twoFactor.attempts += 1;

    // Verify code
    if (twoFactor.code !== code) {
      await this.twoFactorRepository.save(twoFactor);
      throw new BadRequestException('Invalid verification code');
    }

    // Mark as active
    twoFactor.status = TwoFactorAuthStatus.VERIFIED;
    await this.twoFactorRepository.save(twoFactor);

    // Update user's 2FA status
    await this.userRepository.update(userId, { twoFactorEnabled: true });

    this.logger.log(`2FA enabled for user ${userId}`);
    return true;
  }

  async disableTwoFactor(userId: string, password: string): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    // Verify password (you'll need to implement password verification)
    // This is a placeholder - implement actual password verification
    if (!password) {
      throw new BadRequestException('Password is required to disable 2FA');
    }

    // Deactivate all active 2FA records
    await this.twoFactorRepository.update(
      { userId, status: TwoFactorAuthStatus.VERIFIED },
      { status: TwoFactorAuthStatus.EXPIRED },
    );

    // Update user's 2FA status
    await this.userRepository.update(userId, { twoFactorEnabled: false });

    this.logger.log(`2FA disabled for user ${userId}`);
  }

  async sendVerificationCode(userId: string): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    // Check if there's an active 2FA setup
    const existing = await this.twoFactorRepository.findOne({
      where: {
        userId,
        type: TwoFactorAuthType.EMAIL,
        status: TwoFactorAuthStatus.VERIFIED,
      },
    });

    if (existing) {
      throw new BadRequestException(
        'Two-factor verification code is already sent',
      );
    }

    // Generate new verification code
    const code = this.generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Create new verification record
    const twoFactor = this.twoFactorRepository.create({
      userId,
      type: TwoFactorAuthType.EMAIL,
      code,
      expiresAt,
      status: TwoFactorAuthStatus.PENDING,
      attempts: 0,
      maxAttempts: 3,
    });

    await this.twoFactorRepository.save(twoFactor);

    // Send verification email
    await this.emailServiceUtils.sendTwoFactorCode(
      user.email,
      code,
      user.fullName || user.email,
    );

    this.logger.log(`2FA verification code sent to user ${userId}`);
  }

  async validateLoginCode(userId: string, code: string): Promise<boolean> {
    const twoFactor = await this.twoFactorRepository.findOne({
      where: {
        userId,
        type: TwoFactorAuthType.EMAIL,
        status: TwoFactorAuthStatus.PENDING,
      },
      order: { createdAt: 'DESC' },
    });

    if (!twoFactor) {
      return false;
    }

    // Check if code has expired
    if (new Date() > twoFactor.expiresAt) {
      twoFactor.status = TwoFactorAuthStatus.EXPIRED;
      await this.twoFactorRepository.save(twoFactor);
      return false;
    }

    // Check if max attempts reached
    if (twoFactor.attempts >= twoFactor.maxAttempts) {
      twoFactor.status = TwoFactorAuthStatus.EXPIRED;
      await this.twoFactorRepository.save(twoFactor);
      return false;
    }

    // Increment attempts
    twoFactor.attempts += 1;

    // Verify code
    if (twoFactor.code !== code) {
      await this.twoFactorRepository.save(twoFactor);
      return false;
    }

    // Mark as used
    twoFactor.status = TwoFactorAuthStatus.USED;
    await this.twoFactorRepository.save(twoFactor);

    return true;
  }

  async isTwoFactorEnabled(userId: string): Promise<boolean> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    return user?.twoFactorEnabled || false;
  }

  private generateVerificationCode(): string {
    return crypto.randomInt(100000, 999999).toString();
  }
}
