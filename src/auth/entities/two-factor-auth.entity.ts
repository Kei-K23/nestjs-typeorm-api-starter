import {
  Entity,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  BeforeInsert,
  BeforeUpdate,
  PrimaryColumn,
} from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import { User } from 'src/user/entities/user.entity';

export enum TwoFactorAuthType {
  EMAIL = 'email',
}

export enum TwoFactorAuthStatus {
  PENDING = 'pending',
  VERIFIED = 'verified',
  EXPIRED = 'expired',
  USED = 'used',
}

@Entity('two_factor_auth')
export class TwoFactorAuth {
  @PrimaryColumn('uuid')
  id: string;

  @Column()
  userId: string;

  @ManyToOne(() => User, (user) => user.twoFactorAuth)
  @JoinColumn({ name: 'userId' })
  user: User;

  @Column({
    type: 'enum',
    enum: TwoFactorAuthType,
    default: TwoFactorAuthType.EMAIL,
  })
  type: TwoFactorAuthType;

  @Column({ length: 6 })
  code: string;

  @Column({
    type: 'enum',
    enum: TwoFactorAuthStatus,
    default: TwoFactorAuthStatus.PENDING,
  })
  status: TwoFactorAuthStatus;

  @Column()
  expiresAt: Date;

  @Column({ nullable: true })
  verifiedAt: Date;

  @Column({ nullable: true })
  ipAddress: string;

  @Column({ nullable: true })
  userAgent: string;

  @Column({ default: 0 })
  attempts: number;

  @Column({ default: 3 })
  maxAttempts: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @BeforeInsert()
  @BeforeUpdate()
  generateUUID() {
    if (!this.id) {
      this.id = uuidv4();
    }
  }
}
