import { Exclude } from 'class-transformer';
import { RefreshToken } from 'src/auth/entities/refresh-token.entity';
import { v4 as uuidv4 } from 'uuid';
import {
  Entity,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  BeforeUpdate,
  BeforeInsert,
  PrimaryColumn,
  Index,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { Role } from 'src/auth/entities/role.entity';
import { CacheKey } from 'src/auth/entities/cache-key.entity';

@Entity('users')
@Index(['email', 'fullName', 'phone'])
export class User {
  @PrimaryColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  fullName: string;

  @Column({ nullable: true, unique: true })
  phone: string;

  @Column({ nullable: true })
  @Exclude()
  password: string;

  @Column({ default: false })
  isBanned: boolean;

  @Column({ nullable: true })
  profileImageUrl: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt: Date;

  @Column({ default: false })
  twoFactorEnabled: boolean;

  @Column({ nullable: true })
  roleId: string;

  @ManyToOne(() => Role, (role) => role.users, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'roleId' })
  role: Role;

  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
  refreshTokens: RefreshToken[];

  @OneToMany(() => CacheKey, (cacheKey) => cacheKey.user)
  cacheKeys: CacheKey[];

  @BeforeInsert()
  generateUUID() {
    if (!this.id) {
      this.id = uuidv4();
    }
  }

  @BeforeInsert()
  @BeforeUpdate()
  async hashPassword() {
    if (
      this.password &&
      !/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(this.password)
    ) {
      const rounds = Number(process.env.AUTH_PASSWORD_SALT_ROUNDS ?? 10);
      this.password = await bcrypt.hash(this.password, rounds);
    }
  }
}
