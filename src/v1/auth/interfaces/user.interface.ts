import { User } from 'src/v1/user/entities/user.entity';

export type AuthenticatedUser = Omit<
  User,
  'password' | 'generateUUID' | 'hashPassword'
>;

export interface RequestWithUser extends Request {
  params: any;
  user: AuthenticatedUser;
}

export interface JwtPayload {
  sub: string;
  userId: string;
  roleId: string;
  iat?: number;
  exp?: number;
}
