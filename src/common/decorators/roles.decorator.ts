import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);

// Pre-defined role constants to prevent typos
export const USER_ROLES = {
  ADMIN: 'admin',
  USER: 'user',
  MODERATOR: 'moderator',
} as const;

export type UserRole = typeof USER_ROLES[keyof typeof USER_ROLES]; 