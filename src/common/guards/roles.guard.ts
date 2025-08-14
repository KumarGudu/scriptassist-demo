import { Injectable, CanActivate, ExecutionContext, ForbiddenException, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  private readonly logger = new Logger(RolesGuard.name);

  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    
    // If no roles are required, allow access
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }
    
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    
    // Ensure user is authenticated
    if (!user) {
      this.logger.warn(`Unauthenticated access attempt to protected resource from IP: ${request.ip}`);
      throw new ForbiddenException('Authentication required');
    }
    
    // Validate user has required role
    if (!user.role) {
      this.logger.warn(`User ${user.id} has no role assigned`);
      throw new ForbiddenException('Access denied: No role assigned');
    }
    
    const hasRequiredRole = requiredRoles.includes(user.role);
    
    if (!hasRequiredRole) {
      this.logger.warn(
        `User ${user.email} (role: ${user.role}) attempted to access resource requiring roles: ${requiredRoles.join(', ')}`
      );
      throw new ForbiddenException('Access denied: Insufficient permissions');
    }
    
    return true;
  }
} 