import { Injectable, ExecutionContext, UnauthorizedException, Logger } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Observable } from 'rxjs';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger(JwtAuthGuard.name);
  private readonly revokedTokens = new Set<string>(); // In production, use Redis

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    // Check if token is revoked
    if (token && this.revokedTokens.has(token)) {
      throw new UnauthorizedException('Token has been revoked');
    }

    return super.canActivate(context);
  }

  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();

    if (err || !user) {
      const errorMessage = info?.message || 'Authentication failed';
      
      // Log security events
      this.logger.warn(`Authentication failed for IP ${request.ip}: ${errorMessage}`);
      
      // Don't expose internal error details
      throw new UnauthorizedException('Authentication required');
    }

    // Add user to request for further processing
    request.user = {
      ...user,
      ip: request.ip,
      userAgent: request.headers['user-agent'],
    };

    return user;
  }

  private extractTokenFromHeader(request: any): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

  // Method to revoke tokens (call on logout)
  revokeToken(token: string): void {
    this.revokedTokens.add(token);
    
    // Clean up old tokens periodically (in production, handle in Redis with TTL)
    if (this.revokedTokens.size > 10000) {
      this.cleanupRevokedTokens();
    }
  }

  private cleanupRevokedTokens(): void {
    // Simple cleanup - in production, use Redis with automatic expiration
    const tokensArray = Array.from(this.revokedTokens);
    this.revokedTokens.clear();
    
    // Keep only the most recent 5000 tokens
    tokensArray.slice(-5000).forEach(token => this.revokedTokens.add(token));
  }
} 