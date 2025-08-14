import { Injectable, UnauthorizedException, BadRequestException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { IUserService } from '../users/interfaces/user.service.interface';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly MAX_LOGIN_ATTEMPTS = 5;
  private readonly LOCK_TIME = 15 * 60 * 1000; // 15 minutes
  private readonly loginAttempts = new Map<string, { attempts: number; lockUntil?: number }>();

  constructor(
    private readonly usersService: IUserService,
    private readonly jwtService: JwtService,
  ) {}

  async login(loginDto: LoginDto, ip: string) {
    const { email, password } = loginDto;

    // Check for account lockout
    await this.checkAccountLockout(email, ip);

    try {
      // Use constant-time comparison for user lookup
      const user = await this.usersService.findByEmail(email.toLowerCase());
      
      // Always perform password comparison to prevent timing attacks
      const dummyHash = '$2b$10$dummy.hash.to.prevent.timing.attacks.dummy.hash.for.security';
      const hashToCompare = user?.password || dummyHash;
      const passwordValid = await bcrypt.compare(password, hashToCompare);
      
      if (!user || !passwordValid) {
        await this.handleFailedLogin(email, ip);
        
        // Use constant error message to prevent user enumeration
        throw new UnauthorizedException('Invalid credentials');
      }

      // Reset login attempts on successful login
      this.loginAttempts.delete(email);
      this.loginAttempts.delete(ip);

      const payload = { 
        sub: user.id, 
        email: user.email, 
        role: user.role,
        iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(), // JWT ID for token revocation
      };

      // Log successful login (without sensitive data)
      this.logger.log(`Successful login for user: ${user.email}`);

      return {
        access_token: this.jwtService.sign(payload, { expiresIn: '15m' }),
        refresh_token: this.jwtService.sign(
          { sub: user.id, type: 'refresh' },
          { expiresIn: '7d' }
        ),
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
        },
        expiresIn: 900, // 15 minutes in seconds
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      
      this.logger.error(`Login error for email ${email}:`, error.message);
      throw new UnauthorizedException('Authentication failed');
    }
  }

  async register(registerDto: RegisterDto, ip: string) {
    try {
      // Validate email format and normalize
      const email = registerDto.email.toLowerCase();
      
      // Check password strength
      this.validatePasswordStrength(registerDto.password);

      const existingUser = await this.usersService.findByEmail(email);

      if (existingUser) {
        // Use same error as login to prevent user enumeration
        throw new BadRequestException('Registration failed');
      }

      const user = await this.usersService.create({
        ...registerDto,
        email,
      });

      // Generate secure tokens
      const payload = { 
        sub: user.id, 
        email: user.email, 
        role: user.role,
        iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(),
      };

      this.logger.log(`New user registered: ${user.email}`);

      return {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        },
        access_token: this.jwtService.sign(payload, { expiresIn: '15m' }),
        refresh_token: this.jwtService.sign(
          { sub: user.id, type: 'refresh' },
          { expiresIn: '7d' }
        ),
        expiresIn: 900,
      };
    } catch (error) {
      this.logger.error(`Registration error:`, error.message);
      
      if (error instanceof BadRequestException) {
        throw error;
      }
      
      throw new BadRequestException('Registration failed');
    }
  }

  private generateToken(userId: string) {
    const payload = { sub: userId };
    return this.jwtService.sign(payload);
  }

  async validateUser(userId: string): Promise<any> {
    const user = await this.usersService.findOne(userId);
    
    if (!user) {
      return null;
    }
    
    return user;
  }

  async validateUserRoles(userId: string, requiredRoles: string[]): Promise<boolean> {
    try {
      const user = await this.usersService.findOne(userId);
      
      if (!user) {
        return false;
      }

      return requiredRoles.includes(user.role);
    } catch (error) {
      this.logger.error(`Role validation error for user ${userId}:`, error.message);
      return false;
    }
  }

  private async checkAccountLockout(email: string, ip: string): Promise<void> {
    const emailAttempts = this.loginAttempts.get(email);
    const ipAttempts = this.loginAttempts.get(ip);

    const now = Date.now();

    // Check email-based lockout
    if (emailAttempts?.lockUntil && emailAttempts.lockUntil > now) {
      const remainingTime = Math.ceil((emailAttempts.lockUntil - now) / 1000 / 60);
      throw new UnauthorizedException(
        `Account temporarily locked. Try again in ${remainingTime} minutes.`
      );
    }

    // Check IP-based lockout
    if (ipAttempts?.lockUntil && ipAttempts.lockUntil > now) {
      const remainingTime = Math.ceil((ipAttempts.lockUntil - now) / 1000 / 60);
      throw new UnauthorizedException(
        `Too many failed attempts. Try again in ${remainingTime} minutes.`
      );
    }
  }

  private async handleFailedLogin(email: string, ip: string): Promise<void> {
    const now = Date.now();

    // Track attempts by email
    const emailAttempts = this.loginAttempts.get(email) || { attempts: 0 };
    emailAttempts.attempts += 1;

    if (emailAttempts.attempts >= this.MAX_LOGIN_ATTEMPTS) {
      emailAttempts.lockUntil = now + this.LOCK_TIME;
    }

    this.loginAttempts.set(email, emailAttempts);

    // Track attempts by IP
    const ipAttempts = this.loginAttempts.get(ip) || { attempts: 0 };
    ipAttempts.attempts += 1;

    if (ipAttempts.attempts >= this.MAX_LOGIN_ATTEMPTS * 3) { // Higher threshold for IP
      ipAttempts.lockUntil = now + this.LOCK_TIME;
    }

    this.loginAttempts.set(ip, ipAttempts);

    this.logger.warn(
      `Failed login attempt ${emailAttempts.attempts}/${this.MAX_LOGIN_ATTEMPTS} for ${email} from ${ip}`
    );
  }

  private validatePasswordStrength(password: string): void {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

    if (password.length < minLength) {
      throw new BadRequestException('Password must be at least 8 characters long');
    }

    const strength = [hasUpperCase, hasLowerCase, hasNumbers, hasSpecialChar].filter(Boolean).length;
    
    if (strength < 3) {
      throw new BadRequestException(
        'Password must contain at least 3 of: uppercase letters, lowercase letters, numbers, special characters'
      );
    }
  }

  async refreshToken(refreshToken: string): Promise<{ access_token: string; expiresIn: number }> {
    try {
      const payload = this.jwtService.verify(refreshToken);
      
      if (payload.type !== 'refresh') {
        throw new UnauthorizedException('Invalid refresh token');
      }

      const user = await this.usersService.findOne(payload.sub);
      
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      const newPayload = {
        sub: user.id,
        email: user.email,
        role: user.role,
        iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(),
      };

      return {
        access_token: this.jwtService.sign(newPayload, { expiresIn: '15m' }),
        expiresIn: 900,
      };
    } catch (error) {
      this.logger.error('Refresh token error:', error.message);
      throw new UnauthorizedException('Invalid refresh token');
    }
  }
} 