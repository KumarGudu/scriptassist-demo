import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { IUserService } from '../users/interfaces/user.service.interface';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: IUserService,
    private readonly jwtService: JwtService,
  ) {}

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;

    const user = await this.usersService.findByEmail(email);
    
    if (!user) {
      throw new UnauthorizedException('Invalid email');
    }

    const passwordValid = await bcrypt.compare(password, user.password);
    
    if (!passwordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    const payload = { 
      sub: user.id, 
      email: user.email, 
      role: user.role
    };

    return {
      access_token: this.jwtService.sign(payload),
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    };
  }

  async register(registerDto: RegisterDto) {
    const existingUser = await this.usersService.findByEmail(registerDto.email);

    if (existingUser) {
      throw new UnauthorizedException('Email already exists');
    }

    const user = await this.usersService.create(registerDto);

    const token = this.generateToken(user.id);

    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
      token,
    };
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
    return true;
  }
} 