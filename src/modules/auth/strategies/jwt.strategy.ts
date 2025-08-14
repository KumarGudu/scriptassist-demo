import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { IUserService } from '../../users/interfaces/user.service.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private usersService: IUserService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('jwt.secret'),
    });
  }

  async validate(payload: any) {
    const user = await this.usersService.findOne(payload.sub);
    
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    };
  }
} 