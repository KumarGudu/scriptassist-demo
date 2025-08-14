import { Body, Controller, Post, Get, UseGuards, Request, Ip, Headers } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { SecureRateLimitGuard, SecureRateLimit, RateLimitPresets } from '../../common/guards/secure-rate-limit.guard';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags, ApiBody } from '@nestjs/swagger';

@ApiTags('auth')
@Controller('auth')
@UseGuards(SecureRateLimitGuard)
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly jwtAuthGuard: JwtAuthGuard,
  ) {}

  @Post('register')
  @SecureRateLimit(RateLimitPresets.AUTH)
  @ApiOperation({ summary: 'Register a new user' })
  @ApiBody({ type: RegisterDto })
  @ApiResponse({ status: 201, description: 'User successfully registered' })
  @ApiResponse({ status: 400, description: 'Invalid registration data' })
  @ApiResponse({ status: 429, description: 'Too many registration attempts' })
  register(@Body() registerDto: RegisterDto, @Ip() ip: string) {
    return this.authService.register(registerDto, ip);
  }

  @Post('login')
  @SecureRateLimit(RateLimitPresets.AUTH)
  @ApiOperation({ summary: 'Login user' })
  @ApiBody({ type: LoginDto })
  @ApiResponse({ status: 200, description: 'User successfully logged in' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiResponse({ status: 429, description: 'Too many login attempts' })
  login(@Body() loginDto: LoginDto, @Ip() ip: string) {
    return this.authService.login(loginDto, ip);
  }

  @Post('refresh')
  @SecureRateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    maxRequests: 10,
    message: 'Too many token refresh attempts',
  })
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiResponse({ status: 200, description: 'Token successfully refreshed' })
  @ApiResponse({ status: 401, description: 'Invalid refresh token' })
  @ApiResponse({ status: 429, description: 'Too many refresh attempts' })
  refreshToken(@Body('refresh_token') refreshToken: string) {
    return this.authService.refreshToken(refreshToken);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout user and revoke token' })
  @ApiResponse({ status: 200, description: 'Successfully logged out' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  logout(@Request() req, @Headers('authorization') authorization: string) {
    // Extract token and revoke it
    const token = authorization?.replace('Bearer ', '');
    if (token) {
      this.jwtAuthGuard.revokeToken(token);
    }
    
    return { 
      message: 'Successfully logged out',
      success: true 
    };
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  @SecureRateLimit(RateLimitPresets.GENERAL)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get user profile' })
  @ApiResponse({ status: 200, description: 'User profile retrieved' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getProfile(@Request() req) {
    // Return user data without sensitive information
    const { password, ...userProfile } = req.user;
    return {
      success: true,
      user: userProfile,
    };
  }
} 