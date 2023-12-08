import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from 'src/auth/auth.service';
import { JwtPayload } from 'src/auth/interface/jwt-payload.interface';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(
    private jwtService: JwtService,
    private authService: AuthService
  ) { }

  async canActivate(context: ExecutionContext,): Promise<boolean> {

    const request = context.switchToHttp().getRequest();
    const token = this.extractToken(request);

    if (!token) {
      throw new UnauthorizedException('No token')
    }

    try {

      const payload = await this.jwtService.verifyAsync<JwtPayload>(token, { secret: process.env.JWT_KEY });

      const user = await this.authService.findUserById(payload.id);
      if (!user) throw new UnauthorizedException('No existe usuario!');
      if (!user.isActive) throw new UnauthorizedException('Usuario no activo');

      request['user'] = user;

    } catch (error) {
      throw new UnauthorizedException('Error al verificar token');
    }

    return true;
  }

  private extractToken(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
