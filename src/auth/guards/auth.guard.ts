import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JWTPayload } from '../interfaces/jwt.payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(private readonly jwtService: JwtService,
    private readonly authService: AuthService, 

  ){}

  async canActivate(context: ExecutionContext): Promise<boolean>{
    
    
    try {
      const request= context.switchToHttp().getRequest();
      const token = this.extractTokenFromHeader(request);
      if(!token) throw new UnauthorizedException('There is Not bearer token');
      const payload = await this.jwtService.verifyAsync<JWTPayload>(
        token,  { secret: process.env.JWT_SECRET}
      )

      const user = await this.authService.findUserById(payload.id);
      if(!user) throw new UnauthorizedException('User already not exist!');
      if(!user.isActive) throw new UnauthorizedException('user is not active'); 

      request['user'] = user;

    } catch (error) {
        throw new UnauthorizedException();      
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined{
    const [ type , token ] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token: undefined;
  }

}
