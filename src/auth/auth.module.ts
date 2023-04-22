import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthResolver } from './auth.resolver';
import { UserModule } from 'src/user/user.module';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt/dist';
import { jwtConstant } from 'src/constant';
import { JwtStrategy } from './stratergies/jwt.strategy';
import { LocalStrategy } from './stratergies/local.strategy';
import { GoogleStrategy } from './stratergies/google.strategy';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { FacebookStrategy } from './stratergies/facebook.strategy';

@Module({
  imports: [
    UserModule,
    PassportModule,
    JwtModule.register({
      secret: jwtConstant.secret,
      signOptions: { expiresIn: '60s' },
    }),
    ConfigModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    AuthResolver,
    LocalStrategy,
    JwtStrategy,
    GoogleStrategy,
    ConfigService,
    FacebookStrategy,
  ],
  exports: [AuthService, ConfigService],
})
export class AuthModule {}
