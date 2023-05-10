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
import { MailerModule } from '@nestjs-modules/mailer';

@Module({
  imports: [
    UserModule,
    PassportModule,
    JwtModule.register({
      secret: jwtConstant.secret,
      signOptions: { expiresIn: '60s' },
    }),
    ConfigModule,
    MailerModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        transport: {
          host: configService.get('MAIL_HOST'),
          port: configService.get('MAIL_PORT'),
          secure: false,
          auth: {
            user: configService.get('MAIL_USER'),
            pass: configService.get('MAIL_PASSWORD'),
          },
        },
        defaults: {
          from: '"nest-modules" <user@outlook.com>',
        },
      }),
      inject: [ConfigService],
    }),
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
