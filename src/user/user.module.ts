import { Module } from '@nestjs/common';
import { DatabaseModule } from 'src/database/database.module';
import { userProviders } from './user.provider';
import { UserResolver } from './user.resolver';
import { UserService } from './user.service';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [DatabaseModule, JwtModule],
  providers: [UserResolver, UserService, ...userProviders],
  exports: [UserService],
})
export class UserModule {}
