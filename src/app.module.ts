import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { ConfigModule } from '@nestjs/config';
import { join } from 'path';
import { DatabaseModule } from './database/database.module';
import { AuthorResolver } from './app.resolver';
import { ReferenceModule } from './reference/reference.module';
import { UserModule } from './user/user.module';
import { CartModule } from './cart/cart.module';
import { MenuModule } from './menu/menu.module';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    ConfigModule.forRoot(),
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: join(process.cwd(), 'src/schema.gql'),
      sortSchema: true,
    }),
    DatabaseModule,
    ReferenceModule,
    UserModule,
    CartModule,
    MenuModule,
    AuthModule,
  ],
  controllers: [],
  providers: [AuthorResolver],
})
export class AppModule {}
