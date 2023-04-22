import { ConfigService } from '@nestjs/config';
import { Query, Resolver } from '@nestjs/graphql';
import { Author } from './app.schema';

@Resolver(() => Author)
export class AuthorResolver {
  constructor(private readonly configService: ConfigService) {}

  @Query(() => String)
  findAll() {
    return 'Hello world';
  }
}
