import { createUnionType } from '@nestjs/graphql';
import { LoginResponse } from './login-response';
import { SocialUser } from 'src/user/entities/social-user.entities';

export const ResultUnion = createUnionType({
  name: 'ResultUnion',
  types: () => [LoginResponse, SocialUser] as const,
  resolveType(value) {
    if (value.access_token) {
      return LoginResponse;
    }
    if (value.oAuthId) {
      return SocialUser;
    }
    return null;
  },
});
