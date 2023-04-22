import { Args, Context, Mutation, Resolver } from '@nestjs/graphql';
import { Query, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginUserInput } from './dto/login-input';
import { LoginResponse } from './dto/login-response';
import { GqlAuthGuard } from './guards/gql-auth.guard';
import { CreateUser } from 'src/user/dto/create-user.dto';
import { User } from 'src/user/entities/user.entities';
import { SocialOAuthInput } from './dto/social-oauth.dto';
import { SocialUser } from 'src/user/entities/social-user.entities';

@Resolver()
export class AuthResolver {
  constructor(private authService: AuthService) {}

  @UseGuards(GqlAuthGuard)
  @Mutation(() => LoginResponse)
  login(
    @Args('loginUserInput') loginUserInput: LoginUserInput,
    @Context() context,
  ) {
    return this.authService.login(context.user._doc);
  }

  @Mutation(() => User)
  signup(@Args('signupInput') signupInput: CreateUser) {
    return this.authService.signup(signupInput);
  }

  @Mutation(() => SocialUser || User)
  async socialLogin(
    @Args('socialLoginInput') socialLoginInput: SocialOAuthInput,
  ) {
    return await this.authService.socialLogin(socialLoginInput);
  }
}
