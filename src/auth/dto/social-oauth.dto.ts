import { Field, InputType } from '@nestjs/graphql';

@InputType()
export class SocialOAuthInput {
  @Field()
  provider: string;

  @Field()
  accessToken: string;
}
