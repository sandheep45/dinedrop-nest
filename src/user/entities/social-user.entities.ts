import { Field, ObjectType } from '@nestjs/graphql';

@ObjectType()
export class SocialUser {
  @Field({ nullable: true })
  oAuthId: string;

  @Field({ nullable: true })
  email: string;

  @Field({ nullable: true })
  username: string;

  @Field({ nullable: true })
  firstName: string;

  @Field({ nullable: true })
  lastName: string;

  @Field({ nullable: true })
  picture: string;
}
