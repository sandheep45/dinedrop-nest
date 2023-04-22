import { Field, InputType, Int } from '@nestjs/graphql';

@InputType()
export class CreateUser {
  @Field()
  username: string;

  @Field()
  email: string;

  @Field()
  firstName: string;

  @Field()
  lastName: string;

  @Field((type) => Int)
  mobileNumber: number;

  @Field()
  password: string;
}
