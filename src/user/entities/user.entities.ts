import { Field, ID, Int, ObjectType } from '@nestjs/graphql';
import { Schema } from 'mongoose';

@ObjectType()
export class User {
  @Field(() => ID, { nullable: true })
  _id?: Schema.Types.ObjectId;

  @Field({ nullable: true })
  username?: string;

  @Field({ nullable: true })
  email?: string;

  @Field({ nullable: true })
  firstName?: string;

  @Field({ nullable: true })
  lastName?: string;

  @Field((type) => Int, { nullable: true })
  mobileNumber?: number;

  @Field({ nullable: true })
  password?: string;
}
