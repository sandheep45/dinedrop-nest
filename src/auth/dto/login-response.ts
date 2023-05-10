import { Field, ObjectType, OmitType } from '@nestjs/graphql';
import { User } from 'src/user/entities/user.entities';

@ObjectType()
export class LoginResponse extends OmitType(User, ['password']) {
  @Field()
  access_token: string;
}
