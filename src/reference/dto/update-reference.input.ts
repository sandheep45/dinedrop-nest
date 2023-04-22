import { CreateReferenceInput } from './create-reference.input';
import { InputType, Field, Int, PartialType } from '@nestjs/graphql';

@InputType()
export class UpdateReferenceInput extends PartialType(CreateReferenceInput) {
  @Field(() => Int)
  id: number;
}
