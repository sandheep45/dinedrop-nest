import { InputType, Int, Field } from '@nestjs/graphql';

@InputType()
export class CreateReferenceInput {
  @Field(() => Int, { description: 'Example field (placeholder)' })
  exampleField: number;
}
