import { ObjectType, Field, Int } from '@nestjs/graphql';

@ObjectType()
export class Reference {
  @Field(() => Int, { description: 'Example field (placeholder)' })
  exampleField: number;
}
