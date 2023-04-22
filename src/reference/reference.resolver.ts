import { Resolver, Query, Mutation, Args, Int } from '@nestjs/graphql';
import { ReferenceService } from './reference.service';
import { Reference } from './entities/reference.entity';
import { CreateReferenceInput } from './dto/create-reference.input';
import { UpdateReferenceInput } from './dto/update-reference.input';

@Resolver(() => Reference)
export class ReferenceResolver {
  constructor(private readonly referenceService: ReferenceService) {}

  @Mutation(() => Reference)
  createReference(
    @Args('createReferenceInput') createReferenceInput: CreateReferenceInput,
  ) {
    return this.referenceService.create(createReferenceInput);
  }

  @Query(() => [Reference], { name: 'references' })
  findAll(): Reference[] {
    return this.referenceService.findAll();
  }

  @Query(() => Reference, { name: 'reference' })
  findOne(@Args('id', { type: () => Int }) id: number): Reference {
    return this.referenceService.findOne(id);
  }

  @Mutation(() => Reference)
  updateReference(
    @Args('updateReferenceInput') updateReferenceInput: UpdateReferenceInput,
  ) {
    return this.referenceService.update(
      updateReferenceInput.id,
      updateReferenceInput,
    );
  }

  @Mutation(() => Reference)
  removeReference(@Args('id', { type: () => Int }) id: number) {
    return this.referenceService.remove(id);
  }
}
