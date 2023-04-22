import { Module } from '@nestjs/common';
import { ReferenceService } from './reference.service';
import { ReferenceResolver } from './reference.resolver';

@Module({
  providers: [ReferenceResolver, ReferenceService],
})
export class ReferenceModule {}
