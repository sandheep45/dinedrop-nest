import { Injectable } from '@nestjs/common';
import { CreateReferenceInput } from './dto/create-reference.input';
import { UpdateReferenceInput } from './dto/update-reference.input';

@Injectable()
export class ReferenceService {
  create(createReferenceInput: CreateReferenceInput) {
    return 'This action adds a new reference';
  }

  findAll() {
    return [
      {
        exampleField: 1,
      },
      {
        exampleField: 2,
      },
    ];
  }

  findOne(id: number) {
    return {
      exampleField: id,
    };
  }

  update(id: number, updateReferenceInput: UpdateReferenceInput) {
    return `This action updates a #${id} reference`;
  }

  remove(id: number) {
    return `This action removes a #${id} reference`;
  }
}
