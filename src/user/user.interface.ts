import { Document, Schema } from 'mongoose';

export interface User extends Document {
  readonly _id: Schema.Types.ObjectId;
  readonly username: string;
  readonly email: string;
  readonly firstName: string;
  readonly lastName: string;
  readonly mobileNumber: number;
  readonly password: string;
}
