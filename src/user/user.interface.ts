import { Document, Schema } from 'mongoose';
import { Stream } from 'stream';

export interface User extends Document {
  readonly _id: Schema.Types.ObjectId;
  readonly username: string;
  readonly email: string;
  readonly firstName: string;
  readonly lastName: string;
  readonly mobileNumber: number;
  readonly password: string;
}

export interface FileUpload {
  filename: string;
  mimetype: string;
  encoding: string;
  createReadStream: () => Stream;
}
