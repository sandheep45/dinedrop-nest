import { Connection } from 'mongoose';
import { providers } from 'src/constant';
import { UserSchema } from './user.schema';

export const userProviders = [
  {
    provide: providers.user,
    useFactory: (connection: Connection) =>
      connection.model('User', UserSchema),
    inject: [providers.database],
  },
];
