import { ConfigModule } from '@nestjs/config';
import * as mongoose from 'mongoose';
export const databaseProviders = [
  {
    provide: 'DATABASE_CONNECTION',
    useFactory: async (): Promise<typeof mongoose> => {
      await ConfigModule.envVariablesLoaded;
      return await mongoose.connect(process.env.DATABASE_URL);
    },
  },
];
