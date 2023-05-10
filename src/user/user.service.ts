import { Injectable, Inject, HttpException, HttpStatus } from '@nestjs/common';
import { hash } from 'bcrypt';
import { Model } from 'mongoose';
import { SOCIAL_SDK_URLS, jwtConstant, providers } from 'src/constant';
import { CreateUser } from './dto/create-user.dto';
import { User } from './user.interface';
import { SocialUser } from './entities/social-user.entities';
import { JwtService } from '@nestjs/jwt';
import { LoginResponse } from 'src/auth/dto/login-response';

@Injectable()
export class UserService {
  constructor(
    @Inject(providers.user) private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async createUser(createUser: CreateUser): Promise<User | Error> {
    try {
      const saltRounds = 15;
      const hashedPassword = await hash(createUser.password, saltRounds);
      const createdUser = new this.userModel({
        ...createUser,
        password: hashedPassword,
      });
      return createdUser.save();
    } catch (error) {
      return new HttpException(
        error.message || 'Something went wrong',
        HttpStatus.CONFLICT,
      );
    }
  }

  async findAllUsers(): Promise<User[] | Error> {
    const users = await this.userModel.find().exec();

    if (!users) {
      return new HttpException('No user found', HttpStatus.NOT_FOUND);
    }

    return users;
  }

  async findAUserByUsername(username: string): Promise<User | null> {
    const user = await this.userModel.findOne({ username }).exec();

    return user;
  }

  async findAUserByEmail(email: string): Promise<User | null> {
    const user = await this.userModel.findOne({ email }).exec();

    return user;
  }

  async findUserFromSocialoAuth(
    provider: string,
    access_token: string,
  ): Promise<LoginResponse | SocialUser> {
    try {
      const res = await fetch(SOCIAL_SDK_URLS[provider] + access_token);
      const data = await res.json();
      const existingUser = await this.userModel
        .findOne({
          $or: [{ username: data.name }, { email: data.email }],
        })
        .exec();

      if (existingUser) {
        const payload = {
          sub: existingUser._id.toString(),
          username: existingUser.username,
        };
        const { _id, username, email, firstName, lastName, mobileNumber } =
          existingUser;
        return {
          access_token: this.jwtService.sign(payload, {
            secret: jwtConstant.secret,
          }),
          _id,
          username,
          email,
          firstName,
          lastName,
          mobileNumber,
        };
      }

      return {
        email: data.email,
        firstName: data.given_name || data.first_name,
        lastName: data.family_name || data.last_name,
        username: data.name,
        oAuthId: data.sub || data.id,
        picture: data?.picture?.data?.url || data.picture,
      };
    } catch (error) {
      return error;
    }
  }
}
