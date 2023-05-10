import { HttpException, HttpStatus, UseGuards } from '@nestjs/common';
import { Args, Mutation, Query, Resolver } from '@nestjs/graphql';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { CreateUser } from './dto/create-user.dto';
import { User } from './entities/user.entities';
import { UserService } from './user.service';

@Resolver(() => User)
export class UserResolver {
  constructor(private readonly userService: UserService) {}

  // @UseGuards(LocalAuthGuard)
  @Query(() => [User], { name: 'Users' })
  async findAllUsers(): Promise<User[] | Error> {
    return await this.userService.findAllUsers();
  }

  @UseGuards(JwtAuthGuard)
  @Query(() => User, { name: 'User', nullable: true })
  async findAUser(@Args('Username') username: string): Promise<User | Error> {
    const user = await this.userService.findAUserByUsername(username);
    if (!user) {
      return new HttpException("User doesn'n exist", HttpStatus.NOT_FOUND);
    }
    return user;
  }

  @Mutation(() => User)
  async createUser(@Args('createUserDto') createUserDto: CreateUser) {
    return this.userService.createUser(createUserDto);
  }
}
