import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { compare } from 'bcrypt';
import { CreateUser } from 'src/user/dto/create-user.dto';
import { User } from 'src/user/entities/user.entities';
import { UserService } from 'src/user/user.service';
import { LoginResponse } from './dto/login-response';
import { SocialOAuthInput } from './dto/social-oauth.dto';
import { SocialUser } from 'src/user/entities/social-user.entities';
import { jwtConstant } from 'src/constant';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  async validateUser(username: string, password: string): Promise<any> {
    const user = await this.userService.findAUserByUsername(username);

    if (user instanceof Error) {
      return new HttpException("User doesn'n exist", HttpStatus.NOT_FOUND);
    }

    const confirmPassword = await compare(password, user.password);

    if (!user) {
      return new HttpException("User doesn'n exist", HttpStatus.NOT_FOUND);
    }

    if (!confirmPassword) {
      return new HttpException('Password mismatch', HttpStatus.UNAUTHORIZED);
    }

    const { password: userPassword, ...result } = user;
    return result;
  }

  async login(user: User): Promise<LoginResponse> {
    const payload = {
      sub: user._id,
      username: user.username,
    };
    const { password, ...rest } = user;
    return {
      access_token: this.jwtService.sign(payload, {
        secret: jwtConstant.secret,
      }),
      ...rest,
    };
  }

  async signup(signupInput: CreateUser): Promise<User | Error> {
    if (Object.values(signupInput).some((entity) => entity === '')) {
      return new HttpException(
        'Fields cannot be empty',
        HttpStatus.BAD_REQUEST,
      );
    }
    const existingUsername = await this.userService.findAUserByUsername(
      signupInput.username,
    );

    const existingEmail = await this.userService.findAUserByEmail(
      signupInput.email,
    );

    if (existingUsername) {
      return new HttpException(
        'This username already exist',
        HttpStatus.CONFLICT,
      );
    }

    if (existingEmail) {
      return new HttpException('This email already exist', HttpStatus.CONFLICT);
    }

    const newUser = await this.userService.createUser(signupInput);

    return newUser;
  }

  async generateAccessToken(user: User, accessToken: string): Promise<string> {
    const payload = {
      sub: user._id,
      username: user.username,
      accessToken,
    };
    return this.jwtService.signAsync(payload);
  }

  async googleAuthRedirect(req) {
    if (!req) {
      return new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
    return req.user;
  }

  async facebookAuthRedirect(req) {
    if (!req) {
      return new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
    return req.user;
  }

  async socialLogin(
    socialLoginInput: SocialOAuthInput,
  ): Promise<SocialUser | User> {
    const { provider, accessToken } = socialLoginInput;
    const userData = await this.userService.findUserFromSocialoAuth(
      provider,
      accessToken,
    );
    return userData;
  }
}
