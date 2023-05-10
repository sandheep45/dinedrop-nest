import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { compare } from 'bcrypt';
import { MailerService } from '@nestjs-modules/mailer';
import { CreateUser } from 'src/user/dto/create-user.dto';
import { User } from 'src/user/entities/user.entities';
import { UserService } from 'src/user/user.service';
import { LoginResponse } from './dto/login-response';
import { SocialOAuthInput } from './dto/social-oauth.dto';
import { SocialUser } from 'src/user/entities/social-user.entities';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    private mailService: MailerService,
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
      access_token: this.jwtService.sign(payload),
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

  async socialAuthRedirect(req) {
    if (!req) {
      return new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
    return req.user;
  }

  async socialLogin(
    socialLoginInput: SocialOAuthInput,
  ): Promise<LoginResponse | SocialUser> {
    const { provider, accessToken } = socialLoginInput;
    const userData = await this.userService.findUserFromSocialoAuth(
      provider,
      accessToken,
    );
    return userData;
  }

  async sendMail() {
    const mailService = await this.mailService.sendMail({
      to: 'sudip777sharma@gmail.com',
      from: 'spp26041999@gmail.com',
      subject: 'This mail is sent from dinedrop',
      text: 'hey there',
      html: '<h1>Mailservice add hogaya bhai  💪  😉  </h1>',
    });

    const rejectedMail = mailService.rejected.join(', ');

    if (rejectedMail) {
      return new HttpException(
        `Mail not sent to ${rejectedMail}`,
        HttpStatus.BAD_REQUEST,
      );
    }

    return 'hello world';
  }
}
