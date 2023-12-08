import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
import { LoginResponse } from './interface/login-response.interface';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interface/jwt-payload.interface';
import { RegisterUserDto } from './dto/register-user.dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService
  ) { }

  async create(createUserDto: CreateUserDto): Promise<User> {

    try {
      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });

      await newUser.save();
      const { password: _, ...user } = newUser.toJSON();

      return user;

    } catch (error) {
      console.log(error);
      if (error.code === 11000) throw new BadRequestException(`${createUserDto.email} email ya existente!`);
      throw new InternalServerErrorException('Algo salio mal');
    }
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;
    const userIn = await this.userModel.findOne({ email });

    if (!userIn) {
      throw new UnauthorizedException('Credenciales no validas - email');
    }

    if (!bcryptjs.compareSync(password, userIn.password)) {
      throw new UnauthorizedException('Credenciales no validas - password');
    }

    const { password: _, ...user } = userIn.toJSON();

    return {
      user,
      token: await this.createJwtToken({ id: userIn.id })
    }
  }

  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create(registerUserDto);

    return {
      user,
      token: await this.createJwtToken({ id: user._id })
    }
  }

  createJwtToken(payload: JwtPayload): string {
    return this.jwtService.sign(payload);
  }

  findAll(): Promise<User[]> {
    return this.userModel.find({}, { password: 0, __v: 0 });
  }

  async findUserById(id: string): Promise<User> {
    return await this.userModel.findById(id);
  }

  // findOne(id: number) {
  //   return `This action returns a #${id} auth`;
  // }

  // update(id: number, updateUserDto: UpdateUserDto) {
  //   return `This action updates a #${id} auth`;
  // }

  // remove(id: number) {
  //   return `This action removes a #${id} auth`;
  // }
}
