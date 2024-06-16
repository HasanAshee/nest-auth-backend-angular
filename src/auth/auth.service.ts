import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import { JwtService } from "@nestjs/jwt";

import * as bcrypjs from 'bcryptjs';
import { LoginDto } from './dto/loign.dto';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterDto } from './dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {

    try {
      const {password, ...userData} = createUserDto;
      const newUser = new this.userModel({
        password: bcrypjs.hashSync(password, 10),
        ...userData
      });

      await newUser.save();
      const {password:_, ...user} = newUser.toJSON();

      return user;
      
    } catch (error) {
      console.log(error.code)      
      if ( error.code === 11000 ){
        throw new BadRequestException(`${createUserDto.email} already exist`)
      }
      throw new InternalServerErrorException('Something terrible happend pa')
    }

  }

  async register(registerDto: RegisterDto):Promise<LoginResponse>{

    const user = await this.create(registerDto)

    return{
      user: user,
      token: this.getJwtToken({id: user._id})
    }

  }

  async login(loginDto: LoginDto):Promise<LoginResponse>{
    const {email, password} = loginDto;

    const user = await this.userModel.findOne({email});

    if ( !user ){
      throw new UnauthorizedException('not valid email');
    }
    
    if (!bcrypjs.compareSync(password, user.password)){
      throw new UnauthorizedException('not valid pass');
    }

    const {password:_, ...rest} = user.toJSON();

    return {
      user: rest,
      token: this.getJwtToken({id: user.id}),
    }
  }

  findAll():Promise<User[]> {
    return this.userModel.find()
  }

  async findUserById(id: string){
    const user = await this.userModel.findById(id);
    const {password, ...rest} = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload){
    const token = this.jwtService.sign(payload);
    return token;
  } 
}
