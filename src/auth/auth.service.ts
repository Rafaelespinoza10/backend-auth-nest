import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto.';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JWTPayload } from './interfaces/jwt.payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto } from './dto';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private readonly userModel: Model<User>,
    private readonly jwtService: JwtService,
  ){}


  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
          // const newUser = new this.userModel(createAuthDto);
          
          const {password, ...userData} = createUserDto;
          
          //!TOOD: encriptar la contrasena 
          const newUser = new this.userModel({
            password: bcrypt.hashSync(password, 10),
            ...userData,
          });
          const {password: _, ...user} = newUser.toJSON();
          //!TODO: guardar el usuario
        await newUser.save();
        return user;
      
      } catch (error) {
        if(error.code === 11000){
          throw new BadRequestException(`${ createUserDto.email } already exist`);
        }
        throw new InternalServerErrorException('Something terrible happen!');
    }
  }


  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse>{
      try {
        // creamos al usuario 
        const user  = await this.create({ email: registerUserDto.email, password: registerUserDto.password, name: registerUserDto.name});
        return { 
          user,  
          token: this.getJwtToken({id: user._id} )
        }
      } catch (error) {
        if(error.code === 11000){
          throw new BadRequestException(`${registerUserDto.email} already exists`);
        }
        throw new InternalServerErrorException('Something terrible happen!'); 
      }
  }


  async login(loginDto: LoginDto): Promise<LoginResponse>{

    const{ password, email} = loginDto; 
    const user = await this.userModel.findOne({ email });
    if(!user){
      throw new UnauthorizedException('Not valid credentails ');
    } 
    if(!bcrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException('not valid credentails - password');
    }
    const { password: _, ...rest  } = user.toJSON();
    return {
        user: rest, 
        token: this.getJwtToken({ id: user.id }),
    } 
  }
  
  getJwtToken(payload: JWTPayload){
    const token = this.jwtService.sign(payload);
    return token;      
  } 

  findAll():Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id: string){
    const user = await this.userModel.findById(id);
    const{ password, ...rest} = user.toJSON();
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
}
