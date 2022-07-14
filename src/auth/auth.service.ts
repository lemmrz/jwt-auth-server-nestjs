import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Tokens } from './types/tokens.type';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwtService: JwtService) {}

    async signUpLocal(dto: AuthDto): Promise<Tokens> {
        const hash = await this.hashData(dto.password);

        const newUser = await this.prisma.user.create({
            data: {
                email: dto.email,
                hash
            }
        })
        const tokens = await this.getTokens(newUser.id, newUser.email);
        await this.refreshRtHash(newUser.id, tokens.refresh_token);
        return tokens;
    }

    async signInLocal(dto: AuthDto): Promise<Tokens> {
        const user = await this.prisma.user.findFirst({
            where: {
                email: dto.email
            },
        })

        if (!user) throw new ForbiddenException("Access Denied")

        const passwordMatches = await bcrypt.compare(dto.password, user.hash);
        if (!passwordMatches) throw new ForbiddenException("Access Denied")

        const tokens = await this.getTokens(user.id, user.email);
        await this.refreshRtHash(user.id, tokens.refresh_token);
        return tokens;
    }

    async logout(userId: number): Promise<boolean> {
        await this.prisma.user.updateMany({
            where: {
                id: userId,
                hashRt: {
                    not: null
                },
            },
            data: {
                hashRt: null
            }
        })
        return true;
    }

    async refreshToken(userId: number, rt: string) {
        const user = await this.prisma.user.findFirst({
            where: {
                id: userId
            },
        })
        if (!user) throw new ForbiddenException("Access Denied");

        console.log(rt)
        const rtMatches = await bcrypt.compare(rt, user.hashRt);
        if (!rtMatches) throw new ForbiddenException("Access Denied");

        const tokens = await this.getTokens(user.id, user.email);
        await this.refreshRtHash(user.id, tokens.refresh_token);
        return tokens;
    }

    async getTokens(userId: number, email: string): Promise<Tokens> {
        const [at, rt] = await Promise.all([
            this.jwtService.signAsync(
                {
                    userId,
                    email
                },
                {
                    secret: 'at-secret',
                    expiresIn: '15m'
                }),
            this.jwtService.signAsync({
                userId,
                email
            }, {
                secret: 'rt-secret',
                expiresIn: '7d',
            })
        ])
        return {
            access_token: at,
            refresh_token: rt
        }

    }

    async refreshRtHash(userId: number, rt: string) {
        const hash = await this.hashData(rt);
        await this.prisma.user.update({
            where: {
                id: userId
            },
            data: {
                hashRt: hash
            }
        })
    }

    hashData(data: string) {
        return bcrypt.hash(data, 10)
    }

}