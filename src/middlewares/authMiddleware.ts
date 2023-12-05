import { Request, Response, NextFunction } from "express";
import jwt from 'jsonwebtoken';
import { PrismaClient, User } from '@prisma/client';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || "SUPER SECRET";  

type AuthRequest = Request & { user?: User}

export async function authenticateToken(
    req: AuthRequest,
    res: Response,
    next: NextFunction
) {
     // Authentication
     const authHeader = req.headers['authorization'];
     const jwttoken = authHeader?.split(" ")[1];
     if(!jwttoken){
      return res.sendStatus(401);
     }


     // Decode the JWT token
     try{
       const payload = await jwt.verify(jwttoken, JWT_SECRET) as {
         tokenId: number;
       };
       const dbToken = await prisma.token.findUnique({
        where: {id: payload.tokenId},
        include: { user: true},
       });
       
       if(!dbToken?.valid || dbToken.expiration < new Date()){
         return res.sendStatus(401).json({error: "API token expired"});
       }
       
       req.user = dbToken.user;
     }catch(error){
      return res.sendStatus(401);
     }
    
     next();
}