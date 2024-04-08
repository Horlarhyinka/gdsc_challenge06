import { NextFunction, Response, Request } from "express";
import jwt from "jsonwebtoken"
import config from "../config/config";
import userService from "../services/user";
import { UserSchema } from "../models/types/user";

interface ExtReq extends Request{
    user: UserSchema
}

const useAuth = async function(req: Request, res: Response, next: NextFunction){
    function sendUnauthenticated(msg?: string){
        return res.status(401).json({message: msg || "unauthenticated"})
    }
    const authPayload = req.headers["authorization"]
    if(!authPayload)return sendUnauthenticated()
    const [prefix, token] = authPayload.split(" ")
    if(prefix?.toLowerCase() !== "bearer" || !token)return sendUnauthenticated("bearer token is required")
    const {id} = (await jwt.verify(token, config.server.secret)) as {id: string}
    if(!id)return sendUnauthenticated()
    const user = await userService.getById(id)
    if(!user)return sendUnauthenticated("user not found");
    (req as ExtReq).user = user
    next()
}

export default useAuth