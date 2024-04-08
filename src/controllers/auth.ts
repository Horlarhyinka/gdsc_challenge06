import { Request, Response } from "express";
import catchAsyncErrors from "../libs/catchAsyncErrors";
import validator from "../services/validator";
import userService from "../services/user";
import { mailRegex } from "../libs/regex";


export const register = catchAsyncErrors(async(req: Request, res: Response)=>{

    const validateRes = validator.validateCreateUserPayload(req.body)
    if(validateRes.error)return res.status(400).json({message: validateRes.error.message})
    const existing = await userService.findOne({username: req.body.username})
    if(existing)return res.status(400).json({message: "username is taken"})
    const user = await userService.create({...req.body})
    const token = await user.generateJWT()
    return res.status(201).json({user:{...user.toObject(), password: undefined}, token})
})

export const login = catchAsyncErrors(async(req: Request, res: Response)=>{
    const { username, password} = req.body
    if(!username || !password) return res.status(400).json({message: "username and password is required."})
    const user = await userService.findOne({username})
    if(!user)return res.status(404).json({message: "user not found."})
    const passwordCorrect = await user.comparePassword(password)
    if(!passwordCorrect)return res.status(400).json({message: "incorrect passsword"})
    const token = await user.generateJWT()
    return res.status(200).json({user: {...user.toObject(), password: undefined}, token})
})