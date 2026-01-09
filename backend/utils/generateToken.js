import jwt from "jsonwebtoken";

const accessToken = (id)=>{
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: "10min",
    });
}

const refreshToken = (id)=>{
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: "7d",
    });
}

export {accessToken, refreshToken};