import jwt from "jsonwebtoken";

const accessToken = (id)=>{
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: "1d",
    });
}

const refreshToken = (id)=>{
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: "30d",
    });
}

export {accessToken, refreshToken};