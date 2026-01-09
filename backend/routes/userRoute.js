
import express from "express";
import { userLogin, userRegister, VerifyOtp, otpResend, userLogout,forgotPassword,reSetPassword,changePassword } from "../controllers/authUseRegister.js";
import { userProfileUpload } from "../middlewares/Multer.js";
import rateLimit from "express-rate-limit";
import userAuth from "../middlewares/userauth.js";

const userRouter = express.Router();


const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many attempts. Try again later",
});


//auth
userRouter.post('/register',authLimiter, userProfileUpload.single('profilePicture'), userRegister);
userRouter.post('/login',authLimiter,userLogin);
userRouter.post('/verify-user-otp',authLimiter,VerifyOtp)
userRouter.post('/resend-otp',authLimiter,otpResend)
userRouter.post('/user-logout',userAuth, userLogout)

//passwords

userRouter.post('/user-forgot-password',authLimiter,forgotPassword)
userRouter.post('/user-reset-password',authLimiter,reSetPassword)
userRouter.post('/user-change-password',authLimiter,userAuth,changePassword)




export default userRouter; 