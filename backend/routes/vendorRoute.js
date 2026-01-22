import express from "express";
import { vendorRegister, vendorLogin, vendorLogout, vendorVerifyOtp, vendorResetPassword, forgotPassword, vendorRefreshToken, vendorResendOtp, vendorChangePassword } from "../controllers/authVendorRegister.js";
import {userProfileUpload}  from "../middlewares/Multer.js"; 
import vendorauth from "../middlewares/vendorauth.js";
import rateLimit from "express-rate-limit";

const vendorRouter = express.Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many attempts. Try again later",
})

//auth
vendorRouter.post(
  "/vendor-register",authLimiter,  
  userProfileUpload.fields([
    { name: "profile", maxCount: 1 },
    { name: "vendorShopImages", maxCount: 10 }
  ]),
  vendorRegister
);

vendorRouter.post('/vendor-refresh-token',vendorRefreshToken)
vendorRouter.post('/vendor-login',authLimiter,vendorLogin)
vendorRouter.post('/vendor-logout',vendorauth,vendorLogout)
vendorRouter.post('/vendor-verify-otp',authLimiter,vendorVerifyOtp)
vendorRouter.post('/vendor-resend-otp',authLimiter,vendorResendOtp)

//password
vendorRouter.post('/vendor-reset-password',authLimiter,vendorResetPassword)
vendorRouter.post('/vendor-forgot-password',authLimiter,forgotPassword)
vendorRouter.post('/vendor-change-password',authLimiter,vendorauth,vendorChangePassword)

//approved status


export default vendorRouter