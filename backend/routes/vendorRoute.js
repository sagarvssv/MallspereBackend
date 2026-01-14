import express from "express";
import { vendorRegister, vendorLogin, vendorLogout, vendorVerifyOtp, vendorResetPassword, forgotPassword } from "../controllers/authVendorRegister.js";
import {userProfileUpload}  from "../middlewares/Multer.js"; 

const vendorRouter = express.Router();


vendorRouter.post(
  "/vendor-register",
  userProfileUpload.fields([
    { name: "profile", maxCount: 1 },
    { name: "vendorShopImages", maxCount: 10 }
  ]),
  vendorRegister
);


vendorRouter.post('/vendor-login',vendorLogin)
vendorRouter.post('/vendor-logout',vendorLogout)
vendorRouter.post('/vendor-verify-otp',vendorVerifyOtp)
vendorRouter.post('/vendor-reset-password',vendorResetPassword)
vendorRouter.post('/vendor-forgot-password',forgotPassword)

export default vendorRouter