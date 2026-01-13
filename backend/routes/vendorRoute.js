import express from "express";
import { vendorRegister, vendorLogin, vendorLogout, vendorVerifyOtp, vendorResetPassword, forgotPassword } from "../controllers/authVendorRegister.js";
import {userProfileUpload}  from "../middlewares/Multer.js"; 

const vendorRouter = express.Router();


vendorRouter.post('/vendor-register',  userProfileUpload.fields([
    { name: "profile", maxCount: 1 },
    { name: "image1", maxCount: 1 },
    { name: "image2", maxCount: 1 },
    { name: "image3", maxCount: 1 },
    { name: "image4", maxCount: 1 },
    { name: "image5", maxCount: 1 }
  ]),vendorRegister);

vendorRouter.post('/vendor-login',vendorLogin)
vendorRouter.post('/vendor-logout',vendorLogout)
vendorRouter.post('/vendor-verify-otp',vendorVerifyOtp)
vendorRouter.post('/vendor-reset-password',vendorResetPassword)
vendorRouter.post('/vendor-forgot-password',forgotPassword)

export default vendorRouter