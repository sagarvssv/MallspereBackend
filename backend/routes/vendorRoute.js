import express from "express";
import { vendorRegister } from "../controllers/authVendorRegister.js";
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

export default vendorRouter