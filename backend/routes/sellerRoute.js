import express from "express";
import { sellerStallRegister } from "../controllers/sellercontroller.js";
import { userProfileUpload } from "../middlewares/Multer.js";
import rateLimit from "express-rate-limit";


const sellerRouter = express.Router();
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: "Too many attempts. Try again later",
})


sellerRouter.post('/seller-stall-register',authLimiter,userProfileUpload.fields([
    { name: "profilePicture", maxCount: 1 },
    { name: "sellerShopImage", maxCount: 5 }
]),sellerStallRegister)


export default sellerRouter;