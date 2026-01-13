import validator from "validator";
import bcrypt from "bcryptjs";
import cloudinary from "../config/cloudinary.js";
import VendorModel from "../models/VendorModel.js";
import generateOtp from "../utils/generateOtp.js";
import sendMailOtp from "../utils/sendMailOtp.js";
import { accessToken,refreshToken } from "../utils/generateToken.js";

const isProd = process.env.NODE_ENV === "production";

const vendorRegister = async (req, res) => {
    try {
        const {
            name, email, password, location, shopName, shopAddress,
            phoneNumber, vendorLicenseNumber, vendorShopNumberOfFloors,
            vendorShopNumberOfStalls, vendorShopOpeningTime,
            vendorShopClosingTime, vendorShopDescription
        } = req.body;

        // 🔹 VALIDATION
        if (!name || !email || !password || !location || !shopName || !shopAddress ||
            !phoneNumber || !vendorLicenseNumber || !vendorShopNumberOfFloors ||
            !vendorShopNumberOfStalls || !vendorShopOpeningTime || !vendorShopClosingTime ||
            !vendorShopDescription) {
            return res.status(400).json({ message: "All fields are required" });
        }

        if (!validator.isEmail(email)) return res.status(400).json({ message: "Invalid email format" });
        if (password.length < 6) return res.status(400).json({ message: "Password must be at least 6 characters" });
        if (!validator.isMobilePhone(phoneNumber, "en-IN")) return res.status(400).json({ message: "Invalid phone number" });

        // 🔹 DUPLICATE CHECK
        const existingVendor = await VendorModel.findOne({ $or: [{ email }, { vendorLicenseNumber }] });
        if (existingVendor) return res.status(409).json({ message: "Vendor already exists" });

        // 🔹 PROFILE IMAGE
        const profilePath = req.files?.profile?.[0]?.path;
        if (!profilePath) return res.status(400).json({ message: "Profile picture is required" });
        const profileUpload = await cloudinary.uploader.upload(profilePath, { folder: "vendor_profiles" });

        // 🔹 SHOP IMAGES
        const shopImages = [
            req.files?.image1?.[0]?.path,
            req.files?.image2?.[0]?.path,
            req.files?.image3?.[0]?.path,
            req.files?.image4?.[0]?.path,
            req.files?.image5?.[0]?.path
        ].filter(Boolean);

        if (shopImages.length === 0) return res.status(400).json({ message: "Shop images required" });

        const uploadedShopImages = [];
        for (const img of shopImages) {
            const result = await cloudinary.uploader.upload(img, { folder: "vendor_shop_images" });
            uploadedShopImages.push(result.secure_url);
        }

        // 🔹 PASSWORD HASHING
        const hashedPassword = await bcrypt.hash(password, 10);

        // 🔹 OTP
        const otp = generateOtp();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

        // 🔹 CREATE VENDOR
        const vendor = await VendorModel.create({
            name,
            email,
            password: hashedPassword,
            location,
            shopName,
            vendorShopAddress: shopAddress,
            vendorContactNumber: phoneNumber,
            vendorLicenseNumber, vendorShopNumberOfFloors,
            vendorShopNumberOfStalls,
            vendorShopOpeningTime,
            vendorShopClosingTime,
            vendorShopDescription,
            vendorShopImages: uploadedShopImages,
            profile: profileUpload.secure_url,
            role: "vendor",
            otp,
            otpExpiry,
            isEmailVerified: false,
            approvedShopStatus: "pending",
            isSubscribed: false,
            plan: "free"
        });

        // 🔹 SEND OTP
        await sendMailOtp(email, otp);

        res.status(201).json({
            message: "Vendor registered successfully. OTP sent.",
            vendorId: vendor._id
        });

    } catch (error) {
        console.error("Vendor Register Error:", error);
        res.status(500).json({ message: "Server Error" });
    }
};

const vendorLogin = async(req,res)=>{
try {
    const{email,password}=req.body

    if(!email || !password){
        return res.status(400).json({message:"All fields are required"})
    }
    const vendor = await VendorModel.findOne({email})
    if(!vendor){
        return res.status(404).json({message:"Vendor not found"})
    }

    const isPasswordMatch = await bcrypt.compare(password,vendor.password)
    if(!isPasswordMatch){
        return res.status(401).json({message:"Invalid credentials"})
    }

    if(!vendor.isEmailVerified){
        return res.status(401).json({message:"Please verify your account first"})
    }
   const accessTokens = accessToken(vendor._id)
   const refreshTokens = refreshToken(vendor._id)

   vendor.token = refreshTokens
   vendor.isLoggedIn = true
   await vendor.save()
   res.cookie("accessToken",accessTokens,{
    httpOnly:true,
    secure:isProd,
    sameSite:isProd ? "none":"lax",
    maxAge:15*60*1000
   });

   res.cookie("refreshToken",refreshTokens,{
    httpOnly:true,
    secured:isProd,
    sameSite:isProd ? "none":"lax",
    maxAge:15*60*1000
   });

   res.status(200).json({
    message:"Vendor logged in successfully",
    vendorId:vendor._id
   })

} catch (error) {
    console.error("Vendor Login Error:",error)
    return res.status(500).json({message:"Server Error"})
}    
};

const vendorLogout = async(req,res)=>{
    try {
        const vendor = await VendorModel.findById(req.userId)
        if(!vendor){
            return res.status(404).json({message:"Unauthorized"})
        }
        vendor.isLoggedIn = false
        vendor.token = ""
        await vendor.save()
        res.clearCookie("accessToken")
        res.clearCookie("refreshToken")
        res.status(200).json({message:"Vendor logged out successfully"})
    } catch (error) {
        console.error("Vendor Logout Error:",error)
        res.status(500).json({message:"Server Error"})
    }
};

const vendorVerifyOtp = async (req, res) => {
  try {
    const { email, otp, vendorLicenseNumber } = req.body;

    if (!email || !otp || !vendorLicenseNumber) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const vendor = await VendorModel.findOne({ email, vendorLicenseNumber });

    if (!vendor) {
      return res.status(404).json({ message: "Vendor not found" });
    }

    if (vendor.isEmailVerified) {
      return res.status(400).json({ message: "Vendor already verified" });
    }

    if (vendor.otpExpiry < Date.now()) {
      return res.status(400).json({ message: "OTP expired" });
    }

    if (String(vendor.otp) !== String(otp)) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    vendor.isEmailVerified = true;
    vendor.otp = undefined;
    vendor.otpExpiry = null;

    await vendor.save();

    res.status(200).json({ message: "Vendor verified successfully" });

  } catch (error) {
    console.error("Vendor Verify Otp Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
};


const  vendorResetPassword = async(req,res)=>{
  try {
      const {email,otp,newPassword,confirmPassword} = req.body
    if(!email,!otp,!newPassword,!confirmPassword){
        return res.status(400).json({message:"All fields are required"})
    }
    const vendor = await VendorModel.findOne({$or:[{email},{vendorLicenseNumber}]})
    if(!vendor){
        return res.status(404).json({message:"Vendor not found"})
    }
    if(vendor.otpExpiry < Date.now()){
        return res.status(400).json({message:"OTP expired"})
    }
    if(newPassword !== confirmPassword){
        return res.status(400).json({message:"Passwords do not match"})
    }
    vendor.password = await bcrypt.hash(newPassword,10)
    vendor.otp = null
    vendor.otpExpiry = null
    await vendor.save()
    res.status(200).json({message:"Password reset successfully"})
  } catch (error) {
      console.error("Vendor Reset Password Error:",error)
      res.status(500).json({message:"Server Error"})
  }

};

const forgotPassword=async(req,res)=>{
 try {
    const {email,vendorLicenseNumber}= req.body
    if(!email || !vendorLicenseNumber){
        return res.status(400).json({message:"All fields are required"})
    }
    const vendor = await VendorModel.findOne({$or:[{email},{vendorLicenseNumber}]})
    if(!vendor){
        return res.status(404).json({message:"Vendor not found"})
    }
    const otp = generateOtp()
    await sendMailOtp(email,otp)
    vendor.otp = otp
    vendor.otpExpiry = Date.now()+10*60*1000;
    vendor.otpLastSentAt = Date.now()
    vendor.otpLastSent = true
    vendor.otpResenCount = vendor.otpResenCount + 1
    await vendor.save()
    res.status(200).json({message:"OTP sent successfully"})

 } catch (error) {
    console.error("Forgot Password Error:",error)
    res.status(500).json({message:"Server Error"})
 }
}




export { vendorRegister, vendorLogin, vendorLogout, vendorVerifyOtp, vendorResetPassword, forgotPassword };