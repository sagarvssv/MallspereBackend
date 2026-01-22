import SuperAdminModel from "../models/SuperAdminModel.js";
import bcrypt from "bcryptjs";
import generateOtp from "../utils/generateOtp.js";
import sendMailOtp from "../utils/sendMailOtp.js";
import validator from "validator";
import sendMailVendorApproved from "../utils/sendMailVendorApproved.js";
import { accessToken, refreshToken } from "../utils/generateToken.js";
import VendorModel from "../models/VendorModel.js";
import sendMailVendorReject from "../utils/sendMailVendorReject.js";

const isProd = process.env.NODE_ENV === "production";

const superAdminRegister = async (req, res) => {
    try {
        let { name, email, password } = req.body;

        // 🔹 TRIM DATA
        name = name?.trim();
        email = email?.trim().toLowerCase();
        password = password?.trim();

        // 🔹 BASIC REQUIRED CHECK
        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required",
            });
        }

        // 🔹 NAME VALIDATION
        if (!validator.isLength(name, { min: 3 })) {
            return res.status(400).json({
                success: false,
                message: "Name must be at least 3 characters",
            });
        }

        // 🔹 EMAIL VALIDATION
        if (!validator.isEmail(email)) {
            return res.status(400).json({
                success: false,
                message: "Invalid email format",
            });
        }

        // 🔹 PASSWORD VALIDATION
        if (
            !validator.isStrongPassword(password, {
                minLength: 6,
                minLowercase: 1,
                minUppercase: 1,
                minNumbers: 1,
                minSymbols: 1,
            })
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Password must be at least 6 please match the password policy",
            });
        }

        // 🔹 DUPLICATE CHECK
        const existingAdmin = await SuperAdminModel.findOne({ email });
        if (existingAdmin) {
            return res.status(409).json({
                success: false,
                message: "Admin already exists",
            });
        }

        // 🔹 SUPER ADMIN LIMIT
        const superAdminCount = await SuperAdminModel.countDocuments();
        if (superAdminCount >= 2) {
            return res.status(403).json({
                success: false,
                message: "Super Admin limit reached",
            });
        }

        // 🔹 HASH PASSWORD
        const hashpassword = await bcrypt.hash(password, 10);

        // 🔹 OTP
        const otp = generateOtp();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

        // 🔹 SAVE SUPER ADMIN
        const newSuperAdmin = await SuperAdminModel.create({
            name,
            email,
            password: hashpassword,
            otp,
            otpExpiry,
            otpLastSentAt: Date.now(),
            otpLastSent: true,
        });

        // 🔹 SEND OTP
        await sendMailOtp(email, otp);

        res.status(201).json({
            success: true,
            message: "Super Admin registered successfully. OTP sent.",
            superAdmin: {
                id: newSuperAdmin._id,
                name: newSuperAdmin.name,
                email: newSuperAdmin.email,
            },
        });
    } catch (error) {
        console.error("Super Admin Register Error:", error);
        res.status(500).json({
            success: false,
            message: "Server Error",
        });
    }
};

const superAdminLogin = async (req, res) => {
    try {
        const { email, password } = req.body
        if (!email || !password) {
            return res.status(400).json({ message: "All fields are required" })
        }
        if (!validator.isEmail(email)) {
            return res.status(400).json({ message: "Invalid email format" })
        }
        if (!validator.isStrongPassword(password)) {
            return res.status(400).json({ message: "Password must be at least 6 please match the password policy" })
        }
        if(!superAdmin.isVerified) return res.status(400).json({message:"Super Admin not verified"});
        if(!superAdmin.isEmailVerified) return res.status(400).json({message:"Super Admin not verified"});
        const superAdmin = await SuperAdminModel.findOne({ email })
        if (!superAdmin) {
            return res.status(404).json({ message: "Super Admin not found" })
        }
        const isMatch = await bcrypt.compare(password, superAdmin.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Password is incorrect" });
        }


        // 5 Generate tokens
        const accessTokens = accessToken(superAdmin._id);
        const refreshTokens = refreshToken(superAdmin._id);


        superAdmin.token = refreshTokens;
        superAdmin.isLoggedIn = true;
        await superAdmin.save();
        res.cookie("accessToken", accessTokens, {
            httpOnly: true,
            secure: isProd,
            sameSite: isProd ? "none" : "lax",
        });
        res.cookie("refreshToken", refreshTokens, {
            httpOnly: true,
            secure: isProd,
            sameSite: isProd ? "none" : "lax",
        });
        // 6 Send response

        res.status(200).json({
            success: true,
            message: "Super Admin logged in successfully",
            accessToken,
            refreshToken,
            superAdmin: {
                id: superAdmin._id,
                name: superAdmin.name,
                email: superAdmin.email,
            },
        });
    } catch (error) {
        console.error("Super Admin Login Error:", error);
        res.status(500).json({ message: "Server Error" });
    }
}

 
const superAdminLogout = async(req,res)=>{
    try {
        const userId = req.userId;
        const superAdmin = await SuperAdminModel.findById(userId);
        if (!superAdmin) return res.status(404).json({ message: "Unauthorized" });
        // invalidate refresh token in DB
        superAdmin.isLoggedIn = false;
        superAdmin.token = ""; // clear refresh token
        await superAdmin.save();
        const cookieOptions = {
            httpOnly: true,
            secure: isProd,
            sameSite: isProd ? "none" : "lax",
        };
        // clear cookies
        res.clearCookie("accessToken", cookieOptions);
        res.clearCookie("refreshToken", cookieOptions);
        res.status(200).json({ message: "Super Admin logged out successfully" });
    } catch (error) {
        console.log("Logout error:");
        return res.status(500).json({ message: "Server Error" });
        
    }
}

const superAdminProfile = async (req, res) => {
    try {
        const userId = req.userId;
        const superAdmin = await SuperAdminModel.findById(userId);
        if (!superAdmin) return res.status(404).json({ message: "Unauthorized" });
        res.status(200).json({
            success: true,
            superAdmin: {
                id: superAdmin._id,
                name: superAdmin.name,
                email: superAdmin.email,
            },
        });
    } catch (error) {
        console.error("Super Admin Profile Error:", error);
        res.status(500).json({ message: "Server Error" });
    }
};

const superAdminVerifyOtp = async(req,res)=>{
    try {
        const{email,otp}=req.body;
        if(!email||!otp){
            return res.status(400).json({message:"OTP is required"})

        }
        const superAdmin = await SuperAdminModel.findOne({email});
        if(!superAdmin){
            return res.status(404).json({message:"Super Admin not found"})
        }
    
        
        if(superAdmin.isVerified){
            return res.status(400).json({message:"Super Admin already verified"})
        }
        if(superAdmin.otpExpiry<Date.now()){
            return res.status(400).json({message:"OTP expired"})
        }
        if(String(superAdmin.otp) !== String(otp)){
            return res.status(400).json({message:"Invalid OTP"})
        }
        superAdmin.isEmailVerified = true;
        superAdmin.isVerified = true;
        superAdmin.otp = null;
        superAdmin.otpExpiry = null;
        await superAdmin.save();
        res.status(200).json({message:"Super Admin verified successfully"})
        
    } catch (error) {
        console.error("Super Admin Verify OTP Error:")
        return res.status(500).json({message:"Server Error"})
    }
}
const superAdminOtpResend = async (req, res) => {
  try {
    const { email } = req.body

    const user = await SuperAdminModel.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // if (user.isVerified) {
    //   return res.status(400).json({ message: "User already verified" });
    // }

    if (user.otpLastSentAt && Date.now() - user.otpLastSentAt < 60 * 1000) {
      return res.status(429).json({ message: "Please wait before sending another OTP" });
    }
    else {
      const otp = generateOtp();
      await sendMailOtp(user.email, otp);
      user.otp = otp;
      user.otpExpiry = Date.now() + 10 * 60 * 1000;
      user.otpLastSent = true;
      user.otpLastSentAt = Date.now();
      //user.isVerified = false;
      user.otpResendCount = user.otpResendCount + 1;
      await user.save();
      res.status(200).json({ message: "OTP Resent successfully" });
    }

  } catch (error) {

    console.error("Resend OTP Error:", error);
    res.status(500).json({ message: "Server Error" });

  }
}


const SuperAdminforgotPassword = async (req, res) => {
  try {
    const { email } = req.body
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }
    const user = await SuperAdminModel.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const otp = generateOtp();
    await sendMailOtp(email, otp)
    user.otp = otp;
    user.otpExpiry = Date.now() + 10 * 60 * 1000;
    user.otpLastSent = true;
    user.otpLastSentAt = Date.now();
    await user.save();
    res.status(200).json({ message: "OTP sent successfully" });

  } catch (error) {
    console.error("Forgot Password Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
}

const SuperAdminReSetPassword = async (req, res) => {
  try {
    const { email, otp, newPassword, confirmPassword } = req.body;

    if (!email || !otp || !newPassword || !confirmPassword) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const user = await SuperAdminModel.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "Invalid OTP" });
    }

    if (user.otpExpiry < Date.now()) {
      return res.status(400).json({ message: "OTP expired" });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.otp = null;
    user.otpExpiry = null;

    await user.save();

    res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    console.error("Reset Password Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
};


const SuperAdminchangePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword, confirmPassword } = req.body

    if (!oldPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const user = await SuperAdminModel.findById(req.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Old password is incorrect" });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: "Password too short" });
    }


    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: "New password and confirm password do not match" });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.status(200).json({ message: "Password changed successfully" });

  } catch (error) {
    console.error("Change Password Error:", error);
    res.status(500).json({ message: "Server Error" });

  }
}

const superAdminrefreshTokenHandler = async (req, res) => {
  try {
    const refreshTokenFromCookie = req.cookies.refreshToken;

    if (!refreshTokenFromCookie) {
      return res.status(401).json({ message: "Access token expired, please login again" });
    }

    const user = await SuperAdminModel.findOne({ token: refreshTokenFromCookie });
    if (!user) {
      return res.status(401).json({ message: "Access token expired, please login again" });
    }

    // Generate new tokens
    const newAccessToken = accessToken(user._id);
    const newRefreshToken = refreshToken(user._id);

    // Save new refresh token in DB
    user.token = newRefreshToken;
    await user.save();

    // Set cookies
    res.cookie("accessToken", newAccessToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "none" : "lax",
      maxAge: 15 * 60 * 1000,
    });

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({ message: "Token refreshed successfully" });
  } catch (error) {
    console.error("Refresh Token Error:", error);
    return res.status(500).json({ message: "Server Error" });
  }
};



const getpendingvendors = async (req, res) => {
    try {
        const pendingVendors = await VendorModel.find({ vendorAdminApproval: "pending" }).sort({ createdAt: -1 }).select("-password -otp -token");
        res.status(200).json({
            success: true,
            vendors: pendingVendors,
            count: pendingVendors.length
        })
    } catch (error) {
        console.error("Get Pending Vendors Error:", error)
        res.status(500).json({ message: "Server Error" })

    }
}

const getapprovedvendors = async (req, res) => {
    try {
        const approvedVendors = await VendorModel.find({ vendorAdminApproval: "approved" }).sort({ createdAt: -1 }).select("-password -otp -token");
        res.status(200).json({
            success: true,
            vendors: approvedVendors,
            count: approvedVendors.length
        })
    } catch (error) {
        console.error("Get Approved Vendors Error:", error)
        res.status(500).json({ message: "Server Error" })

    }
}

const getrejectedvendors = async (req, res) => {
    try {
        const rejectedVendors = await VendorModel.find({ vendorAdminApproval: "rejected" }).sort({ createdAt: -1 }).select("-password -otp -token");
        res.status(200).json({
            success: true,
            vendors: rejectedVendors,
            count: rejectedVendors.length
        })
    } catch (error) {
        console.error("Get Rejected Vendors Error:", error)
        res.status(500).json({ message: "Server Error" })

    }
}


const getallvendors = async (req, res) => {
    try {
        const allVendors = await VendorModel.find().sort({ createdAt: -1 }).select("-password -otp -token");
        res.status(200).json({
            success: true,
            vendors: allVendors,
            count: allVendors.length
        })
    } catch (error) {
        console.error("Get All Vendors Error:", error)
        res.status(500).json({ message: "Server Error" })

    }
}

const superAdminApproveVendor = async (req, res) => {
  try {
    const { vendorId } = req.params;
    const superAdminId = req.userId; // set from auth middleware

    const vendor = await VendorModel.findOne({vendorId});

    if (!vendor) {
      return res.status(404).json({ message: "Vendor not found" });
    }

   if (vendor.vendorAdminApproval === "approved") {
  return res.status(400).json({
    message: "Vendor is already approved",
  });
}


    vendor.vendorAdminApproval = "approved";
    vendor.vendorAdminApprovedby = superAdminId;
    vendor.vendorAdminApprovedAt = new Date();
    vendor.vendorAdminRejectedReason = ""


    await vendor.save();

    await sendMailVendorApproved(vendor.email, vendor.name);

    res.status(200).json({
      success: true,
      message: "Vendor approved successfully",
      vendorId: vendor._id,
    });

  } catch (error) {
    console.error("Approve Vendor Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
};

const superAdminRejectVendor = async (req, res) => {
   try {
     const { vendorId } = req.params;
    const superAdminId = req.userId; // set from auth middleware
    const vendor = await VendorModel.findOne({vendorId});
    if (!vendor) {
      return res.status(404).json({ message: "Vendor not found" });
    }
     if (vendor.vendorAdminApproval === "rejected") {
      return res.status(400).json({
        message: "Vendor is already rejected",
      });
    }
    vendor.vendorAdminApproval = "rejected";
    vendor.vendorAdminApprovedby = superAdminId;
    vendor.vendorAdminRejectedReason = req.body.reason||"Vendor rejected by Super Admin";
    vendor.vendorAdminRejectedAt = new Date();
    vendor.vendorAdminApprovedAt = null;
    await vendor.save();
    await sendMailVendorReject(vendor.email, vendor.name);
    res.status(200).json({
      success: true,
      message: "Vendor rejected successfully",
      vendorId: vendor._id,
    });
   } catch (error) {
    console.error("Reject Vendor Error:", error);
    res.status(500).json({ message: "Server Error" });
    
   }
    
}

const getSingleVendor = async (req, res) => {
  try {
    const { vendorId } = req.params;
    const vendor = await VendorModel.findOne({vendorId}).select("-password -otp -token");
    if (!vendor) {
      return res.status(404).json({ message: "Vendor not found" });
    }
    res.status(200).json({ success: true, vendor });
  } catch (error) {
    console.error("Get Single Vendor Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
};


export {
    getpendingvendors,
    getapprovedvendors,
    getrejectedvendors,
    getallvendors,
    superAdminRegister,
    superAdminLogin,
    SuperAdminchangePassword,
    SuperAdminforgotPassword,
    SuperAdminReSetPassword,
    superAdminVerifyOtp,
    superAdminOtpResend,
    superAdminProfile,
    superAdminLogout,
    superAdminrefreshTokenHandler ,
    superAdminApproveVendor,
    superAdminRejectVendor,
    getSingleVendor
}