import validator from "validator";
import bcrypt from "bcryptjs";
import UserModel from "../models/UserModel.js";
import generateOtp from "../utils/generateOtp.js";
import { accessToken, refreshToken } from "../utils/generateToken.js";
import sendMailOtp from "../utils/sendMailOtp.js";
import cloudinary from "../config/cloudinary.js";

const isProd = process.env.NODE_ENV === "production";


const userRegister = async (req, res) => {
  try {
    const { username, email, password } = req.body

    // 1️ Validation
    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }
    let profilePicture = ''
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: "profile_pictures",
        resource_type: "image",
      });
      profilePicture = result.secure_url;
    }

    if (!validator.isEmail(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    if (password.length < 6) {
      return res.status(400).json({
        message: "Password must be at least 6 characters long",
      });
    }

    // 2️ Check existing user
    const existingUser = await UserModel.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email already in use" });
    }


    // 4️ Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 5️ Generate OTP
    const otp = generateOtp();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    // 6️ Create user
    const newUser = await UserModel.create({
      username,
      email,
      password: hashedPassword,
      profilePicture: profilePicture,
      otp,
      otpExpiry,
      isVerified: false,
      role: "user",
      isLoggedIn: false,
    });

    // Send OTP email
    await sendMailOtp(email, otp);
    await newUser.save();

    //  Final response
    res.status(201).json({
      message: "User registered successfully. OTP sent to email.",
      user: {
        id: newUser._id,
        username: newUser.username,
        password: newUser.password,
        email: newUser.email,
        profilePicture: newUser.profilePicture,
      },
    });

  } catch (error) {
    console.error("Registration Error:", error);
    res.status(500).json({ message: "Server Error", error: error.message });
  }
};



const userLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1️ Validation
    if (!email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }
    // 2️ Check user existence
    const userExisting = await UserModel.findOne({ email });
    if (!userExisting) {
      return res.status(404).json({ message: "User not found" });
    }
    // 3 Check user existence

    if (!userExisting.isVerified) {
      return res.status(401).json({ message: "Please verify your account first" });
    }

    // 4 Check password
    const isPasswordMatch = await bcrypt.compare(password, userExisting.password);
    if (!isPasswordMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    // 5 Generate tokens
    const accessTokens = accessToken(userExisting._id);
    const refreshTokens = refreshToken(userExisting._id);
    userExisting.token = refreshTokens;
    userExisting.isLoggedIn = true;
    await userExisting.save();
    // 6 Set cookies
    res.cookie("accessToken", accessTokens, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "none" : "lax",
      maxAge: 15 * 60 * 1000,
    });
    res.cookie("refreshToken", refreshTokens, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    // 7 Final response
    res.status(200).json({
      message: "User logged in successfully",
      user: {
        id: userExisting._id,
        username: userExisting.username,
        email: userExisting.email,
        profilePicture: userExisting.profilePicture,
        role: userExisting.role,
        token: userExisting.token
      },
    });

  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
}


const userLogout = async (req, res) => {
  try {
    const userId = req.userId;

    const user = await UserModel.findById(userId);
    if (!user) return res.status(404).json({ message: "Unauthorized" });

    // invalidate refresh token in DB
    user.isLoggedIn = false;
    user.token = ""; // clear refresh token
    await user.save();

    const cookieOptions = {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "none" : "lax",
    };

    // clear cookies
    res.clearCookie("accessToken", cookieOptions);
    res.clearCookie("refreshToken", cookieOptions);

    res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ message: "Server Error" });
  }
};

const VerifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: "Email and OTP are required" });
    }

    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: "User already verified" });
    }

    if (user.otpExpiry < Date.now()) {
      return res.status(400).json({ message: "OTP expired" });
    }

    if (String(user.otp) !== String(otp)) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    user.isVerified = true;
    user.otp = null;
    user.otpExpiry = null;

    await user.save();

    res.status(200).json({
      message: "User verified successfully, please login now"
    });

  } catch (error) {
    console.error("OTP Verification Error:", error);
    res.status(500).json({ message: "Server Error" });
  }
};


const otpResend = async (req, res) => {
  try {
    const { email } = req.body

    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: "User already verified" });
    }

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
      user.isVerified = false;
      user.otpResendCount = user.otpResendCount + 1;
      await user.save();
      res.status(200).json({ message: "OTP Resent successfully" });
    }

  } catch (error) {

    console.error("Resend OTP Error:", error);
    res.status(500).json({ message: "Server Error" });

  }
}


const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }
    const user = await UserModel.findOne({ email });
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

const reSetPassword = async (req, res) => {
  try {
    const { email, otp, newPassword, confirmPassword } = req.body;

    if (!email || !otp || !newPassword || !confirmPassword) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const user = await UserModel.findOne({ email });
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


const changePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword, confirmPassword } = req.body

    if (!oldPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const user = await UserModel.findById(req.userId);
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


const refreshTokenHandler = async (req, res) => {
  try {
    const refreshTokenFromCookie = req.cookies.refreshToken;

    if (!refreshTokenFromCookie) {
      return res.status(401).json({ message: "Access token expired, please login again" });
    }

    const user = await UserModel.findOne({ token: refreshTokenFromCookie });
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



export { userRegister, userLogin, userLogout, VerifyOtp, otpResend, forgotPassword, reSetPassword, changePassword, refreshTokenHandler };
