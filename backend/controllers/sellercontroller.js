import validator from "validator";
import SellerModel from "../models/SellerModel.js";
import cloudinary from "../config/cloudinary.js";
import VendorModel from "../models/VendorModel.js";
import bcrypt from "bcryptjs";
import generateOtp from "../utils/generateOtp.js";
import { generateShopId } from "../utils/IdGenerator.js";
import sendOtpMail from "../utils/sendMailOtp.js";
import { accessToken, refreshToken } from "../utils/generateToken.js";

const sellerStallRegister = async (req, res) => {
    try {
        const {
            name,
            email,
            password,
            licenseId,
            mallName,
            shopName,
            category,
            sellerShopAddress,
            sellerContactNumber,
            location,
            floorNumber
        } = req.body;

        // 🔹 Required fields check
        if (
            !name || !email || !password || !licenseId || !mallName || !shopName ||
            !category || !sellerShopAddress || !sellerContactNumber || !location || !floorNumber
        ) {
            return res.status(400).json({ message: "All fields are required" });
        }

        // 🔹 Email validation
        if (!validator.isEmail(email)) {
            return res.status(400).json({ message: "Invalid email format" });
        }

        // 🔹 Find vendor by license
        const vendor = await VendorModel.findOne({
            "stallLicenses.licenseId": licenseId
        });

        if (!vendor) return res.status(400).json({ message: "Invalid license ID" });

        // 🔹 Validate license
        const license = vendor.stallLicenses.find(li => li.licenseId === licenseId);
        if (!license) return res.status(400).json({ message: "Invalid license ID" });
        if (license.isUsed) return res.status(400).json({ message: "License ID already used" });
        if (new Date() > new Date(license.expiresAt)) return res.status(400).json({ message: "License ID has expired" });

        // 🔹 Password strength
        if (!validator.isStrongPassword(password, {
            minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1
        })) {
            return res.status(400).json({ message: "Password is not strong enough" });
        }

        // 🔹 Contact number
        if (!validator.isMobilePhone(sellerContactNumber, 'any')) {
            return res.status(400).json({ message: "Invalid contact number" });
        }

        // 🔹 Check existing seller
        const existingSeller = await SellerModel.findOne({ email });
        if (existingSeller) {
            if (!existingSeller.isEmailVerified) {
                return res.status(400).json({ message: "Email not verified yet. Please verify first." });
            }
            return res.status(409).json({ message: "Seller already exists" });
        }

        // 🔹 Profile picture upload
        const profilePicture = req.files?.profilePicture?.[0]?.path;
        if (!profilePicture) return res.status(400).json({ message: "Profile picture is required" });

        const profileUpload = await cloudinary.uploader.upload(profilePicture, {
            folder: "sellerProfilePictures",
            use_filename: true,
            unique_filename: true,
            resource_type: "image"
        });

        // 🔹 Stall images upload
        const stallFiles = req.files?.sellerShopImage;
        if (!stallFiles || stallFiles.length === 0) return res.status(400).json({ message: "Stall images are required" });

        const uploadedStallImages = [];
        for (const file of stallFiles) {
            const upload = await cloudinary.uploader.upload(file.path, {
                folder: "sellerStallImages",
                use_filename: true,
                unique_filename: true,
                resource_type: "image"
            });
            uploadedStallImages.push(upload.secure_url);
        }

        // 🔹 Hash password & generate OTP
        const hashedPassword = await bcrypt.hash(password, 10);
        const otp = generateOtp();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 min

        // 🔹 Shop ID
        const shopId = generateShopId(mallName, category);

        // 🔹 Create seller
        const newSeller = new SellerModel({
            name,
            email,
            password: hashedPassword,
            licenseId,
            mallName,
            shopName,
            category,
            sellerShopAddress,
            sellerContactNumber,
            location,
            floorNumber,
            profilePicture: profileUpload.secure_url,
            sellerShopImage: uploadedStallImages[0],       // main image
            sellerShopImages: uploadedStallImages,        // all images
            shopId,
            role: "seller",
            otp,
            otpExpiry,
            isEmailVerified: false,
            isLoggedIn: false,
            isActive: false,
            vendorApprovalStatus: "pending",
            vendorId: vendor._id,                          // MongoDB reference
            vendorCustomId: vendor.vendorId,              // your unique string
            offersCreated: []
        });

        await newSeller.save();

        // 🔹 Mark license as used
        license.isUsed = true;
        license.category = category;
        license.usedAt = new Date();
        license.usedForShopId = shopId;
        const licenses = vendor.stallLicenses || [];
        vendor.totalLicenses = licenses.length;
        vendor.usedLicenses = vendor.stallLicenses.filter(li => li.isUsed === true).length;
        vendor.availableLicenses = vendor.totalLicenses - vendor.usedLicenses;
        await vendor.save();  // save license change

        // 🔹 Add shop info to vendor
        vendor.shops = vendor.shops || [];
        vendor.shops.push({
            shopId,
            shopName,
            mallName,
            category,
            licenseId,
            floorNumber,
            approvalStatus: "pending"
        });
        await vendor.save();

        // 🔹 Send OTP mail
        await sendOtpMail(email, otp);

        res.status(201).json({
            message: "Seller stall registered successfully. Please verify your email to activate your account.",
            sellerId: newSeller.shopId,
            email: newSeller.email,
            offersCreated: newSeller.offersCreated
        });

    } catch (error) {
        console.error("Seller Stall Register error:", error);
        res.status(500).json({ error: error.message });
    }
};

const sellerStallLogin = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required" });
        }

        const seller = SellerModel.findOne({ email });
        if (!seller) {
            return res.status(404).json({ message: "Seller stall not found" });
        }

        const isMatch = await bcrypt.compare(password, seller.password);
        if (!isMatch) {
            return res.status(401).json({ message: "Invalid credentials" });
        }
        const accessTokenValue = accessToken(seller._id);
        const refressTokenValue = refreshToken(seller._id);
        seller.token = refressTokenValue;
        seller.isLoggedIn = true;
        await seller.save();
        res.cookie("accessToken", accessTokenValue, {
            httpOnly: true,
            secure: isProd,
            sameSite: isProd ? "none" : "lax",
            maxAge: 24 * 15 * 60 * 1000,
        });

        res.cookie("refreshToken", refreshTokenValue, {
            httpOnly: true,
            secure: isProd,
            sameSite: isProd ? "none" : "lax",
            maxAge: 7 * 24 * 15 * 60 * 1000,
        });

        res.status(200).json({
            message: "Seller stall logged in successfully",
            sellerId: seller.shopId,
            email: seller.email,
            offersCreated: seller.offersCreated
        });
    } catch (error) {
        console.error("Seller Stall Login error:", error);
        res.status(500).json({ error: error.message });

    }

};



export { sellerStallRegister, sellerStallLogin };