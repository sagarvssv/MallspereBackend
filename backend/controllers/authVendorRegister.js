import validator from "validator";
import bcrypt from "bcryptjs";
import cloudinary from "../config/cloudinary.js";
import VendorModel from "../models/VendorModel.js";
import generateOtp from "../utils/generateOtp.js";
import sendOtpMail from "../utils/sendMailOtp.js";

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
        await sendOtpMail(email, otp);

        res.status(201).json({
            message: "Vendor registered successfully. OTP sent.",
            vendorId: vendor._id
        });

    } catch (error) {
        console.error("Vendor Register Error:", error);
        res.status(500).json({ message: "Server Error" });
    }
};


export { vendorRegister };