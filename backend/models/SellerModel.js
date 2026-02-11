import mongoose from "mongoose";

const sellerSchema = new mongoose.Schema({
    // Basic Info
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
    profilePicture: { type: String, default: "" },
    location: { type: String, required: true },
    role: {
        type: String,
        enum: ["seller", "vendor", "superadmin", "user"],
        default: "seller"
    },
    
    // Auth & Verification
    isEmailVerified: { type: Boolean, default: false },
    isLoggedIn: { type: Boolean, default: false },
    otp: { type: String},
    otpExpiry: { type: Date},
    token: { type: String, default: "" },
    
    //  VENDOR CONNECTION 
    vendorId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Vendor",
        required: true,
        index: true
    },
    
    //  LICENSE CONNECTION 
    licenseId: {
        type: String,
        required: true,
        index: true
    },
    
    // 🔹 MALL INFO 
    mallName: {
        type: String,
        required: true
    },
    
    // Shop Details
    shopId: { type: String, required: true, unique: true },
    shopName: { type: String, required: true },
    category: { type: String, required: true },
    sellerShopAddress: { type: String, required: true },
    sellerContactNumber: { type: String, required: true },
    sellerShopImage: { type: String, required: true },
    floorNumber: { type: String, required: true },
    
    //  VENDOR APPROVAL 
    vendorApprovalStatus: {
        type: String,
        enum: ["pending", "approved", "rejected"],
        default: "pending"
    },
    vendorRejectedReason: { type: String, default: "" },
    vendorApprovedAt: { type: Date, default: null },
    vendorRejectedAt: { type: Date, default: null },
    isActive: { type: Boolean, default: false },
    offersCreated: { type: [String], default: [] },
    
}, { timestamps: true });

const SellerModel = mongoose.models.Seller || mongoose.model("Seller", sellerSchema);
export default SellerModel;