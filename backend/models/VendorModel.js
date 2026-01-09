import mongoose from "mongoose";



const vendorSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    password: {
        type: String,
        required: true,
    },
    role: {
        type: String,
        enum: ["vendor", "seller", "superadmin", "user"],
        default: "vendor"
    },
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    isLoggedIn: {
        type: Boolean,
        default: false
    },
    otp: {
        type: String,
        required: true
    },
    token: {
        type: String,
        default: ""
    },
    otpExpiry: {
        type: Date,
        required: true
    },
    shopName: {
        type: String,
        required: true
    },
    vendorShopAddress: {
        type: String,
        required: true
    },
    vendorContactNumber: {
        type: String,
        required: true
    },
    vendorShopImage: {
        type: String,
        required: true
    },
    
     vendorLicenseNumber: {
        type: String,
        required: true
    },
    vendorShopNumberOfFloors: {
        type: Number,
        required: true
    },
    vendorShopNumberOfStalls: {
        type: Number,
        required: true
    },
    vendorShopTimings: {
        type: String,
        required: true
    },
    approvedShopStatus: {
        type: String,
        enum: ["pending", "approved", "rejected"],
        default: "pending"
    },
    rejectedReason: {
        type: String,
        default: ""
    }
}, {
    timestamps: true
});

const VendorModel = mongoose.models.Vendor || mongoose.model("Vendor", vendorSchema);
export default VendorModel;

       


