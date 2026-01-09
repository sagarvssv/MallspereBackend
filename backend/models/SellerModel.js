import mongoose from "mongoose";



const sellerSchema = new mongoose.Schema({
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
        enum: ["seller", "vendor", "superadmin", "user"],
        default: "seller"
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
    sellerShopAddress: {
        type: String,
        required: true
    },
    sellerContactNumber: {
        type: String,
        required: true
    },
    sellerShopImage: {
        type: String,
        required: true
    },
}, {
    timestamps: true
})
const SellerModel = mongoose.models.Seller || mongoose.model("Seller", sellerSchema);

export default SellerModel;
