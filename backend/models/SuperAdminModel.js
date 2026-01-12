import mongoose from "mongoose";

const superAdminSchema = new mongoose.Schema({
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
        enum: ["superadmin", "user", "admin", "vendor"],
        default: "superadmin"
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
        default: null
    },
    otpExpiry: {
        type: Date,
        default: null
    },
    otpLastSent: {
        type: Boolean,
        default: false
    },
    otpLastSentAt: {
        type: Date,
        default: null
    },
    otpResendCount: {
        type: Number,
        default: 0
    },
    isVerified: {
        type: Boolean,
        default: false
    }
});

export default mongoose.model("SuperAdmin", superAdminSchema);