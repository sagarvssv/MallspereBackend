import mongoose from "mongoose";


const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    profilePicture: {
        type: String,
        default: ""
    },
    password: {
        type: String,
        required: true,
    },
    role: {
        type: String,
        enum: ["user", "admin", "superadmin", "seller"],
        default: "user"
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    isLoggedIn: {
        type: Boolean,
        default: false
    },
    otp: {
        type: String,
        default: ""
    },
    token: {
        type: String,
        default: ""
    },
    otpExpiry: {
        type: Date,
        default: null
    },
        otpLastSent: { 
            type: Boolean,
             default: false },

    otpLastSentAt: {
        type: Date,
        default: null
    },
    otpResendCount: {
        type: Number,
        default: 0
    },
    savedOffers: {
        type: [String],
        default: []
    }
}, {
    timestamps: true
})


const UserModel = mongoose.models.User || mongoose.model("User", userSchema);

export default UserModel;