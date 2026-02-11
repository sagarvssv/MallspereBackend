import mongoose from "mongoose";

const vendorSchema = new mongoose.Schema(
  {
    // 🔹 UNIQUE VENDOR (MALL OWNER) ID
    vendorId: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    // 🔹 BASIC INFO
    name: { type: String, required: true },
    email: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    profile: { type: String, default: "" },
    password: { type: String, required: true },
    location: { type: String, required: true },
    role: {
      type: String,
      enum: ["vendor", "seller", "superadmin", "user"],
      default: "vendor"
    },
    // 🔹 AUTH & OTP
    isEmailVerified: { type: Boolean, default: false },
    isLoggedIn: { type: Boolean, default: false },
    otp: { type: String },
    otpExpiry: { type: Date },
    token: { type: String, default: "" },
    otpLastSentAt: { type: Date, default: null },
    otpLastSent: { type: Boolean, default: false },
    otpResendCount: { type: Number, default: 0 },
    // 🔹 SUBSCRIPTION
    isSubscribed: { type: Boolean, default: false },
    plan: {
      type: String,
      enum: ["free", "premium"],
      default: "free"
    },
    // 🔹 MALL / SHOP INFO
    mallName: { type: String, required: true }, // Changed from array to single string
    vendorShopAddress: { type: String, required: true },
    vendorContactNumber: { type: String, required: true },
    vendorShopImages: { type: [String], required: true },
    vendorLicenseNumber: { type: String, required: true },
    vendorShopNumberOfFloors: { type: Number, required: true },
    vendorShopNumberOfStalls: { type: Number, required: true },
    vendorShopOpeningTime: { type: String, required: true },
    vendorShopClosingTime: { type: String, required: true },
    vendorShopDescription: { type: String, required: true },
    // 🔹 ADMIN APPROVAL
    vendorAdminApproval: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
    vendorAdminRejectedReason: { type: String, default: "" },
    vendorAdminApprovedby: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "SuperAdmin",
      default: null
    },
    vendorAdminApprovedAt: {
      type: Date,
      default: null
    },
    vendorAdminRejectedAt: {
      type: Date,
      default: null
    },
    vendorAdminIsActive: {
      type: Boolean,
      default: false
    },
    // 🔹 STALL LICENSES (NEW)
    stallLicenses: [
      {
        licenseId: { type: String, required: true, unique: true },
        mallName: { type: String, required: true },
        category: { type: String, default: null },
        isUsed: { type: Boolean, default: false },
        usedAt: { type: Date, default: null },
        usedForShopId: { type: String, default: null },
        generatedAt: { type: Date, default: Date.now },
        expiresAt: { type: Date, required: true }, // 30 days from generation
        isActive: { type: Boolean, default: true },
        isExpired: { type: Boolean, default: false }
      }
    ],
    // 🔹 STALLS (EACH NEEDS ADMIN APPROVAL)
    shops: [
      {
        shopId: { type: String, required: true },
        shopName: { type: String, required: true },
        mallName: { type: String, required: true },
        category: { type: String, required: true },
        licenseId: { type: String, required: true }, // Link to license
        floorNumber: { type: Number, required: true },
        approvalStatus: {
          type: String,
          enum: ["pending", "approved", "rejected"],
          default: "pending"
        },
        rejectedReason: {
          type: String,
          default: ""
        },
        isActive: {
          type: Boolean,
          default: false
        },
     
        createdAt: { type: Date, default: Date.now }
      }

    ],
       totalLicenses: {
          type: Number,
          default: 0
        },

        usedLicenses: {
          type: Number,
          default: 0
        },
        availableLicenses: {
          type: Number,
          default: 0
        },
  },
  { timestamps: true }
);

const VendorModel =
  mongoose.models.Vendor || mongoose.model("Vendor", vendorSchema);
export default VendorModel;