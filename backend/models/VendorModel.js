import mongoose from "mongoose";

const vendorSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, index: true },
  profile: { type: String, default: "" },
  password: { type: String, required: true },
  location: { type: String, required: true },
  role: { type: String, enum: ["vendor", "seller", "superadmin", "user"], default: "vendor" },

  isEmailVerified: { type: Boolean, default: false },
  isLoggedIn: { type: Boolean, default: false },

  otp: { type: String, required: true },
  otpExpiry: { type: Date, default: null },
  token: { type: String, default: "" },

  isSubscribed: { type: Boolean, default: false },
  plan: { type: String, enum: ["free", "premium"], default: "free" },

  shopName: { type: String, required: true },
  vendorShopAddress: { type: String, required: true },
  vendorContactNumber: { type: String, required: true },
  vendorShopImages: { type: [String], required: true },

  vendorLicenseNumber: { type: String, required: true },
  vendorShopNumberOfFloors: { type: Number, required: true },
  vendorShopNumberOfStalls: { type: Number, required: true },
  vendorShopOpeningTime: { type: String, required: true },
  vendorShopClosingTime: { type: String, required: true },
  vendorShopDescription: { type: String, required: true },

  approvedShopStatus: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
  rejectedReason: { type: String, default: "" }

}, { timestamps: true });

const VendorModel = mongoose.models.Vendor || mongoose.model("Vendor", vendorSchema);
export default VendorModel;
