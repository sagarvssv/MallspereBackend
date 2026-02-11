import express from 'express';
import {
    getpendingvendors,
    getapprovedvendors,
    getrejectedvendors,
    getallvendors,
    superAdminRegister,
    superAdminLogin,
    SuperAdminchangePassword,
    SuperAdminforgotPassword,
    SuperAdminReSetPassword,
    superAdminVerifyOtp,
    superAdminOtpResend,
    superAdminProfile,
    superAdminLogout,
    superAdminrefreshTokenHandler,
    superAdminApproveVendor,
    getSingleVendor,superAdminRejectVendor,superAdminVerifyForgotPasswordOtp
} from '../controllers/superAdminController.js'
import superadminauth from '../middlewares/superadminauth.js';
const superAdminRouter = express.Router();
const superAdminauth = superadminauth

//auth
superAdminRouter.post('/super-admin-login', superAdminLogin)
superAdminRouter.post('/super-admin-verify-otp', superAdminVerifyOtp)
superAdminRouter.post('/super-admin-resend-otp', superAdminOtpResend)
superAdminRouter.post('/super-admin-logout',superAdminauth, superAdminLogout)
superAdminRouter.post('/super-admin-forgot-password', SuperAdminforgotPassword)
superAdminRouter.post('/super-admin-verify-forgot-password-otp',superAdminVerifyForgotPasswordOtp)
superAdminRouter.post('/super-admin-reset-password', SuperAdminReSetPassword)
superAdminRouter.post('/super-admin-change-password',superAdminauth, SuperAdminchangePassword)
superAdminRouter.get('/super-admin-profile',superAdminauth, superAdminProfile)
superAdminRouter.get('/super-admin-refresh-token',superAdminrefreshTokenHandler)

//register
superAdminRouter.post('/super-admin-register', superAdminRegister)

//vendors
superAdminRouter.get('/single-vendor/:vendorId',superAdminauth, getSingleVendor)
superAdminRouter.patch('/super-admin-approve-vendor/:vendorId',superAdminauth, superAdminApproveVendor)
superAdminRouter.patch('/super-admin-reject-vendor/:vendorId',superAdminauth, superAdminRejectVendor)
superAdminRouter.get('/pending-vendors',superAdminauth, getpendingvendors)
superAdminRouter.get('/approved-vendors',superAdminauth, getapprovedvendors)
superAdminRouter.get('/rejected-vendors',superAdminauth, getrejectedvendors)
superAdminRouter.get('/all-vendors',superAdminauth, getallvendors)

export default superAdminRouter

