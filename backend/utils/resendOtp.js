import resend from "../config/resend.js";

const resendOtp = async (email, otp) => {
  await resend.emails.send({
    from: process.env.EMAIL_FROM,
    to: email,
    subject: "Resent OTP Code",
    html: `<h2>Your OTP: ${otp}</h2>`,
  });
};

export default resendOtp;
