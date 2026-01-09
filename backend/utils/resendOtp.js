import resend from "../config/mail.js";

const reSendOtp = async (to, otp) => {
  try {
    await resend.emails.send({
      from: process.env.EMAIL_FROM,
      to,
      subject: "Your OTP Verification Code",
      html: `
        <div style="font-family: Arial;">
          <h2>Email Verification</h2>
          <p>Your OTP is:</p>
          <h1 style="color:#4CAF50">${otp}</h1>
          <p>This OTP is valid for 10 minutes.</p>
        </div>
      `,
    });
  } catch (error) {
    console.error("Resend OTP error:", error.message);
  }
};

export default reSendOtp;
