import resend from "../config/mail.js";

const sendOtpMail = async (to, otp) => {
  await resend.emails.send({
    from: process.env.EMAIL_FROM,
    to,
    subject: "Your OTP Code",
    html: `
      <h2>Email Verification</h2>
      <p>Your OTP is:</p>
      <h1>${otp}</h1>
      <p>Valid for 10 minutes</p>
    `,
  });
};

export default sendOtpMail;
