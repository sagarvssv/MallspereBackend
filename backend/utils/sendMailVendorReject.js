import resend from "../config/mail.js";

const sendMailVendorReject = async (email, name) => {
  await resend.emails.send({
    from: process.env.EMAIL_FROM,
    to: email, // ✅ FIX
    subject: "Your Account Approved",
    html: `
      <h3>Hello ${name},</h3>
      <p>Your vendor account has been rejected.</p>
      <p>Please make sure to address the reason for rejection.</p>
    `,
  });
};

export default sendMailVendorReject;
