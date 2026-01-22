import resend from "../config/mail.js";

const sendMailVendorApproved = async (email, name) => {
  await resend.emails.send({
    from: process.env.EMAIL_FROM,
    to: email, // ✅ FIX
    subject: "Your Account Approved",
    html: `
      <h3>Hello ${name},</h3>
      <p>Your vendor account has been approved.</p>
      <p>Please log in to your account.</p>
    `,
  });
};

export default sendMailVendorApproved;
