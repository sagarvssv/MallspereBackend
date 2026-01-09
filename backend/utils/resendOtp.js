import transporter from "../config/mail.js";


const reSendOtp=(to,otp)=>{
 const mailOptions ={
   from: `"Mallsphere" <${process.env.EMAIL_USER}>`,
   to: to,
   subject: "Your OTP Verification Code",
   html: `
     <div style="font-family: Arial;">
       <h2>Email Verification</h2>
       <p>Your OTP is:</p>
       <h1 style="color:#4CAF50">${otp}</h1>
       <p>This OTP is valid for 10 minutes.</p>
     </div>
   `,
 };

 try {
   transporter.sendMail(mailOptions);
 } catch (error) {
   console.log(error);
 }

}

export default reSendOtp