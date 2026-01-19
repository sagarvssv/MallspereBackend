
import jwt from "jsonwebtoken";


const vendorauth = (req, res, next) => {
  try {
    const token = req.cookies.accessToken;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        if (err.name === "VendorTokenExpiredError") {
          return res.status(401).json({ message: "VendorAccess token expired" });
        }
        return res.status(401).json({ message: "Invalid token" });
      }
      req.userId = decoded.id;
      next();
    });
  } catch (error) {
    console.error("VendorAuth middleware error:", error);
    res.status(500).json({ message: "Server Error" });
  }
};

export default vendorauth