
import jwt from "jsonwebtoken";


const userauth = (req, res, next) => {
  try {
    const token = req.cookies.accessToken;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        if (err.name === "TokenExpiredError") {
          return res.status(401).json({ message: "Access token expired" });
        }
        return res.status(401).json({ message: "Invalid token" });
      }
      req.userId = decoded.id;
      next();
    });
  } catch (error) {
    console.error("Auth middleware error:", error);
    res.status(500).json({ message: "Server Error" });
  }
};

export default userauth