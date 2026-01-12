import dotenv from "dotenv/config";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import userRouter from "./routes/userRoute.js";
import connectDB from "./config/db.js";
import helmet from "helmet";
import vendorRouter from "./routes/vendorRoute.js";


const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); 
app.use(helmet({
  crossOriginResourcePolicy: false,
}));

// CORS configuration
app.set("trust proxy", 1);

const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5174",
  process.env.CLIENT_URL
].filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS blocked: ${origin}`));
    }
  },
  credentials: true
}));
connectDB();

// Static files
app.use("/uploads", express.static("uploads"));

// Routes 
app.use("/api/auth", userRouter); 
app.use('/api/auth',vendorRouter)

// Test route
app.get("/", (req, res) => {
  res.json({ message: "Server is running" });
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "Something went wrong!" });
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

export default app;