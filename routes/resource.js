import express from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config(); // nếu chạy local

const JWT_SECRET = process.env.JWT_SECRET;

const router = express.Router();

// Middleware kiểm tra Bearer token
function authenticateToken(req, res, next) {
  // Lấy token từ header: Authorization: Bearer <token>
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "missing_token" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error(err);
      return res.status(403).json({ error: "invalid_or_expired_token" });
    }

    // user = payload đã sign ở auth-server
    req.user = user;
    next();
  });
}

// API public (không cần token)
router.get("/public", (req, res) => {
  res.json({ message: "This is public resource" });
});

// API protected (cần token)
router.get("/me", authenticateToken, (req, res) => {
  // req.user được gắn trong middleware authenticateToken
  res.json({
    message: "Protected resource",
    user: {
      id: req.user.sub,
      username: req.user.username,
      roles: req.user.roles,
    },
  });
});

export default router;
