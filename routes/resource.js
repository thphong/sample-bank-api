import express from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import db from "../db.js";
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

/**
 * @openapi
 * /resource/me:
 *   get:
 *     summary: Lấy thông tin tài khoản người dùng từ Access Token
 *     description: >
 *       Endpoint bảo vệ (protected API) yêu cầu JWT Access Token hợp lệ.
 *       Token phải được gửi trong header `Authorization: Bearer <token>`.
 *
 *       Dữ liệu trả về gồm:
 *       - Thông tin người dùng trong hệ thống (username, fullname, balance, account_number)
 *       - Roles được cấp trong VC/VP và embedded vào Access Token
 *
 *     tags:
 *       - Protected Resources
 *
 *     security:
 *       - BearerAuth: []
 *
 *     responses:
 *       200:
 *         description: Truy xuất thông tin người dùng thành công.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: integer
 *                       example: 7
 *                     username:
 *                       type: string
 *                       example: "alice"
 *                     fullname:
 *                       type: string
 *                       example: "Alice Johnson"
 *                     account_number:
 *                       type: string
 *                       example: "112233445566"
 *                     balance:
 *                       type: number
 *                       example: 54000000
 *                     roles:
 *                       type: object
 *                       description: Roles được phép từ VC (filtered by ROLES env)
 *                       example:
 *                         VIEW_ACCOUNT: "View account balance"
 *                         MAKE_TRANSACTION: "Make a transaction"
 *
 *       401:
 *         description: Thiếu Bearer token trong header.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "missing_token"
 *
 *       403:
 *         description: Token không hợp lệ hoặc hết hạn.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "invalid_or_expired_token"
 */
router.get("/me", authenticateToken, (req, res) => {
  // req.user được gắn trong middleware authenticateToken

  const stmt = db.prepare("SELECT * FROM users WHERE id = ?");
  const user = stmt.get(req.user.sub);

  res.json({
    user: {
      id: user.id,
      username: user.username,
      fullname: user.fullname,
      account_number: user.account_number,
      balance: user.balance,
      roles: req.user.roles,
    },
  });
});

export default router;
