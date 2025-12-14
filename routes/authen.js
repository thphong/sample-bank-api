import express from "express";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { encrypt, decrypt, verifyVP } from "did-core-sdk";
import { addLog } from "./log.js";
import db from "../db.js";
import dotenv from "dotenv";
dotenv.config(); // nếu chạy local

const router = express.Router();

const PUBLIC_KEY = process.env.PUBLIC_KEY;
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const didBank = process.env.didBank;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || 3600; // seconds
const NONCE_EXPIRES_IN = process.env.NONCE_EXPIRES_IN || 300; // seconds
const roles = JSON.parse(process.env.ROLES);

const pendingNonces = new Map();

/**
 * @openapi
 * /auth/nonce:
 *   post:
 *     summary: Cấp nonce phục vụ quy trình đăng nhập SSI (VC/VP)
 *     description: >
 *       Endpoint này nhận một thông điệp đã mã hoá `msg` từ client.
 *       Server giải mã để lấy `didReq`, `didOri` và `pkReq`, sau đó:
 *       - Kiểm tra DID gốc (`didOri`) có tồn tại trong hệ thống
 *       - Sinh nonce và lưu tạm thời trong server (in-memory)
 *       - Gửi lại response đã mã hoá bằng `pkReq`, chứa `didReq`, `didOri`, `nonce`, TTL
 *
 *       Nonce dùng cho bước xác thực VP tại `/auth/access-token`.
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - msg
 *             properties:
 *               msg:
 *                 type: string
 *                 description: Thông điệp đã mã hóa chứa DID requestor và requester public key
 *                 example: "eyJhbGciOiJFZG... (encrypted)"
 *     responses:
 *       200:
 *         description: Nonce được cấp thành công và đã được mã hoá trả về trong `resMsg`.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 resMsg:
 *                   type: string
 *                   example: "eyJhbGciOiJFZG... (encrypted payload)"
 *       400:
 *         description: Request body thiếu hoặc không đúng định dạng.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Missing 'msg' in request body"
 *       404:
 *         description: DID người dùng không tồn tại hoặc lỗi hệ thống.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   examples:
 *                     userNotFound:
 *                       summary: Không có user tương ứng
 *                       value: "User account not found"
 *                     internalError:
 *                       summary: Lỗi server
 *                       value: "Internal Error"
 */
router.post("/nonce", async (req, res) => {
  try {
    const { msg } = req.body || {};
    if (!msg) {
      return res.status(400).json({
        error: "Missing 'msg' in request body",
      });
    }

    const { didReq, didOri, pkReq } = await decrypt(
      PUBLIC_KEY,
      PRIVATE_KEY,
      msg
    );

    const stmt = db.prepare("SELECT id,username FROM users WHERE did = ?");
    const user = stmt.get(didOri);

    if (!user) {
      return res.status(404).json({ error: "User account not found" });
    }

    const nonce = crypto.randomBytes(16).toString("hex");
    const expiresAt = Date.now() + Number(NONCE_EXPIRES_IN) * 1000;

    pendingNonces.set(didReq, { didOri, nonce, expiresAt });

    addLog(
      didReq,
      didOri,
      user.id,
      "LOGIN_NONCE_ISSUED",
      req.ip,
      `Nonce issued for requestor=${didReq}, userdid=${didOri}, username=${user.username}`
    );

    const resMsg = await encrypt(pkReq, {
      didReq,
      didOri,
      nonce,
      expires_in_seconds: Number(NONCE_EXPIRES_IN),
    });

    return res.json({ resMsg });
  } catch (error) {
    console.error("error: ", error);
    return res.status(404).json({
      error: error.message,
    });
  }
});

/**
 * @openapi
 * /auth/access-token:
 *   post:
 *     summary: Xác minh VP + nonce để cấp JWT Access Token
 *     description: >
 *       Endpoint này giải mã `msg` để lấy `vp` (Verifiable Presentation).
 *       Server thực hiện các bước:
 *
 *       - Lấy `holder` (didReq) và `challenge` (nonce) từ VP
 *       - Kiểm tra nonce khớp và chưa hết hạn
 *       - Verify VP bằng chuẩn DID + issuer chain
 *       - Xác định DID gốc `didOri` (trường hợp delegated VC → `parentIssuer`)
 *       - Check issuer phải là `didBank`
 *       - Lọc roles trong VC theo danh sách được phép (`roles`)
 *       - Sinh JWT access token và trả về
 *
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - msg
 *             properties:
 *               msg:
 *                 type: string
 *                 description: Thông điệp đã mã hóa chứa VP
 *                 example: "eyJhbGciOiJFZERTQSJ9... (encrypted)"
 *
 *     responses:
 *       200:
 *         description: Đăng nhập SSI thành công, JWT Access Token được cấp.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 access_token:
 *                   type: string
 *                   description: JWT access token theo chuẩn Bearer
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *                 token_type:
 *                   type: string
 *                   example: "Bearer"
 *                 expires_in:
 *                   type: number
 *                   example: 3600
 *       400:
 *         description: Nonce hoặc VP không hợp lệ.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   examples:
 *                     nonceNotFound:
 *                       summary: Chưa yêu cầu nonce
 *                       value: "Nonce not found. Call auth/nonce first."
 *                     invalidNonce:
 *                       summary: Nonce sai
 *                       value: "Invalid nonce"
 *                     nonceExpired:
 *                       summary: Nonce hết hạn
 *                       value: "Nonce expired"
 *                     invalidDidOri:
 *                       summary: didOri không khớp
 *                       value: "Invalid didOri"
 *                     invalidIssuer:
 *                       summary: Ngân hàng không phải issuer
 *                       value: "VP is not issued by bank"
 *       401:
 *         description: VC/VP hợp lệ nhưng không có roles phù hợp.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   examples:
 *                     invalidUser:
 *                       summary: DID không map với user
 *                       value: "Invalid username."
 *                     invalidSubjects:
 *                       summary: credentialSubjects không hợp lệ
 *                       value: "Invalid credential subjects"
 *                     noRoles:
 *                       summary: VC không có quyền phù hợp trong whitelist roles
 *                       value: "No property found that matches allowed roles"
 *       404:
 *         description: Lỗi xử lý hệ thống.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Internal Error"
 */
router.post("/access-token", async (req, res) => {
  try {
    const { msg } = req.body || {};

    if (!msg) {
      return res.status(400).json({
        error: "Missing 'msg' in request body",
      });
    }

    const { vp } = await decrypt(PUBLIC_KEY, PRIVATE_KEY, msg);

    const didReq = vp.holder;
    const nonce = vp.challenge;

    const nonceEntry = pendingNonces.get(didReq);
    if (!nonceEntry) {
      return res
        .status(400)
        .json({ error: "Nonce not found. Call auth/nonce first." });
    }

    if (nonceEntry.nonce !== nonce) {
      return res.status(400).json({ error: "Invalid nonce" });
    }

    if (Date.now() > nonceEntry.expiresAt) {
      pendingNonces.delete(didReq);
      return res.status(400).json({ error: "Nonce expired" });
    }

    //Verify VP
    const { holder, issuer, parentIssuer, credentialSubjects } = await verifyVP(
      vp,
      nonce
    );
    const didOri = parentIssuer ? issuer : holder;

    if (nonceEntry.didOri !== didOri) {
      return res.status(400).json({ error: "Invalid didOri" });
    }

    if (didOri == didReq) {
      if (issuer != didBank) {
        return res.status(400).json({ error: "VP is not issued by bank" });
      }
    } else {
      if (parentIssuer != didBank) {
        return res.status(400).json({ error: "VP is not issued by bank" });
      }
    }

    const stmt = db.prepare("SELECT id, username FROM users WHERE did = ?");
    const user = stmt.get(didOri);

    if (!user) {
      return res.status(401).json({ error: "Invalid username." });
    }

    // Xoá nonce sau khi dùng
    pendingNonces.delete(didReq);

    // return res.json({
    //   message: "Login successful",
    //   user: {
    //     id: user.id,
    //     username: user.username,
    //   },
    // });

    if (!credentialSubjects || !credentialSubjects.length) {
      return res.status(401).json({ error: "Invalid credential subjects" });
    }

    const allowedRoles = Object.fromEntries(
      Object.entries(credentialSubjects[0]).filter(([key]) =>
        roles.includes(key)
      )
    );

    if (allowedRoles.length === 0) {
      return res
        .status(401)
        .json({ error: "No property found that matches allowed roles" });
    }

    const payload = {
      sub: user.id, // subject (user id)
      username: user.username, // thêm thông tin cần thiết
      roles: allowedRoles, // optional
      // có thể thêm claim khác: scope, client_id, ...
    };

    const accessToken = jwt.sign(payload, JWT_SECRET, {
      expiresIn: Number(JWT_EXPIRES_IN), // giây
      issuer: didBank, // optional
      audience: didReq, // optional
    });

    addLog(
      didReq,
      didOri,
      user.id,
      "ACCESS_TOKEN_ISSUED",
      req.ip,
      `Access Token issued for requestor=${didReq}, userdid=${didOri}, username=${user.username}`
    );

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: Number(JWT_EXPIRES_IN),
      // refresh_token: "...",
    });
  } catch (error) {
    console.error("error: ", error);
    return res.status(404).json({
      error: error.message,
    });
  }
});

export default router;
