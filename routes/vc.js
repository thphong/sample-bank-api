import express from "express";
import crypto from "crypto";
import {
  encrypt,
  decrypt,
  verify,
  createVC,
  jsonToArrayBuffer,
  convert2PrivateJsonWebKey,
  b64uToArrBuf,
  resolveDid
} from "did-core-sdk";
import { addLog } from "./log.js";
import db from "../db.js";
import dotenv from "dotenv";
dotenv.config(); // nếu chạy local

const router = express.Router();

const PUBLIC_KEY = process.env.PUBLIC_KEY;
const PRIVATE_KEY = process.env.PRIVATE_KEY;
const didBank = process.env.didBank;
const NONCE_EXPIRES_IN = process.env.NONCE_EXPIRES_IN || 300; // seconds
const VC_EXPIRES_IN = process.env.VC_EXPIRES_IN || 7776000; // seconds

const pendingNonces = new Map();

/**
 * @openapi
 * /vc/nonce:
 *   post:
 *     summary: Cấp nonce để chuẩn bị cấp VC
 *     description: >
 *       Endpoint này nhận một thông điệp đã được mã hóa (`msg`), giải mã để lấy DID của requester (`didReq`)
 *       và khóa công khai tạm (`pkReq`).  
 *       Nếu DID tồn tại trong hệ thống, server sinh một nonce tạm thời, lưu lại trong bộ nhớ (in-memory) kèm thời gian hết hạn,
 *       sau đó mã hóa lại response và trả về trong trường `resMsg`.
 *     tags:
 *       - Verifiable Credentials
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
 *                 description: Thông điệp được mã hóa chứa tối thiểu `didReq` và `pkReq`.
 *                 example: "eyJhbGciOiJFZG... (encrypted payload)"
 *     responses:
 *       200:
 *         description: Nonce được tạo và mã hóa trả về cho requester.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 resMsg:
 *                   type: string
 *                   description: >
 *                     Thông điệp đã được mã hóa bằng `pkReq`, chứa `didReq`, `nonce`
 *                     và `expires_in_seconds`.
 *                   example: "eyJhbGciOiJFZG... (encrypted response)"
 *       400:
 *         description: Thiếu dữ liệu trong request body.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Missing 'msg' in request body"
 *       404:
 *         description: User không tồn tại hoặc lỗi nội bộ (Internal Error).
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   examples:
 *                     userNotFound:
 *                       summary: Không tìm thấy user theo DID
 *                       value: "User account not found"
 *                     internalError:
 *                       summary: Lỗi nội bộ
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

    const { didReq, pkReq } = await decrypt(PUBLIC_KEY, PRIVATE_KEY, msg);

    const stmt = db.prepare("SELECT id,username FROM users WHERE did = ?");
    const user = stmt.get(didReq);

    if (!user) {
      return res.status(404).json({ error: "User account not found" });
    }

    const nonce = crypto.randomBytes(16).toString("hex");
    const expiresAt = Date.now() + Number(NONCE_EXPIRES_IN) * 1000; // 5 phút

    pendingNonces.set(didReq, { nonce, expiresAt });

    addLog(
      didReq,
      didReq,
      user.id,
      "VC_NONCE_ISSUED",
      req.ip,
      `Nonce issued for requestor=${didReq}, userdid=${didReq}, username=${user.username}`
    );

    const resMsg = await encrypt(pkReq, {
      didReq,
      nonce,
      expires_in_seconds: Number(NONCE_EXPIRES_IN),
    });

    return res.json({ resMsg });
  } catch (error) {
    console.error("error: ", error);
    return res.status(404).json({
      error: "Internal Error",
    });
  }
});

/**
 * @openapi
 * /vc/request:
 *   post:
 *     summary: Yêu cầu cấp Verifiable Credential (VC)
 *     description: >
 *       Endpoint này nhận một thông điệp đã được mã hóa (`msg`), trong đó chứa `didReq`, `nonce` và chữ ký `signReq`.  
 *       Server sẽ:
 *       - Kiểm tra nonce còn tồn tại và chưa hết hạn  
 *       - Resolve DID Document của `didReq`  
 *       - Verify chữ ký trên (didReq, nonce) bằng khóa công khai từ DID Document  
 *       - Kiểm tra DID tồn tại trong bảng `users`  
 *       - Nếu hợp lệ, sinh VC cho user với các quyền VIEW_ACCOUNT và MAKE_TRANSACTION  
 *       - Xóa nonce đã dùng và ghi log VC_ISSUED.
 *     tags:
 *       - Verifiable Credentials
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
 *                 description: >
 *                   Thông điệp được mã hóa, bên trong chứa `didReq`, `nonce` và `signReq`
 *                   (chữ ký base64url trên JSON `{ didReq, nonce }`).
 *                 example: "eyJhbGciOiJFZG... (encrypted payload)"
 *     responses:
 *       200:
 *         description: VC được cấp thành công cho DID của người dùng.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 vc:
 *                   type: object
 *                   description: Verifiable Credential được cấp.
 *                   example:
 *                     "@context":
 *                       - "https://www.w3.org/2018/credentials/v1"
 *                     type:
 *                       - "VerifiableCredential"
 *                       - "BankAccessCredential"
 *                     issuer: "did:iota:smr:0xIssuerDid"
 *                     issuanceDate: "2025-12-10T10:00:00Z"
 *                     expirationDate: "2026-03-10T10:00:00Z"
 *                     credentialSubject:
 *                       id: "did:iota:smr:0xUserDid"
 *                       VIEW_ACCOUNT: "View account balance"
 *                       MAKE_TRANSACTION: "Make a transaction"
 *                     proof:
 *                       type: "Ed25519Signature2020"
 *                       created: "2025-12-10T10:00:01Z"
 *                       verificationMethod: "did:iota:smr:0xIssuerDid#keys-1"
 *                       proofPurpose: "assertionMethod"
 *                       jws: "eyJhbGciOiJFZERTQSJ9..signature"
 *       400:
 *         description: Lỗi liên quan tới nonce hoặc body không hợp lệ.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   examples:
 *                     missingMsg:
 *                       summary: Thiếu trường msg
 *                       value: "Missing 'msg' in request body"
 *                     nonceNotFound:
 *                       summary: Chưa gọi /vc/nonce hoặc nonce không tồn tại
 *                       value: "Nonce not found. Call vc/nonce first."
 *                     invalidNonce:
 *                       summary: Nonce không khớp
 *                       value: "Invalid nonce"
 *                     nonceExpired:
 *                       summary: Nonce đã hết hạn
 *                       value: "Nonce expired"
 *       401:
 *         description: Thông tin người dùng hoặc chữ ký không hợp lệ.
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
 *                     invalidSignature:
 *                       summary: Chữ ký VP sai
 *                       value: "Invalid signature."
 *       403:
 *         description: Không thể resolve DID Document của requester.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Can't resolve did document"
 *       404:
 *         description: Lỗi nội bộ khi xử lý yêu cầu.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Internal Error"
 */
router.post("/request", async (req, res) => {
  try {
    const { msg } = req.body || {};

    if (!msg) {
      return res.status(400).json({
        error: "Missing 'msg' in request body",
      });
    }

    const { didReq, nonce, signReq } = await decrypt(
      PUBLIC_KEY,
      PRIVATE_KEY,
      msg
    );

    const nonceEntry = pendingNonces.get(didReq);
    if (!nonceEntry) {
      return res
        .status(400)
        .json({ error: "Nonce not found. Call vc/nonce first." });
    }

    if (nonceEntry.nonce !== nonce) {
      return res.status(400).json({ error: "Invalid nonce" });
    }

    if (Date.now() > nonceEntry.expiresAt) {
      pendingNonces.delete(didReq);
      return res.status(400).json({ error: "Nonce expired" });
    }

    const didDocument = await resolveDid(didReq);

    if (!didDocument) {
      return res.status(403).json({ error: "Can't resolve did document" });
    }

    //Verify VP
    const checkSign = await verify(
      jsonToArrayBuffer({ didReq, nonce }),
      b64uToArrBuf(signReq),
      didDocument.verificationMethod[0].publicKeyJwk
    );

    const stmt = db.prepare("SELECT id, username FROM users WHERE did = ?");
    const user = stmt.get(didReq);

    if (!user) {
      return res.status(401).json({ error: "Invalid username." });
    }

    if (!checkSign) {
      return res.status(401).json({ error: "Invalid signature." });
    }

    // Xoá nonce sau khi dùng
    pendingNonces.delete(didReq);

    addLog(
      didReq,
      didReq,
      user.id,
      "VC_ISSUED",
      req.ip,
      `VC issued for requestor=${didReq}, userdid=${didReq}, username=${user.username}`
    );

    const vc = await createVC(
      {
        issuer: didBank,
        subject: didReq,
        expirationDate: new Date(
          Date.now() +
          Number(VC_EXPIRES_IN) * 1000
        ).toISOString(),
        credentialSubject: {
          VIEW_ACCOUNT: "View account balance",
          MAKE_TRANSACTION: "Make a transaction",
        },
      },
      convert2PrivateJsonWebKey(PUBLIC_KEY, PRIVATE_KEY)
    );

    return res.json({
      vc: vc,
    });
  } catch (error) {
    console.error("error: ", error);
    return res.status(404).json({
      error: "Internal Error",
    });
  }
});

export default router;
