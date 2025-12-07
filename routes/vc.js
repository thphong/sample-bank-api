import express from "express";
import crypto from "crypto";
import {
  encrypt,
  decrypt,
  verify,
  createVC,
  jsonToArrayBuffer,
  convert2PrivateJsonWebKey,
  convert2PublicJsonWebKey,
  b64uToArrBuf
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

// GET /login_nonce?username=...
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

// POST /login  body: { username, password, nonce }
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

    //Verify VP
    const checkSign = await verify(
      jsonToArrayBuffer({ didReq, nonce }),
      b64uToArrBuf(signReq),
      convert2PublicJsonWebKey(PUBLIC_KEY)
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
        expirationDate: (
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
