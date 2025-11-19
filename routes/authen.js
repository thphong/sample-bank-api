import express from "express";
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
const pendingNonces = new Map();

// GET /login_nonce?username=...
router.get("/login_nonce", async (req, res) => {
  const { msg } = req.body || {};
  if (!msg) {
    return res.status(400).json({
      error: "Missing 'msg' in request body",
    });
  }

  const { didReq, didOri, pkReq } = await decrypt(PUBLIC_KEY, PRIVATE_KEY, msg);

  const stmt = db.prepare("SELECT id,username FROM users WHERE did = ?");
  const user = stmt.get(didOri);

  if (!user) {
    return res.status(404).json({ error: "User account not found" });
  }

  const nonce = crypto.randomBytes(16).toString("hex");
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 phút

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
    expires_in_seconds: 300,
  });

  return res.json({ resMsg });
});

// POST /login  body: { username, password, nonce }
router.post("/login", async (req, res) => {
  try {
    const { msg } = req.body || {};

    if (!msg) {
      return res.status(400).json({
        error: "Missing 'msg' in request body",
      });
    }

    const { vp } = await decrypt(PUBLIC_KEY, PRIVATE_KEY, msg);

    console.log('vp ', vp);

    const didReq = vp.holder;
    const nonce = vp.challenge;

    const nonceEntry = pendingNonces.get(didReq);
    if (!nonceEntry) {
      return res
        .status(400)
        .json({ error: "Nonce not found. Call /login_nonce first." });
    }

    if (nonceEntry.nonce !== nonce) {
      return res.status(400).json({ error: "Invalid nonce" });
    }

    if (Date.now() > nonceEntry.expiresAt) {
      pendingNonces.delete(didReq);
      return res.status(400).json({ error: "Nonce expired" });
    }

    console.log('verifyVP');

    //Verify VP
    const { holder, issuer, parentIssuer, credentialSubjects } = await verifyVP(
      vp,
      nonce
    );
    const didOri = parentIssuer ? issuer : holder;
    console.log('didOri', didOri);
    
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

    console.log('GetUser');

    if (!user) {
      return res.status(401).json({ error: "Invalid username." });
    }

    // Xoá nonce sau khi dùng
    pendingNonces.delete(didReq);

    addLog(
      didReq,
      didOri,
      user.id,
      "LOGIN_SUCCESS",
      req.ip,
      "User logged in successfully"
    );

    return res.json({
      message: "Login successful",
      user: {
        id: user.id,
        username: user.username,
      },
    });
  } catch (err) {
    console.error("Error", err);
    return res.status(404).json({ error: err });
  }
});

export default router;
