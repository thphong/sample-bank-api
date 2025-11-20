import { encrypt, decrypt, createVP } from "did-core-sdk";
import express from "express";

const router = express.Router();

router.get("/encrypt", async (req, res) => {
  try {
    const { publicKey, objs } = req.body || {};

    const enc = await encrypt(publicKey, objs);
    res.json({ msg: enc });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: err });
  }
});

router.get("/decrypt", async (req, res) => {
  try {
    const { publicKey, privateKey, msg } = req.body || {};

    const dec = await decrypt(publicKey, privateKey, msg);
    res.json({ objs: dec });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: err });
  }
});

router.get("/make-vp", async (req, res) => {
  try {
    const { vcs, holderDid, holderPrivateKeyJwk, nonce } = req.body || {};

    const vp = await createVP(vcs, holderDid, holderPrivateKeyJwk, nonce);
    res.json({ vp: vp });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: err });
  }
});

export default router;
