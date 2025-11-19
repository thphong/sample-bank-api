import { encrypt, decrypt } from "did-core-sdk";
import express from "express";

const router = express.Router();

router.get("/encrypt", async (req, res) => {
  try {
    const { publicKey, objs } = req.body || {};

    const enc = await encrypt(publicKey, objs);
    res.json({ msg: enc });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: "Database error" });
  }
});

router.get("/decrypt", async (req, res) => {
  try {
    const { publicKey, privateKey, msg } = req.body || {};

    const dec = await decrypt(publicKey, privateKey, msg);
    res.json({ objs: dec });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: "Database error" });
  }
});

export default router;