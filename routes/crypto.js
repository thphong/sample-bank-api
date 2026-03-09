import { encrypt, decrypt, sign, createVP, createDelegatedVC, jsonToArrayBuffer, convert2PrivateJsonWebKey, arrBuftobase64u } from "did-core-sdk";
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

router.get("/sign", async (req, res) => {
  try {
    const { publicKey, privateKey, data } = req.body || {};

    const sigBuf = await sign(
      jsonToArrayBuffer(data),
      convert2PrivateJsonWebKey(publicKey, privateKey)
    );

    const signReq = arrBuftobase64u(sigBuf);

    res.json({ signReq: signReq });
  } catch (err) {
    console.error("Error signing data:", err);
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

router.get("/make-delegated-vc", async (req, res) => {
  try {
    const { parentVC, childSubject, claims, delegatorPublickey, delegatorPrivatekey } = req.body || {};

    console.log('parentVC', parentVC);
    console.log('childSubject', childSubject);
    console.log('claims', claims);
    console.log('delegatorPublickey', delegatorPublickey);
    console.log('delegatorPrivatekey', delegatorPrivatekey);

    const now = new Date();
    const nextMonth = new Date(now);
    nextMonth.setMonth(nextMonth.getMonth() + 1);
    const expirationDate = nextMonth.toISOString();

    const delegatorKey = convert2PrivateJsonWebKey(delegatorPublickey, delegatorPrivatekey);

    const delegatedVC = await createDelegatedVC(parentVC, childSubject, claims, delegatorKey, expirationDate);
    res.json({ delegatedVC: delegatedVC });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: err });
  }
});

export default router;
