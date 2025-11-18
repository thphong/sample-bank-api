import express from "express";
import { DatabaseSync } from "node:sqlite";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import { encrypt, decrypt, verifyVP } from "did-core-sdk";

const app = express();
const PORT = 3000;
//Todo: Need to read from Registry
const PRIVATE_KEY = "KkMJ1Pb_Z7QhMlM5PpsrfgsBTo_kDF1yIlLt818WIbg";
const PUBLIC_KEY = "esQN45b1Jny4apXOzkqojviwguOsZRNvZh6AXPeDjhY";

app.use(express.json());

// Khởi tạo SQLite dùng module built-in của Node 22
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dbPath = path.join(__dirname, "app.db");
const db = new DatabaseSync(dbPath);

// Tạo bảng nếu chưa có
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    fullname TEXT NOT NULL,
    dob DATE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    didReq TEXT, 
    didOri TEXT,
    user_id INTEGER,
    action TEXT NOT NULL,
    ip TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// Tạo user thphong nếu chưa có
(function ensureDefaultUser() {
  const stmtFind = db.prepare("SELECT id FROM users WHERE username = ?");
  const row = stmtFind.get("thphong");
  if (!row) {
    const stmtInsert = db.prepare(
      "INSERT INTO users (did, username, fullname, dob) VALUES (?, ?, ?, ?)"
    );
    stmtInsert.run(
      "did:iota:testnet:0x6fe676bbfe9e9590693c17dc743ac4adf83bf0300103d21624586700edc664bc",
      "thphong",
      "Dương Thành Phong",
      "1990-01-01"
    );
    console.log('Created default user: username="thphong"');
  }
})();

// Map lưu nonce tạm thời: { username -> { nonce, expiresAt } }
const pendingNonces = new Map();

// Helper ghi log
function addLog(didReq, didOri, userId, action, ip, details) {
  const stmt = db.prepare(
    "INSERT INTO logs (didReq, didOri, user_id, action, ip, details) VALUES (?, ?, ?, ?, ?, ?)"
  );
  stmt.run(
    didReq || null,
    didOri || null,
    userId || null,
    action,
    ip || null,
    details || null
  );
}

// GET /login_nonce?username=...
app.get("/login_nonce", async (req, res) => {
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
app.post("/login", async (req, res) => {
  const { msg } = req.body || {};

  if (!msg) {
    return res.status(400).json({
      error: "Missing 'msg' in request body",
    });
  }

  const { vp } = await decrypt(PUBLIC_KEY, PRIVATE_KEY, msg);

  const issuer = vp.verifiableCredential[0]?.issuer;
  const didReq = vp.holder;
  const nonce = vp.challenge;

  const nonceEntry = pendingNonces.get(didReq);
  if (!nonceEntry) {
    return res
      .status(400)
      .json({ error: "Nonce not found. Call /login_nonce first." });
  }

  const didOri =
    nonceEntry.didOri == didReq ? didReq : vp.verifiableCredential[0]?.issuer;

  if (nonceEntry.nonce !== nonce) {
    return res.status(400).json({ error: "Invalid nonce" });
  }

  if (Date.now() > nonceEntry.expiresAt) {
    pendingNonces.delete(didReq);
    return res.status(400).json({ error: "Nonce expired" });
  }

  //Verify VP
  /*
  const {
    holder: vp_holder,
    issuer: vp_issuer,
    parentIssuer,
    credentialSubjects,
  } = await verifyVP(vp, nonce);
  //TODO: Check holder & issuer
  */

  const stmt = db.prepare("SELECT id, username FROM users WHERE did = ?");
  const user = stmt.get(didOri);

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
});

// GET /users - lấy tất cả user
app.get("/users", (req, res) => {
  try {
    const stmt = db.prepare("SELECT * FROM users");
    const users = stmt.all(); // trả về mảng các dòng
    res.json(users);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// GET /logs - lấy tất cả log
app.get("/logs", (req, res) => {
  try {
    const stmt = db.prepare(`
      SELECT 
        id,
        didReq,
        didOri,
        user_id,
        action,
        ip,
        details,
        created_at
      FROM logs
      ORDER BY created_at DESC
    `);
    const logs = stmt.all();
    res.json(logs);
  } catch (err) {
    console.error("Error fetching logs:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.get("/encrypt", async (req, res) => {
  try {
    const { publicKey, objs } = req.body || {};

    const enc = await encrypt(publicKey, objs);
    res.json({ msg: enc });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.get("/decrypt", async (req, res) => {
  try {
    const { publicKey, privateKey, msg } = req.body || {};

    const dec = await decrypt(publicKey, privateKey, msg);
    res.json({ objs: dec });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.listen(PORT, async () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
