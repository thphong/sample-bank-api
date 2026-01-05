import { DatabaseSync } from "node:sqlite";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
dotenv.config(); // nếu chạy local

// Khởi tạo SQLite dùng module built-in của Node 22
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dbPath = path.join(__dirname, "app.db");
const db = new DatabaseSync(dbPath);
const didUser = process.env.didUser;

// Tạo bảng nếu chưa có
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    fullname TEXT NOT NULL,
    account_number TEXT NOT NULL,
    balance NUMERIC(18,2) NOT NULL,
    dob DATE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

const stmt = db.prepare(`
      INSERT INTO users (did, username, fullname, dob, account_number, balance)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(username)
      DO UPDATE SET
        did = excluded.did,
        fullname = excluded.fullname,
        dob = excluded.dob,
        account_number = excluded.account_number,
        balance = excluded.balance
    `);

stmt.run(didUser, 'thphong', 'Dương Thành Phong', '1990-01-01', '0441000160289', 150000000);

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

export default db;
