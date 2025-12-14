import express from "express";
import db from "../db.js";

const router = express.Router();

// GET /users - lấy tất cả user
router.get("/", (req, res) => {
  try {
    const stmt = db.prepare("SELECT * FROM users");
    const users = stmt.all(); // trả về mảng các dòng
    res.json(users);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// API: tạo user mới hoặc update nếu username đã tồn tại
router.post("/", (req, res) => {
  const { did, username, fullname, dob, account_number, balance } = req.body;

  if (!did || !username || !fullname || !dob || !account_number) {
    return res.status(400).json({
      error: "did, username, fullname, dob, account_number are required",
    });
  }

  try {
    // Dùng UPSERT của SQLite (ON CONFLICT)
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

    stmt.run(did, username, fullname, dob, account_number, balance || 0);

    // Lấy lại record đã insert/update
    const user = db
      .prepare("SELECT * FROM users WHERE username = ?")
      .get(username);

    return res.json({
      success: true,
      user,
    });
  } catch (err) {
    console.error("Error in /users:", err);

    // Trường hợp trùng did với username khác
    if (String(err.message).includes("UNIQUE constraint failed: users.did")) {
      return res.status(409).json({
        error: "did already used by another user",
      });
    }

    return res.status(500).json({
      error: "Internal server error",
    });
  }
});

export default router;
