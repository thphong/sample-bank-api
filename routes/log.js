import express from "express";
import db from "../db.js";

const router = express.Router();

// Helper ghi log
export function addLog(didReq, didOri, userId, action, ip, details) {
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

// GET /logs - lấy tất cả log
router.get("/", (req, res) => {
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

export default router;
