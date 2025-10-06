// server.js
import express from "express";
import { Pool } from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(express.json());
app.use(cookieParser());

// --- Config ---
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "trocaistoemprod";
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Render fornece
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

// --- Helpers ---
const createToken = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });

const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
};

// --- Routes ---
app.post("/api/register", async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password) return res.status(400).json({ error: "username + password required" });

  try {
    const hashed = await bcrypt.hash(password, 10);
    const query = `INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email`;
    const { rows } = await pool.query(query, [username, email || null, hashed]);
    const user = rows[0];
    const token = createToken({ id: user.id, username: user.username });
    res.cookie("fc_token", token, { httpOnly: true, sameSite: "lax", maxAge: 7*24*60*60*1000 });
    res.json({ ok: true, user });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "username or email already exists" });
    console.error(err);
    res.status(500).json({ error: "server error" });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "username + password required" });

  try {
    const { rows } = await pool.query(`SELECT id, username, password, email FROM users WHERE username=$1`, [username]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: "invalid credentials" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "invalid credentials" });

    const token = createToken({ id: user.id, username: user.username });
    res.cookie("fc_token", token, { httpOnly: true, sameSite: "lax", maxAge: 7*24*60*60*1000 });
    res.json({ ok: true, user: { id: user.id, username: user.username, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "server error" });
  }
});

// Rota protegida exemplo
app.get("/api/me", async (req, res) => {
  const token = req.cookies.fc_token;
  if (!token) return res.status(401).json({ error: "unauthorized" });

  const data = verifyToken(token);
  if (!data) return res.status(401).json({ error: "invalid token" });

  const { rows } = await pool.query(`SELECT id, username, email FROM users WHERE id=$1`, [data.id]);
  res.json({ ok: true, user: rows[0] });
});

// --- Start ---
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
