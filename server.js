const express = require("express");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// PostgreSQL pool
const pool = new Pool({
  connectionString: "postgresql://postgres:Vaibhav@0106@db.fxmgvysxzvspjjonfliw.supabase.co:5432/postgres",
  ssl: { rejectUnauthorized: false }
});

// Create tables if not exists
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS bookmarks (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      url TEXT NOT NULL,
      UNIQUE(user_id, url)
    );
  `);
  console.log("Tables ensured.");
})();

// Validate email
function isValidEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

// Register
app.post("/api/register", async (req, res) => {
  const { name, username, email, password, confirmPassword } = req.body;
  if (!name || !username || !email || !password || !confirmPassword)
    return res.status(400).json({ success: false, message: "All fields are required" });
  if (!isValidEmail(email))
    return res.status(400).json({ success: false, message: "Invalid email format" });
  if (password !== confirmPassword)
    return res.status(400).json({ success: false, message: "Passwords do not match" });

  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (name, username, email, password_hash) VALUES ($1, $2, $3, $4)",
      [name, username, email, hash]
    );
    res.json({ success: true });
  } catch (err) {
    if (err.message.includes("users_username_key"))
      return res.status(400).json({ success: false, message: "Username already taken" });
    if (err.message.includes("users_email_key"))
      return res.status(400).json({ success: false, message: "Email already registered" });
    console.error(err);
    res.status(500).json({ success: false, message: "Database error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password)
    return res.status(400).json({ success: false, message: "Login and password required" });

  try {
    const result = await pool.query(
      "SELECT id, name, username, email, password_hash FROM users WHERE email = $1 OR username = $1",
      [login]
    );
    if (result.rows.length === 0)
      return res.status(400).json({ success: false, message: "Invalid login or password" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ success: false, message: "Invalid login or password" });

    res.json({ success: true, username: user.username, userId: user.id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Database error" });
  }
});

// Bookmarks sync
app.post("/api/sync/bookmarks", async (req, res) => {
  const { userId, bookmarks } = req.body;
  if (!userId || !Array.isArray(bookmarks))
    return res.status(400).json({ success: false, message: "Invalid payload" });

  try {
    await pool.query("BEGIN");
    await pool.query("DELETE FROM bookmarks WHERE user_id = $1", [userId]);
    for (const bm of bookmarks) {
      await pool.query("INSERT INTO bookmarks (user_id, title, url) VALUES ($1, $2, $3)", [
        userId,
        bm.title,
        bm.url
      ]);
    }
    await pool.query("COMMIT");
    res.json({ success: true });
  } catch (err) {
    await pool.query("ROLLBACK");
    console.error(err);
    res.status(500).json({ success: false, message: "Database error" });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
 


