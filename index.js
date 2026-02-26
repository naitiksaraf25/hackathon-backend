const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

const SECRET_KEY = "hackathon_secret_key";

// ✅ Railway compatible PORT
const PORT = process.env.PORT || 5000;

// ✅ SQLite database (same folder me create hoga)
const db = new sqlite3.Database("./database.db");

// ✅ Tables create
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      role TEXT
    )
  `);
});


// =============================
// REGISTER (Citizen + Admin)
// =============================
app.post("/register", async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: "All fields required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)`,
      [name, email, hashedPassword, role],
      function (err) {
        if (err) {
          return res.status(400).json({ message: "User already exists" });
        }

        res.json({ message: "User registered successfully" });
      }
    );
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});


// =============================
// LOGIN (Citizen + Admin)
// =============================
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.get(
    `SELECT * FROM users WHERE email = ?`,
    [email],
    async (err, user) => {
      if (err || !user) {
        return res.status(400).json({ message: "Invalid credentials" });
      }

      const validPassword = await bcrypt.compare(password, user.password);

      if (!validPassword) {
        return res.status(400).json({ message: "Invalid credentials" });
      }

      const token = jwt.sign(
        { id: user.id, role: user.role },
        SECRET_KEY,
        { expiresIn: "1d" }
      );

      res.json({
        message: "Login successful",
        token,
        role: user.role
      });
    }
  );
});


// =============================
// TEST ROUTE
// =============================
app.get("/", (req, res) => {
  res.send("Backend is running 🚀");
});


// =============================
// START SERVER
// =============================
app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
