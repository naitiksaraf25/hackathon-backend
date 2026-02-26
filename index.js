const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();

const app = express();
app.use(express.json());
app.use(cors());

const SECRET = "supersecretkey";

const db = new sqlite3.Database("./database.db");

/* ================= DATABASE ================= */

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT 'citizen'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS complaints (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      description TEXT,
      category TEXT,
      location TEXT,
      priority TEXT,
      status TEXT DEFAULT 'pending',
      citizen_id INTEGER,
      citizen_name TEXT,
      created_at TEXT
    )
  `);

  // Default Admin
  db.get(`SELECT * FROM users WHERE email='admin@nagarseva.in'`, async (err, row) => {
    if (!row) {
      const hashed = await bcrypt.hash("admin123", 10);
      db.run(`INSERT INTO users (name,email,password,role)
              VALUES (?,?,?,?)`,
              ["Admin", "admin@nagarseva.in", hashed, "admin"]);
    }
  });
});

/* ================= AUTH MIDDLEWARE ================= */

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

/* ================= REGISTER ================= */

app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password)
    return res.status(400).json({ error: "All fields required" });

  const hashed = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO users (name,email,password,role)
     VALUES (?,?,?,?)`,
    [name, email, hashed, "citizen"],
    function (err) {
      if (err) return res.status(409).json({ error: "Email exists" });

      const token = jwt.sign({ id: this.lastID }, SECRET);

      res.json({
        token,
        user: { id: this.lastID, name, email, role: "citizen" }
      });
    }
  );
});

/* ================= LOGIN ================= */

app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM users WHERE email=?`, [email], async (err, user) => {
    if (!user) return res.status(404).json({ error: "USER_NOT_FOUND" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Wrong password" });

    const token = jwt.sign({ id: user.id }, SECRET);

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  });
});

/* ================= SUBMIT COMPLAINT ================= */

app.post("/api/complaints", auth, (req, res) => {
  const { title, description, category, location, priority } = req.body;

  db.get(`SELECT * FROM users WHERE id=?`, [req.user.id], (err, user) => {

    const date = new Date().toISOString();

    db.run(
      `INSERT INTO complaints
       (title,description,category,location,priority,status,citizen_id,citizen_name,created_at)
       VALUES (?,?,?,?,?,'pending',?,?,?)`,
      [title, description, category, location, priority, user.id, user.name, date],
      function (err) {
        res.json({
          id: this.lastID,
          title,
          description,
          category,
          location,
          priority,
          status: "pending",
          citizen_name: user.name,
          created_at: date
        });
      }
    );
  });
});

/* ================= GET MY COMPLAINTS ================= */

app.get("/api/my-complaints", auth, (req, res) => {
  db.all(
    `SELECT * FROM complaints WHERE citizen_id=? ORDER BY id DESC`,
    [req.user.id],
    (err, rows) => res.json(rows)
  );
});

/* ================= GET ALL COMPLAINTS (ADMIN) ================= */

app.get("/api/complaints", auth, (req, res) => {
  db.get(`SELECT role FROM users WHERE id=?`, [req.user.id], (err, user) => {
    if (user.role !== "admin")
      return res.status(403).json({ error: "Forbidden" });

    db.all(`SELECT * FROM complaints ORDER BY id DESC`, [], (err, rows) => {
      res.json(rows);
    });
  });
});

/* ================= UPDATE STATUS ================= */

app.patch("/api/complaints/:id/status", auth, (req, res) => {
  const { status } = req.body;

  db.run(
    `UPDATE complaints SET status=? WHERE id=?`,
    [status, req.params.id],
    () => res.json({ message: "Updated" })
  );
});

/* ================= ADMIN STATS ================= */

app.get("/api/admin/stats", auth, (req, res) => {
  db.all(`SELECT status FROM complaints`, [], (err, rows) => {
    const stats = { total: rows.length, pending:0, inProgress:0, resolved:0, rejected:0 };
    rows.forEach(r => stats[r.status]++);
    res.json(stats);
  });
});

/* ================= SERVER ================= */

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("Server running"));