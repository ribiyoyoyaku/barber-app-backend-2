
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// ============================================================
// DATABASE
// ============================================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

// テーブル初期化
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS customers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT,
      email TEXT,
      notes TEXT,
      visits INTEGER DEFAULT 0,
      last_visit TEXT,
      total_spent INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS services (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      duration INTEGER,
      price INTEGER,
      color TEXT
    );
    CREATE TABLE IF NOT EXISTS bookings (
      id TEXT PRIMARY KEY,
      customer_id TEXT,
      customer_name TEXT,
      staff_id TEXT,
      service_id TEXT,
      date TEXT,
      time TEXT,
      slot INTEGER DEFAULT 0,
      status TEXT DEFAULT 'confirmed',
      price INTEGER,
      notes TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );
    CREATE TABLE IF NOT EXISTS staff (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      color TEXT DEFAULT '#a8c8f0',
      sort_order INTEGER DEFAULT 0
    );
  `);

  // デフォルトスタッフを挿入（なければ）
  const { rowCount: staffCount } = await pool.query("SELECT 1 FROM staff LIMIT 1");
  if (staffCount === 0) {
    const defaultStaff = [
      ["s1", "田中 一郎", "#f0a8a8", 0],
      ["s2", "佐藤 次郎", "#a8c8f0", 1],
      ["s3", "鈴木 三恵", "#b8e0c8", 2],
    ];
    for (const [id, name, color, sort_order] of defaultStaff) {
      await pool.query(
        "INSERT INTO staff (id, name, color, sort_order) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
        [id, name, color, sort_order]
      );
    }
  }

  // デフォルトサービスを挿入（なければ）
  const { rowCount } = await pool.query("SELECT 1 FROM services LIMIT 1");
  if (rowCount === 0) {
    const defaults = [
      ["sv1", "カット",            30,  3500,  "#fde8b0"],
      ["sv2", "カット＋シャンプー", 45,  4500,  "#c8e6fb"],
      ["sv3", "シェービング",       30,  2500,  "#ffd6d6"],
      ["sv4", "カラー",            90,  8000,  "#e8d5f5"],
      ["sv5", "パーマ",            120, 10000, "#d5f0e8"],
      ["sv6", "スキンフェード",     40,  4000,  "#ffe5c8"],
    ];
    for (const [id, name, duration, price, color] of defaults) {
      await pool.query(
        "INSERT INTO services (id, name, duration, price, color) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
        [id, name, duration, price, color]
      );
    }
  }

  // デフォルトパスワードを設定（なければ）
  const pw = await pool.query("SELECT value FROM settings WHERE key = 'password_hash'");
  if (pw.rowCount === 0) {
    const hash = await bcrypt.hash(process.env.SHOP_PASSWORD || "barber1234", 10);
    await pool.query(
      "INSERT INTO settings (key, value) VALUES ('password_hash', $1) ON CONFLICT DO NOTHING",
      [hash]
    );
  }

  console.log("DB initialized");
}

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
const JWT_SECRET = process.env.JWT_SECRET || "barber-secret-key-change-in-production";

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "認証が必要です" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "トークンが無効です" });
  }
}

// ============================================================
// AUTH ROUTES
// ============================================================

// POST /api/login
app.post("/api/login", async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: "パスワードを入力してください" });

    const result = await pool.query("SELECT value FROM settings WHERE key = 'password_hash'");
    if (result.rowCount === 0) return res.status(500).json({ error: "設定エラー" });

    const valid = await bcrypt.compare(password, result.rows[0].value);
    if (!valid) return res.status(401).json({ error: "パスワードが違います" });

    const token = jwt.sign({ shop: true }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "サーバーエラー" });
  }
});

// POST /api/change-password
app.post("/api/change-password", auth, async (req, res) => {
  try {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 4)
      return res.status(400).json({ error: "4文字以上のパスワードを入力してください" });
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE settings SET value = $1 WHERE key = 'password_hash'", [hash]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "サーバーエラー" });
  }
});

// ============================================================
// BOOKINGS
// ============================================================

app.get("/api/bookings", auth, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM bookings ORDER BY date, time, slot");
    res.json(rows.map(r => ({
      id: r.id, customerId: r.customer_id, customerName: r.customer_name,
      staffId: r.staff_id, serviceId: r.service_id, date: r.date,
      time: r.time, slot: r.slot, status: r.status, price: r.price, notes: r.notes,
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/bookings", auth, async (req, res) => {
  try {
    const b = req.body;
    await pool.query(
      `INSERT INTO bookings (id, customer_id, customer_name, staff_id, service_id, date, time, slot, status, price, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (id) DO UPDATE SET
         customer_id=$2, customer_name=$3, staff_id=$4, service_id=$5,
         date=$6, time=$7, slot=$8, status=$9, price=$10, notes=$11`,
      [b.id, b.customerId, b.customerName, b.staffId, b.serviceId,
       b.date, b.time, b.slot ?? 0, b.status, b.price, b.notes]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete("/api/bookings/:id", auth, async (req, res) => {
  try {
    await pool.query("DELETE FROM bookings WHERE id = $1", [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// CUSTOMERS
// ============================================================

app.get("/api/customers", auth, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM customers ORDER BY name");
    res.json(rows.map(r => ({
      id: r.id, name: r.name, phone: r.phone, email: r.email,
      notes: r.notes, visits: r.visits, lastVisit: r.last_visit, totalSpent: r.total_spent,
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/customers", auth, async (req, res) => {
  try {
    const c = req.body;
    await pool.query(
      `INSERT INTO customers (id, name, phone, email, notes, visits, last_visit, total_spent)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (id) DO UPDATE SET
         name=$2, phone=$3, email=$4, notes=$5, visits=$6, last_visit=$7, total_spent=$8`,
      [c.id, c.name, c.phone || "", c.email || "", c.notes || "",
       c.visits || 0, c.lastVisit || null, c.totalSpent || 0]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete("/api/customers/:id", auth, async (req, res) => {
  try {
    await pool.query("DELETE FROM customers WHERE id = $1", [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// SERVICES
// ============================================================

app.get("/api/services", auth, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM services ORDER BY id");
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/services", auth, async (req, res) => {
  try {
    const s = req.body; // array
    for (const sv of s) {
      await pool.query(
        `INSERT INTO services (id, name, duration, price, color)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (id) DO UPDATE SET name=$2, duration=$3, price=$4, color=$5`,
        [sv.id, sv.name, sv.duration, sv.price, sv.color]
      );
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});



// ============================================================
// START
// ============================================================
const PORT = process.env.PORT || 3001;
// STAFF ROUTES
app.get("/api/staff", auth, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM staff ORDER BY sort_order, id");
    res.json(rows.map(r => ({ id: r.id, name: r.name, color: r.color, sortOrder: r.sort_order })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post("/api/staff", auth, async (req, res) => {
  try {
    const s = req.body;
    await pool.query(`INSERT INTO staff (id, name, color, sort_order) VALUES ($1,$2,$3,$4) ON CONFLICT (id) DO UPDATE SET name=$2, color=$3, sort_order=$4`, [s.id, s.name, s.color || "#a8c8f0", s.sortOrder || 0]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete("/api/staff/:id", auth, async (req, res) => {
  try {
    await pool.query("DELETE FROM staff WHERE id = $1", [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
initDB().then(() => {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}).catch(e => {
  console.error("DB init failed:", e);
  process.exit(1);
});

