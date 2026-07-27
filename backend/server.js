// server.js
//
// Backend for an HONEST tap/task-to-earn Telegram Mini App.
//
// Core rule this whole file follows:
//   Points only get created when something that pays for them actually
//   happens (an ad impression, a sponsor task, an admin-approved bonus).
//   Nothing here invents balances, fakes a leaderboard, or lets a referral
//   pay out before the referred user does something real.
//
// This is a learning-scale scaffold: SQLite file, no auth provider beyond
// Telegram's own initData check. Swap in Postgres + a real ad network SDK
// when you're ready to go to production.

import express from "express";
import cors from "cors";
import crypto from "crypto";
import Database from "better-sqlite3";

const BOT_TOKEN = process.env.BOT_TOKEN || ""; // set this from @BotFather
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || ""; // set this yourself, keep it secret
const PORT = process.env.PORT || 3000;

const db = new Database("earnapp.db");
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,                 -- Telegram user id
  username TEXT,
  points INTEGER NOT NULL DEFAULT 0,
  referred_by INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL,          -- 'ad' | 'sponsor_task' | 'referral_bonus' | 'redeem'
  amount INTEGER NOT NULL,     -- positive = earned, negative = redeemed
  label TEXT NOT NULL,         -- human-readable source, shown in the open ledger
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS ad_views (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS redemptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  points INTEGER NOT NULL,
  payout_method TEXT,          -- e.g. 'Telebirr', 'CBE Birr', 'HelloCash'
  payout_account TEXT,         -- phone number / account number
  payout_name TEXT,            -- account holder name
  status TEXT NOT NULL DEFAULT 'pending', -- pending | paid | rejected
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  paid_at TEXT
);

-- Simple key/value store for admin-tracked figures, e.g. total ad revenue.
-- You update 'total_revenue_etb' by hand whenever you check your ad network's
-- dashboard, so the admin page can warn you before you approve more payouts
-- than you've actually earned.
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT '0'
);
INSERT OR IGNORE INTO settings (key, value) VALUES ('total_revenue_etb', '0');
`);

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public")); // serves public/admin.html at /admin.html

// ---------------------------------------------------------------------------
// Telegram WebApp initData verification.
// This is what stops someone from just calling your API with a made-up
// user id and crediting themselves points. Never trust a client-supplied id.
// https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
// ---------------------------------------------------------------------------
function verifyInitData(initData) {
  if (!BOT_TOKEN) {
    // Dev mode fallback only — never ship this to production.
    const params = new URLSearchParams(initData);
    const userJson = params.get("user");
    return userJson ? JSON.parse(userJson) : null;
  }
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  params.delete("hash");
  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

  const secretKey = crypto.createHmac("sha256", "WebAppData").update(BOT_TOKEN).digest();
  const computedHash = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex");

  if (computedHash !== hash) return null;
  const userJson = params.get("user");
  return userJson ? JSON.parse(userJson) : null;
}

function requireUser(req, res, next) {
  const initData = req.headers["x-telegram-init-data"];
  const tgUser = verifyInitData(initData || "");
  if (!tgUser) return res.status(401).json({ error: "Could not verify Telegram user" });
  req.tgUser = tgUser;
  next();
}

// Protects the /api/admin/* routes. This is deliberately simple (one shared
// password) since it's just you managing payouts, not a multi-admin system.
// Set ADMIN_PASSWORD on Render before relying on this in production.
function requireAdmin(req, res, next) {
  const supplied = req.headers["x-admin-password"];
  if (!ADMIN_PASSWORD || supplied !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Not authorized" });
  }
  next();
}

function getOrCreateUser(tgUser, referredBy) {
  const existing = db.prepare("SELECT * FROM users WHERE id = ?").get(tgUser.id);
  if (existing) return existing;
  db.prepare(
    "INSERT INTO users (id, username, referred_by) VALUES (?, ?, ?)"
  ).run(tgUser.id, tgUser.username || tgUser.first_name || "user", referredBy || null);
  return db.prepare("SELECT * FROM users WHERE id = ?").get(tgUser.id);
}

function credit(userId, type, amount, label) {
  const tx = db.transaction(() => {
    db.prepare("UPDATE users SET points = points + ? WHERE id = ?").run(amount, userId);
    db.prepare(
      "INSERT INTO transactions (user_id, type, amount, label) VALUES (?, ?, ?, ?)"
    ).run(userId, type, amount, label);
  });
  tx();
}

// ---------------------------------------------------------------------------
// Auth / bootstrap. Call this once when the Mini App opens.
// ---------------------------------------------------------------------------
app.post("/api/auth", (req, res) => {
  const initData = req.headers["x-telegram-init-data"];
  const tgUser = verifyInitData(initData || "");
  if (!tgUser) return res.status(401).json({ error: "Invalid Telegram data" });

  const { refCode } = req.body; // e.g. ref_<telegram_id> from the deep link
  let referredBy = null;
  if (refCode && refCode.startsWith("ref_")) {
    const refId = Number(refCode.replace("ref_", ""));
    if (refId && refId !== tgUser.id) referredBy = refId;
  }

  const user = getOrCreateUser(tgUser, referredBy);

  // Referral bonus is paid to the REFERRER only once, and only now that the
  // referred person has actually opened the app and become a real user —
  // not just for a link being clicked, and never to the new user themselves.
  if (user.referred_by && !db.prepare(
    "SELECT 1 FROM transactions WHERE type = 'referral_bonus' AND label = ?"
  ).get(`new user ${user.id}`)) {
    credit(user.referred_by, "referral_bonus", 20, `new user ${user.id}`);
  }

  res.json({ id: user.id, username: user.username, points: user.points });
});

app.get("/api/me", requireUser, (req, res) => {
  const user = db.prepare("SELECT id, username, points FROM users WHERE id = ?").get(req.tgUser.id);
  res.json(user);
});

// ---------------------------------------------------------------------------
// Rewarded ad flow.
//   1. Frontend calls your ad SDK (e.g. Adsgram) and gets a real "ad watched"
//      callback.
//   2. Frontend calls this endpoint to record it.
//   3. Server enforces a cooldown so one ad view = one credit, not spam.
// The points value here (5) should map to real, sustainable ad revenue per
// view — check what your ad network actually pays before picking a number.
// ---------------------------------------------------------------------------
const AD_COOLDOWN_SECONDS = 30;
const AD_POINTS = 5;

app.post("/api/ad/complete", requireUser, (req, res) => {
  const userId = req.tgUser.id;
  const last = db.prepare(
    "SELECT created_at FROM ad_views WHERE user_id = ? ORDER BY id DESC LIMIT 1"
  ).get(userId);

  if (last) {
    const secondsSince = (Date.now() - new Date(last.created_at + "Z").getTime()) / 1000;
    if (secondsSince < AD_COOLDOWN_SECONDS) {
      return res.status(429).json({ error: "Too soon since last ad", retryAfter: AD_COOLDOWN_SECONDS - secondsSince });
    }
  }

  db.prepare("INSERT INTO ad_views (user_id) VALUES (?)").run(userId);
  credit(userId, "ad", AD_POINTS, "Ad watched");
  const user = db.prepare("SELECT points FROM users WHERE id = ?").get(userId);
  res.json({ credited: AD_POINTS, points: user.points });
});

// ---------------------------------------------------------------------------
// Sponsor tasks (e.g. "join our channel"). In production, verify completion
// server-side (e.g. check channel membership via Bot API) rather than
// trusting a client "I did it" click.
// ---------------------------------------------------------------------------
const SPONSOR_TASKS = {
  join_my_channel: {
    points: 15,
    label: "Joined @ledgerearn"
  },
};

app.post("/api/task/complete", requireUser, (req, res) => {
  const { taskId } = req.body;
  const task = SPONSOR_TASKS[taskId];
  if (!task) return res.status(400).json({ error: "Unknown task" });

  const already = db.prepare(
    "SELECT 1 FROM transactions WHERE user_id = ? AND label = ?"
  ).get(req.tgUser.id, task.label);
  if (already) return res.status(409).json({ error: "Already completed" });

  // TODO: real verification, e.g. bot.getChatMember(channel, userId)
  credit(req.tgUser.id, "sponsor_task", task.points, task.label);
  const user = db.prepare("SELECT points FROM users WHERE id = ?").get(req.tgUser.id);
  res.json({ credited: task.points, points: user.points });
});

// ---------------------------------------------------------------------------
// The open ledger — every point this user has, with where it came from.
// This is the transparency feature: nothing is summarized away or hidden.
// ---------------------------------------------------------------------------
app.get("/api/ledger", requireUser, (req, res) => {
  const rows = db.prepare(
    "SELECT type, amount, label, created_at FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 50"
  ).all(req.tgUser.id);
  res.json(rows);
});

// Real leaderboard — no seeded fake names, just whoever has the most points.
app.get("/api/leaderboard", (req, res) => {
  const rows = db.prepare(
    "SELECT username, points FROM users ORDER BY points DESC LIMIT 20"
  ).all();
  res.json(rows);
});

// ---------------------------------------------------------------------------
// Redemption. This creates a PENDING request for a human/admin process to
// actually pay out (e.g. via Telegram Stars, or manual bank transfer review).
// It does not silently promise money the app hasn't got — and the minimum
// should be a number your ad/sponsor revenue can realistically cover.
// ---------------------------------------------------------------------------
const REDEEM_MINIMUM = 500;

app.post("/api/redeem", requireUser, (req, res) => {
  const { payoutMethod, payoutAccount, payoutName } = req.body;
  if (!payoutMethod || !payoutAccount || !payoutName) {
    return res.status(400).json({ error: "Payout method, account, and name are all required" });
  }

  const user = db.prepare("SELECT points FROM users WHERE id = ?").get(req.tgUser.id);
  if (user.points < REDEEM_MINIMUM) {
    return res.status(400).json({ error: `Minimum redemption is ${REDEEM_MINIMUM} points`, have: user.points });
  }
  const tx = db.transaction(() => {
    db.prepare("UPDATE users SET points = points - ? WHERE id = ?").run(user.points, req.tgUser.id);
    db.prepare(
      "INSERT INTO transactions (user_id, type, amount, label) VALUES (?, 'redeem', ?, 'Redemption requested')"
    ).run(req.tgUser.id, -user.points);
    db.prepare(
      "INSERT INTO redemptions (user_id, points, payout_method, payout_account, payout_name) VALUES (?, ?, ?, ?, ?)"
    ).run(req.tgUser.id, user.points, payoutMethod, payoutAccount, payoutName);
  });
  tx();
  res.json({ status: "pending", points: user.points });
});

// ---------------------------------------------------------------------------
// Admin: review and manage payout requests.
// These endpoints are for YOU, not regular users — protect ADMIN_PASSWORD
// like any other credential. Visit /admin.html on your deployed backend URL
// for a simple page that uses these.
// ---------------------------------------------------------------------------
app.get("/api/admin/redemptions", requireAdmin, (req, res) => {
  const status = req.query.status || "pending";
  const rows = db.prepare(
    `SELECT r.id, r.user_id, u.username, r.points, r.payout_method, r.payout_account,
            r.payout_name, r.status, r.created_at, r.paid_at
     FROM redemptions r JOIN users u ON u.id = r.user_id
     WHERE r.status = ? ORDER BY r.created_at ASC`
  ).all(status);
  res.json(rows);
});

app.post("/api/admin/redemptions/:id/status", requireAdmin, (req, res) => {
  const { status } = req.body; // 'paid' | 'rejected'
  if (!["paid", "rejected"].includes(status)) {
    return res.status(400).json({ error: "status must be 'paid' or 'rejected'" });
  }
  const redemption = db.prepare("SELECT * FROM redemptions WHERE id = ?").get(req.params.id);
  if (!redemption) return res.status(404).json({ error: "Not found" });

  const tx = db.transaction(() => {
    db.prepare(
      "UPDATE redemptions SET status = ?, paid_at = CASE WHEN ? = 'paid' THEN datetime('now') ELSE paid_at END WHERE id = ?"
    ).run(status, status, req.params.id);
    // If rejected, give the points back to the user.
    if (status === "rejected") {
      db.prepare("UPDATE users SET points = points + ? WHERE id = ?").run(redemption.points, redemption.user_id);
      db.prepare(
        "INSERT INTO transactions (user_id, type, amount, label) VALUES (?, 'redeem', ?, 'Redemption rejected — points returned')"
      ).run(redemption.user_id, redemption.points);
    }
  });
  tx();
  res.json({ status });
});

// Revenue tracking: you update this by hand from your ad network's dashboard.
// It's a sanity check, not an automated accounting system.
app.get("/api/admin/revenue", requireAdmin, (req, res) => {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'total_revenue_etb'").get();
  const pendingPoints = db.prepare(
    "SELECT COALESCE(SUM(points), 0) as total FROM redemptions WHERE status = 'pending'"
  ).get();
  res.json({ totalRevenueEtb: Number(row.value), pendingPointsOwed: pendingPoints.total });
});

app.post("/api/admin/revenue", requireAdmin, (req, res) => {
  const { totalRevenueEtb } = req.body;
  if (typeof totalRevenueEtb !== "number" || totalRevenueEtb < 0) {
    return res.status(400).json({ error: "totalRevenueEtb must be a non-negative number" });
  }
  db.prepare("UPDATE settings SET value = ? WHERE key = 'total_revenue_etb'").run(String(totalRevenueEtb));
  res.json({ totalRevenueEtb });
});

app.listen(PORT, () => console.log(`earnapp backend listening on :${PORT}`));
