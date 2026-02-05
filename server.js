const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
app.use(cors());

// Raw body für HMAC (wichtig)
app.use(
  express.json({
    limit: "256kb",
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

const PORT = process.env.PORT || 8787;
const SHARED_SECRET = process.env.SHARED_SECRET || "change-me";
const DATABASE_URL = process.env.DATABASE_URL;

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Render/Cloud
});

// ---- helpers ------------------------------------------------------

function hmacHex(secret, msg) {
  return crypto.createHmac("sha256", secret).update(msg).digest("hex");
}

function timingSafeEq(a, b) {
  try {
    const ba = Buffer.from(a, "hex");
    const bb = Buffer.from(b, "hex");
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

function verifyHmac(req) {
  const ts = req.header("x-ts");
  const nonce = req.header("x-nonce");
  const sig = req.header("x-signature");

  if (!ts || !nonce || !sig) return { ok: false, error: "missing_headers" };

  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum)) return { ok: false, error: "bad_ts" };

  // Timestamp-Toleranz: +/- 120s
  const skew = Math.abs(Date.now() - tsNum);
  if (skew > 120000) return { ok: false, error: "ts_skew" };

  const body = (req.rawBody || Buffer.from("")).toString("utf8");
  const payload = `${ts}.${nonce}.${body}`;
  const expected = hmacHex(SHARED_SECRET, payload);

  if (!timingSafeEq(expected, sig)) return { ok: false, error: "bad_signature" };
  return { ok: true };
}

async function initDb() {
  // Tabellen anlegen, falls nicht vorhanden
  await pool.query(`
    CREATE TABLE IF NOT EXISTS logs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      ts BIGINT NOT NULL,
      type TEXT NOT NULL,
      component TEXT NOT NULL,
      title TEXT NOT NULL,
      acknowledged BOOLEAN NOT NULL DEFAULT FALSE
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS statuses (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      detail TEXT NOT NULL DEFAULT '',
      severity TEXT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);
}

async function loadSnapshot() {
  const logsR = await pool.query(
    `SELECT id, ts AS "timestamp", type, component, title, acknowledged
     FROM logs
     ORDER BY ts DESC
     LIMIT 200`
  );
  const statusesR = await pool.query(
    `SELECT id, name, detail, severity, updated_at AS "updatedAt"
     FROM statuses
     ORDER BY id ASC`
  );

  return {
    logs: logsR.rows,
    statuses: statusesR.rows,
    generatedAt: Date.now(),
  };
}

async function saveSnapshot(snap) {
  // Snapshot wird nicht extra gespeichert – wir lesen direkt aus Tabellen.
  // Funktion bleibt, falls du später Snapshot-Caching machen willst.
  return snap;
}

// ---- routes -------------------------------------------------------

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/api/snapshot", async (req, res) => {
  try {
    const snap = await loadSnapshot();
    res.json(snap);
  } catch (e) {
    console.error("snapshot error:", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

app.post("/api/ingest", async (req, res) => {
  const v = verifyHmac(req);
  if (!v.ok) return res.status(401).json({ ok: false, error: v.error });

  const { component, severity, reason, detail, updatedAt } = req.body || {};

  if (!component || !severity) {
    return res.status(400).json({ ok: false, error: "missing_fields" });
  }

  const ts = Number(updatedAt) || Date.now();

  // Status upsert
  await pool.query(
    `
    INSERT INTO statuses (id, name, detail, severity, updated_at)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (id) DO UPDATE
      SET name = EXCLUDED.name,
          detail = EXCLUDED.detail,
          severity = EXCLUDED.severity,
          updated_at = EXCLUDED.updated_at
    `,
    [
      component.toLowerCase(),
      component,
      detail || reason || "-",
      severity,
      ts,
    ]
  );

  // Log schreiben (acknowledged nur für ok=true)
  const title = `${component} ${severity}`;
  await pool.query(
    `
    INSERT INTO logs (ts, type, component, title, acknowledged)
    VALUES ($1, $2, $3, $4, $5)
    `,
    [
      ts,
      severity,
      component,
      reason ? `${title} (${reason})` : title,
      severity === "ok",
    ]
  );

  // Snapshot readback (optional)
  const snap = await loadSnapshot();
  await saveSnapshot(snap);

  res.json({ ok: true });
});

// ✅ NEU: ACK-Endpoint
// quittiert nur warning/alarm (ok darf NICHT quittierbar sein)
app.post("/api/logs/:id/ack", async (req, res) => {
  try {
    const { id } = req.params;

    const r = await pool.query(
      `UPDATE logs
          SET acknowledged = TRUE
        WHERE id = $1
          AND acknowledged = FALSE
          AND type IN ('warning','alarm')
        RETURNING id, ts AS "timestamp", type, component, title, acknowledged`,
      [id]
    );

    if (r.rowCount === 0) {
      return res.status(400).json({ ok: false, error: "not_ackable_or_not_found" });
    }

    return res.json({ ok: true, log: r.rows[0] });
  } catch (e) {
    console.error("ack error:", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

// ---- start --------------------------------------------------------

initDb()
  .then(() => app.listen(PORT, () => console.log("listening on", PORT)))
  .catch((err) => {
    console.error("DB init failed:", err);
    process.exit(1);
  });

