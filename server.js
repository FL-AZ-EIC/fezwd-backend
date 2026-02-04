const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
app.use(cors());

// Raw body für HMAC (wichtig)
app.use(express.json({
  limit: "256kb",
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

const PORT = process.env.PORT || 8787;
const SHARED_SECRET = process.env.SHARED_SECRET || "change-me";
const DATABASE_URL = process.env.DATABASE_URL;

let pool = null;
if (DATABASE_URL) pool = new Pool({ connectionString: DATABASE_URL });

// --- DB init
async function initDb() {
  if (!pool) return;

  await pool.query(`
    CREATE TABLE IF NOT EXISTS snapshot (
      id TEXT PRIMARY KEY,
      generated_at BIGINT NOT NULL,
      data JSONB NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS logs (
      id TEXT PRIMARY KEY,
      ts BIGINT NOT NULL,
      type TEXT NOT NULL,
      component TEXT NOT NULL,
      title TEXT NOT NULL,
      acknowledged BOOLEAN NOT NULL
    );
  `);

  const r = await pool.query(`SELECT 1 FROM snapshot WHERE id='main'`);
  if (r.rowCount === 0) {
    const now = Date.now();
    const base = {
      generatedAt: now,
      statuses: [
        { id: "internet", name: "Internet", severity: "ok", detail: "—", updatedAt: now }
      ],
      logs: []
    };
    await pool.query(`INSERT INTO snapshot(id, generated_at, data) VALUES('main', $1, $2)`, [now, base]);
  }
}

function verifyHmac(req) {
  const ts = req.header("x-ts");
  const nonce = req.header("x-nonce");
  const sig = req.header("x-signature");
  if (!ts || !nonce || !sig) return { ok: false, reason: "missing_headers" };

  const now = Date.now();
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum) || Math.abs(now - tsNum) > 2 * 60 * 1000) {
    return { ok: false, reason: "ts_out_of_window" };
  }

  const body = req.rawBody ? req.rawBody.toString("utf8") : "";
  const payload = `${ts}.${nonce}.${body}`;

  const expected = crypto.createHmac("sha256", SHARED_SECRET).update(payload).digest("hex");
  try {
    const ok = crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(sig, "hex"));
    return { ok, reason: ok ? "ok" : "bad_signature" };
  } catch {
    return { ok: false, reason: "bad_signature" };
  }
}

async function getSnapshot() {
  const r = await pool.query(`SELECT data FROM snapshot WHERE id='main'`);
  return r.rows[0].data;
}

async function saveSnapshot(obj) {
  const now = Date.now();
  await pool.query(`UPDATE snapshot SET generated_at=$1, data=$2 WHERE id='main'`, [now, obj]);
}

async function getLogs() {
  const r = await pool.query(`SELECT * FROM logs ORDER BY ts DESC LIMIT 200`);
  return r.rows.map(x => ({
    id: x.id,
    timestamp: Number(x.ts),
    type: x.type,
    component: x.component,
    title: x.title,
    acknowledged: !!x.acknowledged
  }));
}

async function addLog({ type, component, title, acknowledged }) {
  await pool.query(
    `INSERT INTO logs(id, ts, type, component, title, acknowledged) VALUES($1,$2,$3,$4,$5,$6)`,
    [crypto.randomUUID(), Date.now(), type, component, title, acknowledged]
  );
  await pool.query(`
    DELETE FROM logs
    WHERE id IN (SELECT id FROM logs ORDER BY ts DESC OFFSET 200)
  `);
}

app.get("/health", (req, res) => res.json({ ok: true, at: Date.now() }));

app.get("/api/snapshot", async (req, res) => {
  if (!pool) return res.status(500).json({ ok: false, error: "DATABASE_URL not set" });
  const snap = await getSnapshot();
  snap.logs = await getLogs();
  res.json(snap);
});

app.post("/api/ingest", async (req, res) => {
  if (!pool) return res.status(500).json({ ok: false, error: "DATABASE_URL not set" });

  const v = verifyHmac(req);
  if (!v.ok) return res.status(401).json({ ok: false, error: v.reason });

  const { component, severity, reason, detail, updatedAt } = req.body || {};
  if (!component || !severity) return res.status(400).json({ ok: false, error: "missing_component_or_severity" });

  const snap = await getSnapshot();
  snap.generatedAt = Date.now();

  const id = String(component).toLowerCase();
  let st = snap.statuses.find(s => s.id === id);
  if (!st) {
    st = { id, name: String(component), severity: "ok", detail: "—", updatedAt: Date.now() };
    snap.statuses.push(st);
  }

  const oldKey = `${st.severity}|${st.detail}`;
  st.severity = severity;
  st.detail = detail || (reason ? `Grund: ${reason}` : "—");
  st.updatedAt = updatedAt || Date.now();
  const newKey = `${st.severity}|${st.detail}`;

  if (newKey !== oldKey) {
    const type = severity === "alarm" ? "alarm" : (severity === "warning" ? "warning" : "info");
    const title =
      severity === "ok" ? `${component} wieder OK`
      : severity === "alarm" ? `${component} Ausfall`
      : `${component} eingeschränkt`;
    await addLog({
      type,
      component: String(component),
      title: reason ? `${title} (${reason})` : title,
      acknowledged: severity === "ok"
    });
  }

  await saveSnapshot(snap);
  res.json({ ok: true });
});

initDb()
  .then(() => app.listen(PORT, () => console.log("listening on", PORT)))
  .catch(err => {
    console.error("DB init failed:", err);
    process.exit(1);
  });
