const express = require("express");
const path = require("path");
const fs = require("fs");
const https = require("https");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const app = express();
const PORT = process.env.PORT || 4002;

const RAPIDAPI_PROXY_SECRET = process.env.RAPIDAPI_PROXY_SECRET;
if (!RAPIDAPI_PROXY_SECRET) {
  console.error("RAPIDAPI_PROXY_SECRET not defined – aborting server start");
  process.exit(1);
}
const ENCRYPTION_KEY = process.env.APISWITCH_ENCRYPTION_KEY;
if (!ENCRYPTION_KEY) {
  console.error("APISWITCH_ENCRYPTION_KEY not defined – aborting server start");
  process.exit(1);
}
const ENCRYPTION_ALGO = "aes-256-gcm";

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const key = Buffer.from(ENCRYPTION_KEY, "base64");
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGO, key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  const tag = cipher.getAuthTag().toString("hex");
  return iv.toString("hex") + ":" + encrypted + ":" + tag;
}

function decrypt(payload) {
  const [ivHex, encryptedHex, tagHex] = payload.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const encrypted = encryptedHex;
  const tag = Buffer.from(tagHex, "hex");
  const key = Buffer.from(ENCRYPTION_KEY, "base64");
  const decipher = crypto.createDecipheriv(ENCRYPTION_ALGO, key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

const DATA_DIR = path.join(__dirname, "../data");
const KEYS_FILE = path.join(DATA_DIR, "keys.json");
const CLIENTS_FILE = path.join(DATA_DIR, "clients.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(KEYS_FILE)) fs.writeFileSync(KEYS_FILE, JSON.stringify({ keys: [] }, null, 2));
if (!fs.existsSync(CLIENTS_FILE)) fs.writeFileSync(CLIENTS_FILE, JSON.stringify({ clients: [] }, null, 2));

// Middleware – vérification du secret RapidAPI (route-level uniquement)
function verifyRapidapiSecret(req, res, next) {
  const secret = req.headers["x-rapidapi-proxy-secret"];
  if (secret !== RAPIDAPI_PROXY_SECRET) {
    return res.status(403).json({ error: "Invalid RAPIDAPI proxy secret" });
  }
  next();
}

app.use(express.json());

// Routes publiques – pas de vérification du secret
app.use(express.static(path.join(__dirname, "../public")));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "../public/index.html")));
app.get("/api/health", (req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

// CLIENT MANAGEMENT – verifyRapidapiSecret appliqué individuellement
app.post("/api/register-client", verifyRapidapiSecret, (req, res) => {
  const clientsData = JSON.parse(fs.readFileSync(CLIENTS_FILE, "utf8"));
  const newKey = uuidv4();
  clientsData.clients.push({ apiKey: newKey, createdAt: new Date().toISOString() });
  fs.writeFileSync(CLIENTS_FILE, JSON.stringify(clientsData, null, 2));
  res.json({ apiKey: newKey });
});

app.get("/api/clients", verifyRapidapiSecret, (req, res) => {
  const clientsData = JSON.parse(fs.readFileSync(CLIENTS_FILE, "utf8"));
  res.json({ clients: clientsData.clients });
});

// PROVIDER KEYS – CRUD
function getClientFromHeader(req) {
  const clientKey = req.headers["x-apiswitch-key"];
  if (!clientKey) return null;
  const clients = JSON.parse(fs.readFileSync(CLIENTS_FILE, "utf8")).clients;
  return clients.find(c => c.apiKey === clientKey) || null;
}

app.post("/api/keys", verifyRapidapiSecret, (req, res) => {
  const client = getClientFromHeader(req);
  if (!client) return res.status(401).json({ error: "Invalid or missing client ApiSwitch key" });

  const { provider, key, label } = req.body;
  if (!provider || !key) return res.status(400).json({ error: "provider and key are required" });

  const keysData = JSON.parse(fs.readFileSync(KEYS_FILE, "utf8"));
  const duplicate = keysData.keys.find(k => k.clientApiKey === client.apiKey && decrypt(k.encryptedKey) === key);
  if (duplicate) return res.status(409).json({ error: "Key already exists for this client" });

  const encryptedKey = encrypt(key);
  keysData.keys.push({
    id: Date.now().toString(),
    clientApiKey: client.apiKey,
    provider,
    encryptedKey,
    label: label || provider,
    createdAt: new Date().toISOString(),
    usageCount: 0,
    lastUsed: null,
    remainingQuota: null,
    exhausted: false,
    last429: null,
    retryAfter: null
  });
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keysData, null, 2));
  res.json({ success: true, id: Date.now().toString() });
});

app.get("/api/keys", verifyRapidapiSecret, (req, res) => {
  const client = getClientFromHeader(req);
  if (!client) return res.status(401).json({ error: "Invalid client key" });
  const keysData = JSON.parse(fs.readFileSync(KEYS_FILE, "utf8"));
  const clientKeys = keysData.keys
    .filter(k => k.clientApiKey === client.apiKey)
    .map(k => ({
      id: k.id,
      provider: k.provider,
      label: k.label,
      createdAt: k.createdAt,
      usageCount: k.usageCount,
      lastUsed: k.lastUsed,
      remainingQuota: k.remainingQuota,
      exhausted: k.exhausted,
      last429: k.last429,
      retryAfter: k.retryAfter
    }));
  res.json({ keys: clientKeys });
});

app.delete("/api/keys/:id", verifyRapidapiSecret, (req, res) => {
  const client = getClientFromHeader(req);
  if (!client) return res.status(401).json({ error: "Invalid client key" });
  const { id } = req.params;
  const keysData = JSON.parse(fs.readFileSync(KEYS_FILE, "utf8"));
  const before = keysData.keys.length;
  keysData.keys = keysData.keys.filter(k => !(k.id === id && k.clientApiKey === client.apiKey));
  if (keysData.keys.length === before) return res.status(404).json({ error: "Key not found" });
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keysData, null, 2));
  res.json({ success: true });
});

// KEY SELECTION LOGIC
function selectBestKey(provider, clientApiKey) {
  const keysData = JSON.parse(fs.readFileSync(KEYS_FILE, "utf8"));
  const pool = keysData.keys.filter(k =>
    k.provider === provider &&
    k.clientApiKey === clientApiKey &&
    !k.exhausted
  );
  if (pool.length === 0) return null;
  pool.sort((a, b) => {
    const quotaA = a.remainingQuota === null ? Infinity : a.remainingQuota;
    const quotaB = b.remainingQuota === null ? Infinity : b.remainingQuota;
    return quotaB - quotaA;
  });
  return pool[0];
}

function updateKeyQuota(keyId, remainingQuota, statusCode) {
  const keysData = JSON.parse(fs.readFileSync(KEYS_FILE, "utf8"));
  const keyIndex = keysData.keys.findIndex(k => k.id === keyId);
  if (keyIndex >= 0) {
    const key = keysData.keys[keyIndex];
    key.usageCount += 1;
    key.lastUsed = new Date().toISOString();
    if (remainingQuota !== undefined && remainingQuota !== null) {
      key.remainingQuota = parseInt(remainingQuota, 10);
    }
    if (statusCode === 429) {
      key.exhausted = true;
      key.last429 = new Date().toISOString();
    }
    fs.writeFileSync(KEYS_FILE, JSON.stringify(keysData, null, 2));
  }
}

function resetExhaustedKeys() {
  const keysData = JSON.parse(fs.readFileSync(KEYS_FILE, "utf8"));
  const now = Date.now();
  let updated = false;
  keysData.keys.forEach(key => {
    if (key.exhausted && key.last429) {
      const last429Time = new Date(key.last429).getTime();
      if (now - last429Time > 3600000) {
        key.exhausted = false;
        key.last429 = null;
        key.retryAfter = null;
        updated = true;
      }
    }
  });
  if (updated) fs.writeFileSync(KEYS_FILE, JSON.stringify(keysData, null, 2));
}

// PROXY
function getProviderHeaders(provider) {
  const map = {
    openai: { "OpenAI-Beta": "assistants=v1" },
    anthropic: { "anthropic-version": "2023-06-01" },
    stripe: { "Stripe-Version": "2023-10-16" }
  };
  return map[provider.toLowerCase()] || {};
}

async function forwardRequest(hostname, path, payload, apiKey, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname,
      path,
      method: "POST",
      headers: Object.assign({
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`
      }, extraHeaders)
    };
    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: data,
          remainingQuota: res.headers["x-ratelimit-remaining"],
          retryAfter: res.headers["retry-after"] || res.headers["x-ratelimit-reset"]
        });
      });
    });
    req.on("error", reject);
    req.write(JSON.stringify(payload));
    req.end();
  });
}

app.post("/api/proxy", verifyRapidapiSecret, async (req, res) => {
  const clientKey = req.headers["x-apiswitch-key"];
  if (!clientKey) return res.status(401).json({ error: "Missing x-apiswitch-key header" });

  const client = getClientFromHeader(req);
  if (!client) return res.status(401).json({ error: "Invalid client ApiSwitch key" });

  const { provider, endpoint, payload } = req.body;
  if (!provider || !endpoint || !payload) return res.status(400).json({ error: "provider, endpoint and payload required" });

  let keyEntry = selectBestKey(provider, client.apiKey);
  let attempt = 0;
  const maxAttempts = 3;

  while (attempt < maxAttempts && keyEntry) {
    attempt++;
    const decryptedKey = decrypt(keyEntry.encryptedKey);
    try {
      const hostnameMap = { openai: "api.openai.com", anthropic: "api.anthropic.com", stripe: "api.stripe.com" };
      const hostname = hostnameMap[provider.toLowerCase()] || "api.example.com";
      const response = await forwardRequest(hostname, endpoint, payload, decryptedKey, getProviderHeaders(provider));

      updateKeyQuota(keyEntry.id, response.remainingQuota, response.status);

      if (response.status === 429) {
        keyEntry = selectBestKey(provider, client.apiKey);
        continue;
      }

      res.status(response.status || 200).json({ ...JSON.parse(response.body), proxied: true, provider, endpoint });
      return;
    } catch (e) {
      console.error("Proxy error:", e);
      updateKeyQuota(keyEntry.id, null, 500);
      keyEntry = selectBestKey(provider, client.apiKey);
    }
  }

  const exhaustedKeys = JSON.parse(fs.readFileSync(KEYS_FILE, "utf8")).keys
    .filter(k => k.provider === provider && k.clientApiKey === client.apiKey && k.exhausted)
    .map(k => ({ id: k.id, retryAfter: k.retryAfter }));

  const retryAfters = exhaustedKeys.map(k => k.retryAfter).filter(Boolean).map(t => new Date(t).getTime());
  const retryAfter = retryAfters.length > 0 ? Math.min(...retryAfters) : Date.now() + 3600000;

  res.status(503).json({ error: "All keys exhausted", retry_after: retryAfter, exhausted_keys: exhaustedKeys });
});

// 404 fallback
app.use((req, res) => res.status(404).json({ error: "Not Found", path: req.path }));

app.listen(PORT, () => console.log(`ApiSwitch server running on port ${PORT}`));
