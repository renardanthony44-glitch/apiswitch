const express = require("express");
const path = require("path");
const app = express();
const PORT = process.env.PORT || 4002;

// Servir les fichiers statiques du répertoire public
app.use(express.static(path.join(__dirname, "../public")));

// Route principale – renvoie index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

// Health‑check JSON
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// 404 fallback
app.use((req, res) => {
  res.status(404).json({ error: "Not Found", path: req.path });
});

app.listen(PORT, () => {
  console.log(`ApiSwitch server running on port ${PORT}`);
});
