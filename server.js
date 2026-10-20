
const express = require("express");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "10kb" }));

const PORT = process.env.PORT || 3000;

const keys = new Set(
  (process.env.VEXARI_KEYS || "")
    .split(",")
    .map((key) => key.trim())
    .filter(Boolean)
);

app.get("/", (_req, res) => {
  res.json({
    name: "Vexari API",
    status: "online",
    version: "1.0.0"
  });
});

app.post("/verify", (req, res) => {
  const key = req.body?.key;

  if (typeof key !== "string" || key.length < 1 || key.length > 200) {
    return res.status(400).json({
      valid: false,
      message: "Invalid request"
    });
  }

  if (!keys.size) {
    return res.status(503).json({
      valid: false,
      message: "License system is not configured"
    });
  }

  const valid = keys.has(key);

  return res.status(200).json({
    valid,
    message: valid ? "License accepted" : "Invalid license"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Vexari API running on port ${PORT}`);
});
