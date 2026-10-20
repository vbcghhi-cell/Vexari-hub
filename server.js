
const express = require("express");
const crypto = require("node:crypto");
const { rateLimit } = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

// Render runs behind a proxy.
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.json({ limit: "2kb", strict: true }));

// General API limit: 120 requests per IP per 15 minutes.
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many requests. Try again later."
  }
}));

// Stricter limit for license attempts: 10 per IP per 15 minutes.
const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    valid: false,
    message: "Too many attempts. Try again later."
  }
});

// Read SHA-256 hashes from Render Environment.
const keyHashes = (process.env.VEXARI_KEY_HASHES || "")
  .split(",")
  .map((value) => value.trim().toLowerCase())
  .filter((value) => /^[a-f0-9]{64}$/.test(value));

function sha256(value) {
  return crypto.createHash("sha256")
    .update(value, "utf8")
    .digest();
}

function safeEqualHex(a, b) {
  if (
    !/^[a-f0-9]{64}$/.test(a) ||
    !/^[a-f0-9]{64}$/.test(b)
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    Buffer.from(a, "hex"),
    Buffer.from(b, "hex")
  );
}

app.get("/", (_req, res) => {
  res.json({
    name: "Vexari API",
    status: "online",
    version: "1.1.0"
  });
});

app.post("/verify", verifyLimiter, (req, res) => {
  const key = req.body?.key;

  if (
    typeof key !== "string" ||
    key.length < 1 ||
    key.length > 200
  ) {
    return res.status(400).json({
      valid: false,
      message: "Invalid request"
    });
  }

  if (keyHashes.length === 0) {
    return res.status(503).json({
      valid: false,
      message: "License service unavailable"
    });
  }

  const submittedHash = sha256(key).toString("hex");
  const valid = keyHashes.some((storedHash) =>
    safeEqualHex(submittedHash, storedHash)
  );

  return res.status(200).json({
    valid,
    message: valid ? "License accepted" : "Invalid license"
  });
});

// Handle malformed JSON and unexpected errors without exposing details.
app.use((err, _req, res, _next) => {
  if (err instanceof SyntaxError && "body" in err) {
    return res.status(400).json({
      valid: false,
      message: "Invalid JSON"
    });
  }

  if (err.type === "entity.too.large") {
    return res.status(413).json({
      valid: false,
      message: "Request too large"
    });
  }

  return res.status(500).json({
    error: "Internal server error"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("Vexari API started");
});
