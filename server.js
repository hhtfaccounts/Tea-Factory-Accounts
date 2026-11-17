
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);

const required = [
  "DB_HOST",
  "DB_NAME",
  "DB_USER",
  "DB_PASSWORD",
  "SESSION_SECRET",
  "STAFF_USERNAME",
  "STAFF_PASSWORD_HASH"
];

for (const name of required) {
  if (!process.env[name]) {
    console.error("Missing environment variable:", name);
    process.exit(1);
  }
}

// MySQL connection
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const dbp = db.promise();

// Security
app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({ limit: "30mb" }));

// MySQL-backed sessions
const sessionStore = new MySQLStore({
  createDatabaseTable: true,
  clearExpired: true,
  checkExpirationInterval: 15 * 60 * 1000,
  expiration: 24 * 60 * 60 * 1000
}, db);

app.use(session({
  name: "hhtf_session",
  secret: process.env.SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Create the application data table
async function prepareDatabase() {
  await dbp.query(`
    CREATE TABLE IF NOT EXISTS app_state (
      id TINYINT NOT NULL PRIMARY KEY,
      data LONGTEXT NOT NULL,
      version BIGINT UNSIGNED NOT NULL DEFAULT 1,
      updated_at TIMESTAMP NOT NULL
        DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
    )
  `);

  console.log("MySQL application table ready.");
}

// Login protection
function requireLogin(req, res, next) {
  if (!req.session || !req.session.staff) {
    return res.status(401).json({
      error: "Please log in first."
    });
  }

  next();
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    error: "Too many login attempts. Try again later."
  }
});

// Public homepage
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Staff login
app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (
      username !== process.env.STAFF_USERNAME ||
      !password ||
      password.length > 200
    ) {
      return res.status(401).json({
        error: "Incorrect username or password."
      });
    }

    const valid = await bcrypt.compare(
      password,
      process.env.STAFF_PASSWORD_HASH
    );

    if (!valid) {
      return res.status(401).json({
        error: "Incorrect username or password."
      });
    }

    req.session.regenerate((err) => {
      if (err) {
        console.error("Session error:", err);
        return res.status(500).json({
          error: "Could not create login session."
        });
      }

      req.session.staff = true;
      req.session.username = username;

      req.session.save((saveErr) => {
        if (saveErr) {
          console.error("Session save error:", saveErr);
          return res.status(500).json({
            error: "Could not save login session."
          });
        }

        res.setHeader("Cache-Control", "no-store");
        res.json({ success: true });
      });
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({
      error: "Login failed."
    });
  }
});

// Check login
app.get("/api/auth/me", (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  res.json({
    authenticated: !!(req.session && req.session.staff),
    username: req.session?.username || null
  });
});

// Logout
app.post("/api/logout", requireLogin, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        error: "Logout failed."
      });
    }

    res.clearCookie("hhtf_session", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/"
    });

    res.json({ success: true });
  });
});

// Protect the accounts application page
app.get("/account.html", requireLogin, (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(__dirname, "account.html"));
});

// Load saved factory data
app.get("/api/data", requireLogin, async (req, res) => {
  try {
    const [rows] = await dbp.query(
      "SELECT data, version, updated_at FROM app_state WHERE id = 1"
    );

    res.setHeader("Cache-Control", "no-store");

    if (!rows.length) {
      return res.json({
        data: null,
        version: 0
      });
    }

    res.json({
      data: JSON.parse(rows[0].data),
      version: Number(rows[0].version),
      updated_at: rows[0].updated_at
    });
  } catch (err) {
    console.error("Data load error:", err);
    res.status(500).json({
      error: "Could not load factory data."
    });
  }
});

// Save factory data with version checking
app.put("/api/data", requireLogin, async (req, res) => {
  try {
    const data = req.body.data;
    const version = Number(req.body.version);

    if (
      !data ||
      typeof data !== "object" ||
      Array.isArray(data) ||
      !Number.isSafeInteger(version) ||
      version < 0
    ) {
      return res.status(400).json({
        error: "Invalid data or version."
      });
    }

    const json = JSON.stringify(data);

    if (Buffer.byteLength(json, "utf8") > 25 * 1024 * 1024) {
      return res.status(413).json({
        error: "Data is too large."
      });
    }

    if (version === 0) {
      const [result] = await dbp.query(
        `INSERT IGNORE INTO app_state (id, data, version)
         VALUES (1, ?, 1)`,
        [json]
      );

      if (result.affectedRows === 1) {
        return res.json({ success: true, version: 1 });
      }
    } else {
      const [result] = await dbp.query(
        `UPDATE app_state
         SET data = ?, version = version + 1
         WHERE id = 1 AND version = ?`,
        [json, version]
      );

      if (result.affectedRows === 1) {
        return res.json({
          success: true,
          version: version + 1
        });
      }
    }

    const [current] = await dbp.query(
      "SELECT version FROM app_state WHERE id = 1"
    );

    res.status(409).json({
      error: "Data changed elsewhere. Reload before saving.",
      currentVersion: current.length
        ? Number(current[0].version)
        : 0
    });
  } catch (err) {
    console.error("Data save error:", err);
    res.status(500).json({
      error: "Could not save factory data."
    });
  }
});

// Start only after database is ready
prepareDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log("Harihara Tea Factory server running on " + PORT);
    });
  })
  .catch((err) => {
    console.error("Database startup failed:", err);
    process.exit(1);
  });
