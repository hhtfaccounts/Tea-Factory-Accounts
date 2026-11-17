
const express = require("express");
const { google } = require("googleapis");
const crypto = require("crypto");
const { Readable } = require("stream");
const cors = require("cors");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://tea-factory-accounts.onrender.com";

const oauth = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// CORS
app.use(cors({
  origin: [
    FRONTEND_URL,
    "https://hariharateafactory.com",
    "https://www.hariharateafactory.com"
  ],
  credentials: true
}));

app.use(express.json({ limit: "20mb" }));

// Serve frontend files from the main project folder
app.use(express.static(__dirname));

// Homepage
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Check required environment variables
function checkConfig() {
  return !!(
    process.env.GOOGLE_CLIENT_ID &&
    process.env.GOOGLE_CLIENT_SECRET &&
    process.env.GOOGLE_REDIRECT_URI &&
    process.env.SESSION_SECRET
  );
}

// Create signed browser session
function sign(value) {
  return crypto
    .createHmac("sha256", process.env.SESSION_SECRET)
    .update(value)
    .digest("hex");
}

function validSession(req) {
  const cookie = req.headers.cookie || "";
  const match = cookie.match(/(?:^|;\s*)drive_session=([^;]+)/);

  if (!match || !process.env.SESSION_SECRET) return false;

  const expected = sign("connected");
  const received = match[1];

  if (received.length !== expected.length) return false;

  return crypto.timingSafeEqual(
    Buffer.from(received),
    Buffer.from(expected)
  );
}

function requireLogin(req, res, next) {
  if (!process.env.GOOGLE_REFRESH_TOKEN) {
    return res.status(503).json({
      error: "Google Drive is not configured"
    });
  }

  if (!validSession(req)) {
    return res.status(401).json({
      error: "Please connect Google Drive"
    });
  }

  next();
}

// Google Drive client
function driveClient() {
  const auth = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );

  auth.setCredentials({
    refresh_token: process.env.GOOGLE_REFRESH_TOKEN
  });

  return google.drive({
    version: "v3",
    auth
  });
}

// Start Google login
app.get("/auth/google", (req, res) => {
  if (!checkConfig()) {
    return res.status(500).send(
      "Google OAuth environment variables are missing."
    );
  }

  const url = oauth.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: [
      "https://www.googleapis.com/auth/drive.file"
    ]
  });

  res.redirect(url);
});

// Google OAuth callback
app.get("/oauth2callback", async (req, res) => {
  try {
    if (req.query.error) {
      return res.status(400).send(
        "Google authorization was cancelled."
      );
    }

    if (!req.query.code) {
      return res.status(400).send(
        "Google did not return an authorization code."
      );
    }

    const { tokens } = await oauth.getToken(req.query.code);

    if (!process.env.GOOGLE_REFRESH_TOKEN) {
      if (!tokens.refresh_token) {
        return res.status(400).send(
          "No refresh token received. Revoke the app's Google access and try again."
        );
      }

      res.setHeader("Cache-Control", "no-store");

      return res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <title>Google Drive Setup</title>
        </head>
        <body style="font-family:Arial;padding:25px">
          <h2>Google authorization successful!</h2>
          <p>Copy this refresh token into your server environment variables.</p>
          <textarea id="token" rows="6"
            style="width:100%;max-width:600px">${tokens.refresh_token}</textarea>
          <p>
            <button onclick="
              navigator.clipboard.writeText(
                document.getElementById('token').value
              )
            ">Copy token</button>
          </p>
          <p>Keep this token private.</p>
        </body>
        </html>
      `);
    }

    const cookieValue = sign("connected");

    res.setHeader(
      "Set-Cookie",
      `drive_session=${cookieValue}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=2592000`
    );

    res.redirect(FRONTEND_URL);

  } catch (err) {
    console.error("Google login error:", err.message);
    res.status(500).send("Google authentication failed.");
  }
});

// Check connection
app.get("/api/drive/status", (req, res) => {
  res.json({
    connected:
      !!process.env.GOOGLE_REFRESH_TOKEN &&
      validSession(req)
  });
});

// Save Excel file
app.post("/api/drive/save", requireLogin, async (req, res) => {
  try {
    const data = req.body.data;

    if (
      typeof data !== "string" ||
      !data.length ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(data)
    ) {
      return res.status(400).json({
        error: "Invalid Excel data"
      });
    }

    const buffer = Buffer.from(data, "base64");
    const drive = driveClient();

    const result = await drive.files.list({
      q: "name='TeaFactory.xlsx' and trashed=false",
      fields: "files(id)",
      pageSize: 1
    });

    const metadata = {
      name: "TeaFactory.xlsx",
      mimeType:
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    };

    const media = {
      mimeType: metadata.mimeType,
      body: Readable.from(buffer)
    };

    if (result.data.files.length) {
      await drive.files.update({
        fileId: result.data.files[0].id,
        media,
        fields: "id"
      });
    } else {
      await drive.files.create({
        requestBody: metadata,
        media,
        fields: "id"
      });
    }

    res.json({ success: true });

  } catch (err) {
    console.error("Drive save error:", err.message);
    res.status(500).json({
      error: "Drive save failed"
    });
  }
});

// Load Excel file
app.get("/api/drive/load", requireLogin, async (req, res) => {
  try {
    const drive = driveClient();

    const result = await drive.files.list({
      q: "name='TeaFactory.xlsx' and trashed=false",
      fields: "files(id)",
      pageSize: 1
    });

    if (!result.data.files.length) {
      return res.status(404).json({
        error: "Excel file not found"
      });
    }

    const response = await drive.files.get(
      {
        fileId: result.data.files[0].id,
        alt: "media"
      },
      { responseType: "arraybuffer" }
    );

    res.json({
      data: Buffer.from(response.data).toString("base64")
    });

  } catch (err) {
    console.error("Drive load error:", err.message);
    res.status(500).json({
      error: "Drive load failed"
    });
  }
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log("Tea Factory server running on port " + PORT);
});
