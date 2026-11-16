
const express = require("express");
const { google } = require("googleapis");
const crypto = require("crypto");
const { Readable } = require("stream");

const app = express();

app.use(express.json({ limit: "20mb" }));

const PORT = process.env.PORT || 3000;

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://tea-factory-accounts.onrender.com";

const oauth = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// Secure login cookie
function sign(value) {
  return crypto
    .createHmac("sha256", process.env.SESSION_SECRET)
    .update(value)
    .digest("hex");
}

function validSession(req) {
  const cookie = req.headers.cookie || "";
  const match = cookie.match(/drive_session=([^;]+)/);

  if (!match || !process.env.SESSION_SECRET) return false;

  const expected = sign("connected");

  return crypto.timingSafeEqual(
    Buffer.from(match[1]),
    Buffer.from(expected)
  );
}

function requireLogin(req, res, next) {
  if (!process.env.GOOGLE_REFRESH_TOKEN) {
    return res.status(503).json({
      error: "Google Drive setup is incomplete"
    });
  }

  if (!validSession(req)) {
    return res.status(401).json({
      error: "Please connect Google Drive"
    });
  }

  next();
}

// Google Drive connection
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
  const url = oauth.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: [
      "https://www.googleapis.com/auth/drive.file"
    ]
  });

  res.redirect(url);
});

// Google login callback
app.get("/oauth2callback", async (req, res) => {
  try {
    const { tokens } = await oauth.getToken(req.query.code);

    // First connection: show the refresh token once
    if (!process.env.GOOGLE_REFRESH_TOKEN) {
      if (!tokens.refresh_token) {
        return res.status(400).send(
          "No refresh token received. Revoke the app's Google access and try again."
        );
      }

      return res.send(`
        <h2>Google authorization successful!</h2>
        <p>Copy this refresh token into Render Environment Variables.</p>
        <textarea id="token" rows="5" style="width:95%">${tokens.refresh_token}</textarea>
        <button onclick="navigator.clipboard.writeText(document.getElementById('token').value)">
          Copy token
        </button>
        <p>Keep this token private. Do not share it.</p>
      `);
    }

    // Subsequent connections
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
    if (!req.body.data) {
      return res.status(400).json({ error: "Missing file data" });
    }

    const drive = driveClient();
    const buffer = Buffer.from(req.body.data, "base64");

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
    res.status(500).json({ error: "Drive save failed" });
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
    res.status(500).json({ error: "Drive load failed" });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("Tea Factory server running on port " + PORT);
});
