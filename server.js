
const express = require("express");
const { google } = require("googleapis");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json({ limit: "20mb" }));
app.use(express.static("public"));

const PORT = process.env.PORT || 3000;
const TOKEN_FILE = "/var/data/google-token.json";

const oauth = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

function saveToken(token) {
  fs.mkdirSync(path.dirname(TOKEN_FILE), { recursive: true });
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(token));
}

function getToken() {
  if (!fs.existsSync(TOKEN_FILE)) return null;
  return JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8"));
}

function driveClient() {
  const token = getToken();
  if (!token) throw new Error("Google Drive not connected");

  oauth.setCredentials(token);

  oauth.on("tokens", updated => {
    const current = getToken() || {};
    saveToken({ ...current, ...updated });
  });

  return google.drive({ version: "v3", auth: oauth });
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

// Google redirects here
app.get("/oauth2callback", async (req, res) => {
  try {
    const { tokens } = await oauth.getToken(req.query.code);
    saveToken(tokens);

    res.send(`
      <h2>Google Drive connected!</h2>
      <p>You can close this page and return to Tea Factory Accounts.</p>
      <script>
        window.location.href = "/";
      </script>
    `);
  } catch (err) {
    console.error(err);
    res.status(500).send("Google authentication failed.");
  }
});

// Check connection
app.get("/api/drive/status", (req, res) => {
  res.json({ connected: !!getToken() });
});

// Save Excel file
app.post("/api/drive/save", async (req, res) => {
  try {
    const drive = driveClient();
    const buffer = Buffer.from(req.body.data, "base64");

    const result = await drive.files.list({
      q: "name='TeaFactory.xlsx' and trashed=false",
      fields: "files(id)"
    });

    const metadata = {
      name: "TeaFactory.xlsx",
      mimeType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    };

    const media = {
      mimeType: metadata.mimeType,
      body: require("stream").Readable.from(buffer)
    };

    let fileId;

    if (result.data.files.length) {
      fileId = result.data.files[0].id;

      await drive.files.update({
        fileId,
        media,
        fields: "id"
      });
    } else {
      const created = await drive.files.create({
        requestBody: metadata,
        media,
        fields: "id"
      });

      fileId = created.data.id;
    }

    res.json({ success: true, fileId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Drive save failed" });
  }
});

// Load Excel file
app.get("/api/drive/load", async (req, res) => {
  try {
    const drive = driveClient();

    const result = await drive.files.list({
      q: "name='TeaFactory.xlsx' and trashed=false",
      fields: "files(id)",
      pageSize: 1
    });

    if (!result.data.files.length) {
      return res.status(404).json({ error: "Excel file not found" });
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
    console.error(err);
    res.status(500).json({ error: "Drive load failed" });
  }
});

app.listen(PORT, () => {
  console.log("Tea Factory server running on port " + PORT);
});
