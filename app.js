require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { Storage } = require('@google-cloud/storage');
const crypto = require('crypto');
const path = require('path');

const app = express();

//  IMPORTANT (for real IP in production)
app.set('trust proxy', true);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//  Serve UI
app.use('/ui', express.static(path.join(__dirname, 'public')));

// ===== CONFIG =====
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const BUCKET_NAME = process.env.GCS_BUCKET;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// ===== APPROVERS =====
function parseApprovers(str) {
  const map = {};
  if (!str) return map;

  str.split(',').forEach(pair => {
    const [k, v] = pair.split(':');
    if (k && v) map[k.trim()] = v.trim();
  });

  return map;
}
const APPROVERS = parseApprovers(process.env.APPROVERS);

// ===== GCS =====
const storage = new Storage({
  keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS
});

// ===== EMAIL =====
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// ===== DATA =====
// fileName → { gcsPath, userId }
const fileRegistry = new Map();

// ===== RATE LIMIT STORE =====
const requestTracker = new Map(); // ip → timestamp

// ===== LOGGER =====
const log = (msg) => console.log(`[${new Date().toISOString()}] ${msg}`);

// ===== RATE LIMIT FUNCTION =====
function isRateLimited(ip) {
  const now = Date.now();
  const last = requestTracker.get(ip);

  const LIMIT = 10 * 60 * 1000; // 10 minutes

  if (last && (now - last < LIMIT)) {
    return true;
  }

  requestTracker.set(ip, now);
  return false;
}

// ===== EMAIL =====
async function sendEmail({ to, subject, text }) {
  log(` Email → ${to}`);
  await transporter.sendMail({
    from: process.env.SMTP_USER,
    to,
    subject,
    text
  });
}

// ===== NOTIFICATION =====
async function sendNotificationEmails(subject, text) {
  for (const email of Object.values(APPROVERS)) {
    await sendEmail({ to: email, subject, text });
  }
}

// ===== APPROVAL =====
async function sendApprovalEmails(token, subject, text) {
  for (const [name, email] of Object.entries(APPROVERS)) {
    const link = `${BASE_URL}/approve?token=${token}&approver=${name}`;
    await sendEmail({
      to: email,
      subject,
      text: `${text}\n\nApprove:\n${link}`
    });
  }
}

// ===== SIGNED URL =====
async function generateSignedUrl(gcsPath) {
  const filePath = gcsPath.replace(`gs://${BUCKET_NAME}/`, '');
  const file = storage.bucket(BUCKET_NAME).file(filePath);

  const [url] = await file.getSignedUrl({
    version: 'v4',
    action: 'read',
    expires: Date.now() + 15 * 60 * 1000
  });

  return url;
}

//
// ===== HOME =====
//
app.get('/', (req, res) => {
  res.redirect('/ui/request.html');
});

//
// ===== GET SECURE LINK =====
//
app.post('/get-secure-link', (req, res) => {
  try {
    const { userId } = req.body;

    let found = null;

    for (const [fileName, entry] of fileRegistry.entries()) {
      if (entry.userId === userId) {
        found = { fileName, ...entry };
        break;
      }
    }

    if (!found) {
      return res.status(404).json({ error: 'No file mapped for this userId' });
    }

    const token = jwt.sign(
      { gcsPath: found.gcsPath, userId },
      JWT_SECRET,
      { expiresIn: '10m' }
    );

    const url = `${BASE_URL}/ui/secure-download.html?token=${token}`;

    return res.json({ url });

  } catch (err) {
    return res.status(500).json({ error: 'Internal error' });
  }
});

//
// ===== REQUEST FILE (RATE LIMITED) =====
//
app.post('/request-file', async (req, res) => {
  const ip = req.ip;

  if (isRateLimited(ip)) {
    log(`  Rate limit hit → ${ip}`);
    return res.status(429).json({
      error: "  Only 1 request allowed every 10 minutes"
    });
  }

  const { name, requirement } = req.body;

  const userId = crypto.randomBytes(4).toString('hex');

  log(`  Request → ${name} → IP: ${ip} → userId=${userId}`);

  await sendNotificationEmails(
    '  New Requirement',
    `User: ${name}\nRequirement: ${requirement}\nUserId: ${userId}\nIP: ${ip}`
  );

  res.json({ message: "Request sent successfully" });
});

//
// ===== REGISTER FILE =====
//
app.post('/register-file', async (req, res) => {
  const { fileName, gcsPath, userId } = req.body;

  const token = jwt.sign(
    { fileName, gcsPath, userId },
    JWT_SECRET,
    { expiresIn: '10m' }
  );

  await sendApprovalEmails(
    token,
    ' Mapping Approval',
    `File: ${fileName}\nPath: ${gcsPath}\nUserId: ${userId}`
  );

  res.json({ message: 'Approval sent' });
});

//
// ===== APPROVE =====
//
app.get('/approve', (req, res) => {
  const d = jwt.verify(req.query.token, JWT_SECRET);

  res.send(`
    <h2>Approve Mapping</h2>
    <p>${d.fileName}</p>
    <p>${d.gcsPath}</p>
    <p>UserId: ${d.userId}</p>

    <form method="POST" action="/approve-register">
      <input type="hidden" name="token" value="${req.query.token}" />
      <button>Approve</button>
    </form>
  `);
});

//
// ===== APPROVE REGISTER =====
//
app.post('/approve-register', (req, res) => {
  const d = jwt.verify(req.body.token, JWT_SECRET);

  fileRegistry.set(d.fileName, {
    gcsPath: d.gcsPath,
    userId: d.userId
  });

  res.send(`
    <h2> Approved</h2>
    <p>UserId: ${d.userId}</p>

    <button onclick="gen()">Generate Link</button>

    <div id="out"></div>

    <script>
    async function gen(){
      const res = await fetch('/get-secure-link', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ userId: "${d.userId}" })
      });

      const data = await res.json();

      document.getElementById("out").innerHTML =
        '<input value="'+data.url+'" style="width:80%" readonly>' +
        '<br><br><button onclick="copy()">Copy</button>';
    }

    function copy(){
      const el = document.querySelector("#out input");
      el.select();
      document.execCommand("copy");
      alert("Copied!");
    }
    </script>
  `);
});

//
// ===== VALIDATE DOWNLOAD =====
//
app.post('/validate-download', async (req, res) => {
  const { token, userId } = req.body;
  const d = jwt.verify(token, JWT_SECRET);

  if (d.userId !== userId) return res.send("  Invalid UserId");

  const url = await generateSignedUrl(d.gcsPath);
  return res.redirect(url);
});

//
// ===== START =====
//
app.listen(PORT, () => {
  log(`Server running on ${PORT}`);
});