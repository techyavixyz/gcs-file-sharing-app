require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { Storage } = require('@google-cloud/storage');
const crypto = require('crypto');
const path = require('path');

const app = express();

app.set('trust proxy', true);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
const fileRegistry = new Map();
const requestTracker = new Map();
const adminSessions = new Map();
const requestStore = []; // 🔥 NEW (store requests)

// ===== LOGGER =====
const log = (msg) => console.log(`[${new Date().toISOString()}] ${msg}`);

// ===== RATE LIMIT =====
function isRateLimited(ip) {
  const now = Date.now();
  const last = requestTracker.get(ip);
  const LIMIT = 10 * 60 * 1000;

  if (last && (now - last < LIMIT)) return true;

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

// ===== HOME =====
app.get('/', (req, res) => {
  res.redirect('/ui/request.html');
});

// ===== ADMIN GENERATE ACCESS =====
app.post('/admin/generate-access', async (req, res) => {
  try {
    const { approver } = req.body;

    if (!APPROVERS[approver]) {
      return res.status(400).json({ error: "Invalid approver" });
    }

    const accessId = crypto.randomBytes(4).toString('hex');

    adminSessions.set(accessId, {
      approver,
      expires: Date.now() + 10 * 60 * 1000
    });

    await sendEmail({
      to: APPROVERS[approver],
      subject: "Admin Access Code",
      text: `Your admin access code is: ${accessId}\nValid for 10 minutes`
    });

    res.json({ message: "Access ID sent to approver email" });

  } catch (err) {
    res.status(500).json({ error: "Internal error" });
  }
});

// ===== ADMIN VERIFY =====
app.post('/admin/verify', (req, res) => {
  const { accessId } = req.body;

  const session = adminSessions.get(accessId);

  if (!session) {
    return res.status(401).json({ error: "Invalid access ID" });
  }

  if (Date.now() > session.expires) {
    adminSessions.delete(accessId);
    return res.status(401).json({ error: "Access expired" });
  }

  const token = jwt.sign(
    { role: "admin", approver: session.approver },
    JWT_SECRET,
    { expiresIn: '15m' }
  );

  res.json({ token });
});

// ===== GET APPROVERS =====
app.get('/admin/approvers', (req, res) => {
  res.json({ approvers: Object.keys(APPROVERS) });
});

// ===== 🔥 NEW: GET REQUEST LIST =====
app.get('/admin/requests', (req, res) => {
  res.json({
    count: requestStore.length,
    requests: requestStore
  });
});

// ===== GET SECURE LINK =====
app.post('/get-secure-link', (req, res) => {
  try {
    const entries = Array.from(fileRegistry.entries());

    if (!entries.length) {
      return res.status(404).json({ error: 'No file mapped yet' });
    }

    const [fileName, entry] = entries[entries.length - 1];

    const token = jwt.sign(
      { gcsPath: entry.gcsPath, userId: entry.userId },
      JWT_SECRET,
      { expiresIn: '10m' }
    );

    const url = `${BASE_URL}/ui/secure-download.html?token=${token}`;

    return res.json({ url });

  } catch {
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ===== REQUEST FILE =====
app.post('/request-file', async (req, res) => {
  const ip = req.ip;

  if (isRateLimited(ip)) {
    return res.status(429).json({
      error: "Only 1 request allowed every 10 minutes"
    });
  }

  const { name, requirement } = req.body;
  const userId = crypto.randomBytes(4).toString('hex');

  // 🔥 STORE REQUEST
  requestStore.push({
    userId,
    name,
    requirement,
    ip,
    createdAt: new Date().toISOString()
  });

  log(` New request stored → ${userId}`);

  await sendNotificationEmails(
    'New Requirement',
    `User: ${name}\nRequirement: ${requirement}\nUserId: ${userId}\nIP: ${ip}`
  );

  res.json({ message: "Request sent", userId });
});

// ===== REGISTER FILE =====
app.post('/register-file', async (req, res) => {
  try {

    const auth = req.headers.authorization;

    if (auth) {
      const token = auth.split(" ")[1];

      let decoded;
      try {
        decoded = jwt.verify(token, JWT_SECRET);
      } catch {
        return res.status(401).json({ error: "Invalid token" });
      }

      if (decoded.role !== "admin") {
        return res.status(403).json({ error: "Forbidden" });
      }

      const { fileName, gcsPath, userId } = req.body;

      fileRegistry.set(fileName, { gcsPath, userId });

      log(` Direct mapping → ${fileName}`);

      return res.json({
        message: " File mapped & approved instantly"
      });
    }

    const { fileName, gcsPath, userId } = req.body;

    const approvalToken = jwt.sign(
      { fileName, gcsPath, userId },
      JWT_SECRET,
      { expiresIn: '10m' }
    );

    await sendApprovalEmails(
      approvalToken,
      'Mapping Approval',
      `File: ${fileName}\nPath: ${gcsPath}\nUserId: ${userId}`
    );

    return res.json({ message: ' Approval email sent' });

  } catch {
    res.status(500).json({ error: "Internal error" });
  }
});

// ===== APPROVE =====
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

// ===== APPROVE REGISTER =====
app.post('/approve-register', (req, res) => {
  const d = jwt.verify(req.body.token, JWT_SECRET);

  fileRegistry.set(d.fileName, {
    gcsPath: d.gcsPath,
    userId: d.userId
  });

  res.send(`<h2> Approved</h2>`);
});

// ===== VALIDATE DOWNLOAD =====
app.post('/validate-download', async (req, res) => {
  try {
    const { token, userId } = req.body;

    const d = jwt.verify(token, JWT_SECRET);

    if (d.userId !== userId) return res.send("Invalid UserId");

    const url = await generateSignedUrl(d.gcsPath);
    return res.redirect(url);

  } catch {
    return res.send("Invalid or expired token");
  }
});

// ===== CLEANUP =====
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of adminSessions.entries()) {
    if (v.expires < now) adminSessions.delete(k);
  }
}, 60000);

// ===== START =====
app.listen(PORT, () => {
  log(`Server running on ${PORT}`);
});