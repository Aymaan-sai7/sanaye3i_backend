const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const http = require('http');
const { Server } = require('socket.io');
const app = express();

app.set('trust proxy', 1);

const ALLOWED_ORIGIN = process.env.FRONTEND_URL || 'http://localhost:4200';
app.use(cors({ origin: ALLOWED_ORIGIN }));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const BOOTSTRAP_SECRET = process.env.ADMIN_BOOTSTRAP_SECRET;

const DB_FILE = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? `${process.env.RAILWAY_VOLUME_MOUNT_PATH}/db.json`
  : './db.json';

if (!fs.existsSync(DB_FILE)) {
  const initialData = { users: [], workers: [], bookings: [], reviews: [], messages: [], conversations: [], notifications: [] };
  fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
}

function readDB() { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
function writeDB(data) { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }

function ensureNotificationsCollection() {
  const db = readDB();
  if (!db.notifications) {
    db.notifications = [];
    writeDB(db);
  }
}
ensureNotificationsCollection();

function ensureCouponsCollection() {
  const db = readDB();
  if (!db.coupons) {
    db.coupons = [];
    writeDB(db);
  }
}
ensureCouponsCollection();

function ensureAdminLogsCollection() {
  const db = readDB();
  if (!db.adminLogs) {
    db.adminLogs = [];
    writeDB(db);
  }
}
ensureAdminLogsCollection();

const UPLOADS_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? `${process.env.RAILWAY_VOLUME_MOUNT_PATH}/uploads`
  : './uploads';

if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const uniqueName = crypto.randomUUID() + path.extname(file.originalname);
    cb(null, uniqueName);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('نوع الملف مش مسموح به. استخدم صورة أو PDF.'));
    }
    cb(null, true);
  },
});

app.use('/uploads', express.static(UPLOADS_DIR));

function sanitizeUser(user) {
  const { password, resetPasswordToken, resetPasswordExpiry, ...safe } = user;
  return safe;
}

// ============ ADMIN AUDIT LOG ============
function logAdminAction(req, action, targetType, targetId, details) {
  try {
    const db = readDB();
    if (!db.adminLogs) db.adminLogs = [];

    const admin = (db.users || []).find((u) => u.id === req.userId);

    db.adminLogs.unshift({
      id: crypto.randomUUID(),
      adminId: req.userId,
      adminName: admin?.fullName ?? null,
      action,
      targetType,
      targetId,
      details: details ?? null,
      createdAt: new Date().toISOString(),
    });

    if (db.adminLogs.length > 500) {
      db.adminLogs = db.adminLogs.slice(0, 500);
    }

    writeDB(db);
  } catch (err) {
    console.error('Failed to write admin log:', err);
  }
}

// ============ WEBSOCKET (Socket.IO) ============
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: ALLOWED_ORIGIN },
});

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('unauthorized'));
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') return next(new Error('forbidden'));
    socket.userId = decoded.id;
    next();
  } catch {
    next(new Error('unauthorized'));
  }
});

io.on('connection', (socket) => {
  socket.join('admins');
});

function broadcastPendingApprovals() {
  const db = readDB();
  const pendingApprovals = (db.users || []).filter((u) => u.status === 'pending').length;
  io.to('admins').emit('admin:pendingApprovalsChanged', { pendingApprovals });
}

// ============ EMAIL (Brevo HTTP API) ============
async function sendResetPasswordEmail(toEmail, fullName, resetLink) {
  const response = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'api-key': process.env.BREVO_API_KEY,
    },
    body: JSON.stringify({
      sender: { name: 'صنايعي', email: process.env.BREVO_SENDER_EMAIL },
      to: [{ email: toEmail, name: fullName || toEmail }],
      subject: 'إعادة تعيين كلمة المرور - صنايعي',
      htmlContent: `
      <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 480px; margin: auto; padding: 24px;">
        <h2 style="color: #2563EB;">صنايعي</h2>
        <p>أهلاً ${fullName || ''}،</p>
        <p>وصلنا طلب لإعادة تعيين كلمة المرور بتاعة حسابك. اضغط على الزرار ده عشان تعمل باسورد جديد:</p>
        <a href="${resetLink}" style="display:inline-block; background:#2563EB; color:#fff; padding:12px 24px; border-radius:8px; text-decoration:none; margin: 16px 0;">
          إعادة تعيين كلمة المرور
        </a>
        <p style="color:#94A3B8; font-size:13px;">الرابط ده هيشتغل لمدة ساعة واحدة بس. لو مطلبتش تغيير الباسورد، تجاهل الإيميل ده.</p>
      </div>
      `,
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Brevo API error (${response.status}): ${errorBody}`);
  }
}

async function sendAdminNotificationEmail(subject, htmlContent) {
  try {
    const db = readDB();
    const adminEmails = (db.users || [])
      .filter((u) => u.role === 'admin' && u.email)
      .map((u) => u.email);

    if (adminEmails.length === 0) return;

    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'api-key': process.env.BREVO_API_KEY,
      },
      body: JSON.stringify({
        sender: { name: 'صنايعي', email: process.env.BREVO_SENDER_EMAIL },
        to: adminEmails.map((email) => ({ email })),
        subject,
        htmlContent,
      }),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.error(`Admin notification email failed (${response.status}):`, errorBody);
    }
  } catch (err) {
    console.error('Failed to send admin notification email:', err);
  }
}

// ============ AUTH ENDPOINTS ============

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { message: 'محاولات كتير غلط، حاول تاني بعد شوية.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { message: 'محاولات تسجيل كتير، حاول تاني بعد شوية.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { message: 'محاولات كتير، حاول تاني بعد شوية.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/auth/register', registerLimiter, async (req, res) => {
  try {
    const { email, password, fullName, role, nationalId, mobileNumber, workerData } = req.body;

    if (!email || !password || !fullName || !role) {
      return res.status(400).json({ message: 'بيانات ناقصة.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ message: 'الباسورد لازم يكون 8 حروف على الأقل.' });
    }
    if (role !== 'client' && role !== 'pro') {
      return res.status(400).json({ message: 'نوع الحساب غير صالح.' });
    }
    if (role === 'pro' && !workerData) {
      return res.status(400).json({ message: 'بيانات الصنايعي ناقصة.' });
    }
    if (!nationalId || !/^\d{14}$/.test(nationalId)) {
      return res.status(400).json({ message: 'الرقم القومي لازم يكون 14 رقم صحيح.' });
    }
    if (!mobileNumber || !/^01[0125]\d{8}$/.test(mobileNumber)) {
      return res.status(400).json({ message: 'رقم الموبايل غير صحيح.' });
    }

    const db = readDB();

    const emailExists = db.users.find((u) => u.email === email);
    if (emailExists) {
      return res.status(409).json({ message: 'البريد الإلكتروني ده مسجل بالفعل.' });
    }

    const nationalIdExists = db.users.find((u) => u.nationalId === nationalId);
    if (nationalIdExists) {
      return res.status(409).json({ message: 'الرقم القومي ده مسجل بحساب تاني بالفعل.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: crypto.randomUUID(),
      email,
      password: hashedPassword,
      fullName,
      role,
      nationalId,
      mobileNumber,
      status: 'pending',
      createdAt: new Date().toISOString(),
    };

    let newWorker = null;
    if (role === 'pro') {
      newWorker = {
        id: crypto.randomUUID(),
        userId: newUser.id,
        fullName: workerData.fullName ?? fullName,
        trade: workerData.trade,
        tradeLabel: workerData.tradeLabel,
        city: workerData.city,
        hourlyRate: Number(workerData.hourlyRate) || 0,
        yearsOfExperience: Number(workerData.yearsOfExperience) || 0,
        serviceRadius: Number(workerData.serviceRadius) || 15,
        rating: 0,
        reviewsCount: 0,
        isAvailable: false,
        completedJobs: 0,
        bio: workerData.bio ?? '',
        avatarColor: workerData.avatarColor ?? '#2563EB',
        skills: Array.isArray(workerData.skills) ? workerData.skills : [],
      };
    }

    db.users.push(newUser);
    if (newWorker) db.workers.push(newWorker);
    writeDB(db);

    broadcastPendingApprovals();

    sendAdminNotificationEmail(
      'طلب تسجيل جديد - صنايعي',
      `
      <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 480px; margin: auto; padding: 24px;">
        <h2 style="color: #2563EB;">طلب تسجيل جديد</h2>
        <p><strong>${fullName}</strong> سجّل حساب جديد كـ ${role === 'pro' ? 'صنايعي' : 'عميل'}${
        role === 'pro' && newWorker ? ` (${newWorker.tradeLabel})` : ''
      }.</p>
        <p>ادخل لوحة التحكم عشان تراجع الطلب وتوافق عليه أو ترفضه.</p>
        <a href="${ALLOWED_ORIGIN}/admin/registrations" style="display:inline-block; background:#2563EB; color:#fff; padding:10px 20px; border-radius:8px; text-decoration:none; margin-top:12px;">
          مراجعة الطلب
        </a>
      </div>
      `
    );

    const docsUploadToken = jwt.sign({ id: newUser.id, role: newUser.role }, JWT_SECRET, {
      expiresIn: '15m',
    });

    res.status(201).json({
      message: 'طلبك اتبعت للمراجعة، هنراجعه ونرد عليك في أقرب وقت.',
      user: sanitizeUser(newUser),
      worker: newWorker,
      docsUploadToken,
    });
  } catch (err) {
    res.status(500).json({ message: 'حصل خطأ في السيرفر.' });
  }
});

app.post('/auth/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'بيانات ناقصة.' });
    }

    const db = readDB();
    const user = db.users.find((u) => u.email === email);

    if (!user) {
      return res.status(401).json({ message: 'الحساب ده مش موجود، سجل حساب جديد الأول.' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: 'كلمة المرور غلط.' });
    }

    if (user.status === 'pending') {
      return res.status(403).json({ message: 'حسابك لسه قيد المراجعة من الأدمن، هنبلغك أول ما يتم قبوله.' });
    }
    if (user.status === 'blocked') {
      return res.status(403).json({ message: 'حسابك متحظور. تواصل مع الدعم لو محتاج توضيح.' });
    }
    if (user.status === 'rejected') {
      return res.status(403).json({ message: 'للأسف طلب انضمامك اتقفل. تواصل مع الدعم لو حابب تفاصيل.' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ user: sanitizeUser(user), token });
  } catch (err) {
    res.status(500).json({ message: 'حصل خطأ في السيرفر.' });
  }
});

// ============ FORGOT / RESET PASSWORD ============

app.post('/auth/forgot-password', forgotPasswordLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: 'من فضلك أدخل البريد الإلكتروني.' });
    }

    const db = readDB();
    const user = db.users.find((u) => u.email === email);

    const genericResponse = {
      message: 'لو البريد الإلكتروني ده مسجل عندنا، هيوصلك لينك لإعادة تعيين كلمة المرور.',
    };

    if (!user) {
      return res.json(genericResponse);
    }

    const rawToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');

    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpiry = Date.now() + 60 * 60 * 1000;
    writeDB(db);

    const resetLink = `${ALLOWED_ORIGIN}/reset-password?token=${rawToken}&email=${encodeURIComponent(email)}`;

    try {
      await sendResetPasswordEmail(email, user.fullName, resetLink);
    } catch (emailErr) {
      console.error('Failed to send reset email:', emailErr);
    }

    res.json(genericResponse);
  } catch (err) {
    res.status(500).json({ message: 'حصل خطأ في السيرفر.' });
  }
});

app.post('/auth/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;

    if (!email || !token || !newPassword) {
      return res.status(400).json({ message: 'بيانات ناقصة.' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ message: 'الباسورد لازم يكون 8 حروف على الأقل.' });
    }

    const db = readDB();
    const user = db.users.find((u) => u.email === email);

    if (!user || !user.resetPasswordToken || !user.resetPasswordExpiry) {
      return res.status(400).json({ message: 'الرابط ده غير صالح أو مستخدم قبل كده.' });
    }

    if (Date.now() > user.resetPasswordExpiry) {
      delete user.resetPasswordToken;
      delete user.resetPasswordExpiry;
      writeDB(db);
      return res.status(400).json({ message: 'الرابط ده منتهي، اطلب لينك جديد.' });
    }

    const hashedIncoming = crypto.createHash('sha256').update(token).digest('hex');
    if (hashedIncoming !== user.resetPasswordToken) {
      return res.status(400).json({ message: 'الرابط ده غير صالح.' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    delete user.resetPasswordToken;
    delete user.resetPasswordExpiry;
    writeDB(db);

    res.json({ message: 'تم تغيير كلمة المرور بنجاح، سجل دخولك بالباسورد الجديد.' });
  } catch (err) {
    res.status(500).json({ message: 'حصل خطأ في السيرفر.' });
  }
});

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'غير مصرح.' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  } catch {
    return res.status(401).json({ message: 'الجلسة منتهية، سجل دخول تاني.' });
  }
}

function verifyAdmin(req, res, next) {
  verifyToken(req, res, () => {
    if (req.userRole !== 'admin') {
      return res.status(403).json({ message: 'غير مصرح لك بالوصول لده.' });
    }
    next();
  });
}

app.post(
  '/workers/:workerId/verification-docs',
  verifyToken,
  upload.fields([
    { name: 'idFront', maxCount: 1 },
    { name: 'idBack', maxCount: 1 },
    { name: 'certificate', maxCount: 1 },
  ]),
  (req, res) => {
    try {
      const db = readDB();
      const worker = db.workers.find((w) => w.id === req.params.workerId);
      if (!worker) return res.status(404).json({ message: 'مش لاقي بيانات الصنايعي.' });

      if (worker.userId !== req.userId) {
        return res.status(403).json({ message: 'مش مسموحلك بالتعديل ده.' });
      }

      if (req.files?.['idFront']?.[0]) {
        worker.idFrontUrl = `/uploads/${req.files['idFront'][0].filename}`;
      }
      if (req.files?.['idBack']?.[0]) {
        worker.idBackUrl = `/uploads/${req.files['idBack'][0].filename}`;
      }
      if (req.files?.['certificate']?.[0]) {
        worker.certificateUrl = `/uploads/${req.files['certificate'][0].filename}`;
      }
      worker.verificationStatus = 'pending';

      writeDB(db);
      res.json(worker);
    } catch (err) {
      res.status(500).json({ message: 'حصل خطأ أثناء رفع الملفات.' });
    }
  }
);

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err.message?.includes('نوع الملف')) {
    return res.status(400).json({ message: err.message || 'خطأ في رفع الملف.' });
  }
  next(err);
});

// ============ ADMIN ENDPOINTS ============

app.get('/admin/stats', verifyAdmin, (req, res) => {
  const db = readDB();
  const users = db.users || [];
  res.json({
    totalUsers: users.length,
    totalClients: users.filter((u) => u.role === 'client').length,
    totalPros: users.filter((u) => u.role === 'pro').length,
    pendingApprovals: users.filter((u) => u.status === 'pending').length,
    blockedUsers: users.filter((u) => u.status === 'blocked').length,
    totalBookings: (db.bookings || []).length,
    totalReviews: (db.reviews || []).length,
  });
});

app.get('/admin/logs', verifyAdmin, (req, res) => {
  const db = readDB();
  const limit = req.query.limit ? Number(req.query.limit) : 100;
  res.json((db.adminLogs || []).slice(0, limit));
});

app.get('/admin/users', verifyAdmin, (req, res) => {
  const db = readDB();
  let users = db.users || [];
  const { role, status, search } = req.query;

  if (role) users = users.filter((u) => u.role === role);
  if (status) users = users.filter((u) => (u.status ?? 'active') === status);
  if (search) {
    const q = String(search).toLowerCase();
    users = users.filter(
      (u) =>
        u.fullName?.toLowerCase().includes(q) ||
        u.email?.toLowerCase().includes(q) ||
        u.nationalId?.includes(q)
    );
  }

  res.json(users.map(sanitizeUser));
});

app.get('/admin/users/:id', verifyAdmin, (req, res) => {
  const db = readDB();
  const user = (db.users || []).find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ message: 'مش لاقي المستخدم ده.' });

  const worker =
    user.role === 'pro' ? (db.workers || []).find((w) => w.userId === user.id) : null;

  res.json({ user: sanitizeUser(user), worker });
});

app.patch('/admin/users/:id/status', verifyAdmin, (req, res) => {
  const { status } = req.body;
  const validStatuses = ['pending', 'active', 'rejected', 'blocked'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ message: 'الحالة المطلوبة مش صحيحة.' });
  }

  const db = readDB();
  const user = (db.users || []).find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ message: 'مش لاقي المستخدم ده.' });

  const previousStatus = user.status;
  user.status = status;

  if (user.role === 'pro') {
    const worker = (db.workers || []).find((w) => w.userId === user.id);
    if (worker) {
      worker.isAvailable = status === 'active';
    }
  }

  writeDB(db);

  logAdminAction(req, 'user_status_changed', 'user', user.id, {
    targetName: user.fullName,
    from: previousStatus,
    to: status,
  });

  broadcastPendingApprovals();

  res.json(sanitizeUser(user));
});

app.post('/admin/bootstrap', async (req, res) => {
  if (!BOOTSTRAP_SECRET || req.headers['x-bootstrap-secret'] !== BOOTSTRAP_SECRET) {
    return res.status(404).json({ message: 'Not Found' });
  }

  const { email, password, fullName } = req.body;
  if (!email || !password || !fullName) {
    return res.status(400).json({ message: 'بيانات ناقصة.' });
  }

  const db = readDB();
  if (db.users.find((u) => u.role === 'admin')) {
    return res.status(409).json({ message: 'فيه أدمن متعمل بالفعل.' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const admin = {
    id: crypto.randomUUID(),
    email,
    password: hashedPassword,
    fullName,
    role: 'admin',
    status: 'active',
    createdAt: new Date().toISOString(),
  };
  db.users.push(admin);
  writeDB(db);
  res.status(201).json({ message: 'اتعمل الأدمن بنجاح.' });
});

app.patch('/admin/me', verifyAdmin, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: 'إيميل غير صالح.' });
    }

    const db = readDB();

    const emailTaken = db.users.find((u) => u.email === email && u.id !== req.userId);
    if (emailTaken) {
      return res.status(409).json({ message: 'الإيميل ده مستخدم بالفعل بحساب تاني.' });
    }

    const admin = db.users.find((u) => u.id === req.userId);
    if (!admin) return res.status(404).json({ message: 'الحساب مش موجود.' });

    const previousEmail = admin.email;
    admin.email = email;
    writeDB(db);

    logAdminAction(req, 'admin_email_changed', 'admin', admin.id, {
      from: previousEmail,
      to: email,
    });

    res.json(sanitizeUser(admin));
  } catch (err) {
    res.status(500).json({ message: 'حصل خطأ في السيرفر.' });
  }
});

// ============ COUPONS ============

function generateCouponCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 8; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

app.get('/admin/coupons', verifyAdmin, (req, res) => {
  const db = readDB();
  res.json(db.coupons || []);
});

app.post('/admin/coupons', verifyAdmin, (req, res) => {
  try {
    const {
      code,
      discountType,
      discountValue,
      tradeRestriction,
      maxTotalUses,
      expiryDate,
    } = req.body;

    if (!discountType || !['percentage', 'fixed'].includes(discountType)) {
      return res.status(400).json({ message: 'نوع الخصم لازم يكون percentage أو fixed.' });
    }
    if (!discountValue || Number(discountValue) <= 0) {
      return res.status(400).json({ message: 'قيمة الخصم لازم تكون رقم أكبر من صفر.' });
    }
    if (discountType === 'percentage' && Number(discountValue) > 100) {
      return res.status(400).json({ message: 'نسبة الخصم مينفعش تتعدى 100%.' });
    }

    const db = readDB();
    if (!db.coupons) db.coupons = [];

    const finalCode = (code ? String(code).trim().toUpperCase() : generateCouponCode());

    const codeExists = db.coupons.find((c) => c.code === finalCode);
    if (codeExists) {
      return res.status(409).json({ message: 'الكود ده مستخدم بالفعل، جرب كود تاني.' });
    }

    const newCoupon = {
      id: crypto.randomUUID(),
      code: finalCode,
      discountType,
      discountValue: Number(discountValue),
      tradeRestriction: tradeRestriction || null,
      maxTotalUses: maxTotalUses != null ? Number(maxTotalUses) : null,
      usedCount: 0,
      usedByUserIds: [],
      expiryDate: expiryDate || null,
      isActive: true,
      createdAt: new Date().toISOString(),
    };

    db.coupons.push(newCoupon);
    writeDB(db);

    logAdminAction(req, 'coupon_created', 'coupon', newCoupon.id, {
      code: newCoupon.code,
      discountType: newCoupon.discountType,
      discountValue: newCoupon.discountValue,
    });

    res.status(201).json(newCoupon);
  } catch (err) {
    res.status(500).json({ message: 'حصل خطأ في السيرفر.' });
  }
});

app.patch('/admin/coupons/:id', verifyAdmin, (req, res) => {
  const db = readDB();
  const coupon = (db.coupons || []).find((c) => c.id === req.params.id);
  if (!coupon) return res.status(404).json({ message: 'مش لاقي الكوبون ده.' });

  const allowedFields = [
    'discountType',
    'discountValue',
    'tradeRestriction',
    'maxTotalUses',
    'expiryDate',
    'isActive',
  ];
  for (const field of allowedFields) {
    if (field in req.body) {
      coupon[field] = req.body[field];
    }
  }

  writeDB(db);

  logAdminAction(req, 'coupon_updated', 'coupon', coupon.id, {
    code: coupon.code,
    changes: req.body,
  });

  res.json(coupon);
});

app.delete('/admin/coupons/:id', verifyAdmin, (req, res) => {
  const db = readDB();
  const coupon = (db.coupons || []).find((c) => c.id === req.params.id);
  db.coupons = (db.coupons || []).filter((c) => c.id !== req.params.id);
  writeDB(db);

  if (coupon) {
    logAdminAction(req, 'coupon_deleted', 'coupon', req.params.id, { code: coupon.code });
  }

  res.json({ success: true });
});

app.post('/coupons/validate', verifyToken, (req, res) => {
  try {
    const { code, trade } = req.body;
    if (!code) {
      return res.status(400).json({ valid: false, message: 'اكتب كود الكوبون الأول.' });
    }

    const db = readDB();
    const coupon = (db.coupons || []).find(
      (c) => c.code === String(code).trim().toUpperCase()
    );

    if (!coupon) {
      return res.status(404).json({ valid: false, message: 'الكود ده مش موجود.' });
    }
    if (!coupon.isActive) {
      return res.status(400).json({ valid: false, message: 'الكوبون ده مش شغال دلوقتي.' });
    }
    if (coupon.expiryDate && Date.now() > new Date(coupon.expiryDate).getTime()) {
      return res.status(400).json({ valid: false, message: 'الكوبون ده منتهي الصلاحية.' });
    }
    if (coupon.tradeRestriction && trade && coupon.tradeRestriction !== trade) {
      return res.status(400).json({
        valid: false,
        message: `الكوبون ده مخصص لخدمة تانية بس.`,
      });
    }
    if (coupon.maxTotalUses != null && coupon.usedCount >= coupon.maxTotalUses) {
      return res.status(400).json({ valid: false, message: 'الكوبون ده خلص الاستخدامات بتاعته.' });
    }
    if (coupon.usedByUserIds.includes(req.userId)) {
      return res.status(400).json({ valid: false, message: 'أنت استخدمت الكوبون ده قبل كده.' });
    }

    res.json({
      valid: true,
      discountType: coupon.discountType,
      discountValue: coupon.discountValue,
      code: coupon.code,
    });
  } catch (err) {
    res.status(500).json({ valid: false, message: 'حصل خطأ في السيرفر.' });
  }
});

app.get('/coupons/active', (req, res) => {
  const db = readDB();
  const now = Date.now();

  const activeCoupons = (db.coupons || [])
    .filter((c) => {
      if (!c.isActive) return false;
      if (c.expiryDate && now > new Date(c.expiryDate).getTime()) return false;
      if (c.maxTotalUses != null && c.usedCount >= c.maxTotalUses) return false;
      return true;
    })
    .map((c) => ({
      code: c.code,
      discountType: c.discountType,
      discountValue: c.discountValue,
      tradeRestriction: c.tradeRestriction,
    }));

  res.json(activeCoupons);
});

// ============ PUBLIC STATS ============
let publicStatsCache = null;
let publicStatsCacheAt = 0;
const PUBLIC_STATS_TTL_MS = 15 * 60 * 1000;

function computePublicStats() {
  const db = readDB();
  const users = db.users || [];
  const workers = db.workers || [];
  const bookings = db.bookings || [];
  const reviews = db.reviews || [];

  const activeUserIds = new Set(users.filter((u) => u.status === 'active').map((u) => u.id));

  const approvedWorkers = workers.filter((w) => activeUserIds.has(w.userId));
  const totalWorkers = approvedWorkers.length;
  const activeWorkersNow = approvedWorkers.filter((w) => w.isAvailable).length;

  const totalClients = users.filter((u) => u.role === 'client' && u.status === 'active').length;

  const completedBookings = bookings.filter((b) => b.status === 'completed');
  const completedJobs = completedBookings.length;

  const avgRating =
    reviews.length > 0
      ? Math.round(
          (reviews.reduce((sum, r) => sum + (Number(r.rating) || 0), 0) / reviews.length) * 10
        ) / 10
      : 0;

  const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
  const now = Date.now();
  const recentCompletedRevenue = completedBookings
    .filter((b) => b.scheduledAt && now - new Date(b.scheduledAt).getTime() <= THIRTY_DAYS_MS)
    .reduce((sum, b) => sum + (Number(b.totalAmount) || 0), 0);
  const avgMonthlyIncome = totalWorkers > 0 ? Math.round(recentCompletedRevenue / totalWorkers) : 0;

  const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
  const clientsThisWeek = new Set(
    bookings
      .filter((b) => b.createdAt && now - new Date(b.createdAt).getTime() <= SEVEN_DAYS_MS)
      .map((b) => b.clientId)
  ).size;

  const workersByTrade = {};
  approvedWorkers.forEach((w) => {
    const trade = w.trade || 'other';
    workersByTrade[trade] = (workersByTrade[trade] || 0) + 1;
  });

  return {
    totalWorkers,
    activeWorkersNow,
    totalClients,
    completedJobs,
    avgRating,
    avgMonthlyIncome,
    clientsThisWeek,
    workersByTrade,
    updatedAt: new Date().toISOString(),
  };
}

app.get('/stats/public', (req, res) => {
  try {
    const now = Date.now();
    if (!publicStatsCache || now - publicStatsCacheAt > PUBLIC_STATS_TTL_MS) {
      publicStatsCache = computePublicStats();
      publicStatsCacheAt = now;
    }
    res.json(publicStatsCache);
  } catch (err) {
    res.status(500).json({ message: 'حصل خطأ في السيرفر.' });
  }
});

// ── إنشاء حجز (مخصص، بيسبق أي هاندلر تاني على /bookings) ─────────────
app.post('/bookings', verifyToken, (req, res) => {
  try {
    const { couponCode, ...bookingData } = req.body;
    const db = readDB();

    const originalAmount = Number(bookingData.totalAmount) || 0;
    let discountAmount = 0;
    let appliedCouponCode = null;

    if (couponCode) {
      const coupon = (db.coupons || []).find(
        (c) => c.code === String(couponCode).trim().toUpperCase()
      );

      if (!coupon) {
        return res.status(400).json({ message: 'كود الكوبون ده مش موجود.' });
      }
      if (!coupon.isActive) {
        return res.status(400).json({ message: 'الكوبون ده مش شغال دلوقتي.' });
      }
      if (coupon.expiryDate && Date.now() > new Date(coupon.expiryDate).getTime()) {
        return res.status(400).json({ message: 'الكوبون ده منتهي الصلاحية.' });
      }
      if (
        coupon.tradeRestriction &&
        bookingData.trade &&
        coupon.tradeRestriction !== bookingData.trade
      ) {
        return res.status(400).json({ message: 'الكوبون ده مخصص لخدمة تانية بس.' });
      }
      if (coupon.maxTotalUses != null && coupon.usedCount >= coupon.maxTotalUses) {
        return res.status(400).json({ message: 'الكوبون ده خلص الاستخدامات بتاعته.' });
      }
      if (coupon.usedByUserIds.includes(req.userId)) {
        return res.status(400).json({ message: 'أنت استخدمت الكوبون ده قبل كده.' });
      }

      discountAmount =
        coupon.discountType === 'percentage'
          ? (originalAmount * coupon.discountValue) / 100
          : coupon.discountValue;
      discountAmount = Math.min(discountAmount, originalAmount);
      appliedCouponCode = coupon.code;

      coupon.usedCount += 1;
      coupon.usedByUserIds.push(req.userId);
    }

    const finalAmount = Math.round((originalAmount - discountAmount) * 100) / 100;

    if (!db.bookings) db.bookings = [];
    const newBooking = {
      id: crypto.randomUUID(),
      ...bookingData,
      // ⚠️ لازم يكون العميل صاحب الحساب اللي بعت الطلب ده — مش أي clientId
      // اتبعت في الـ body، وإلا حد يقدر يعمل حجز باسم عميل تاني
      clientId: req.userId,
      workStage: null,
      originalAmount,
      discountAmount,
      couponCode: appliedCouponCode,
      totalAmount: finalAmount,
    };
    db.bookings.push(newBooking);
    writeDB(db);

    sendAdminNotificationEmail(
      'حجز جديد - صنايعي',
      `
      <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 480px; margin: auto; padding: 24px;">
        <h2 style="color: #2563EB;">حجز جديد</h2>
        <p><strong>${newBooking.clientName}</strong> حجز <strong>${newBooking.workerName}</strong>
          (${newBooking.workerTrade}).</p>
        <p>القيمة: ${newBooking.totalAmount} ج.م${
        newBooking.couponCode ? ` (بعد خصم كوبون "${newBooking.couponCode}")` : ''
      }</p>
        <a href="${ALLOWED_ORIGIN}/admin/bookings" style="display:inline-block; background:#2563EB; color:#fff; padding:10px 20px; border-radius:8px; text-decoration:none; margin-top:12px;">
          شوف الحجوزات
        </a>
      </div>
      `
    );

    res.status(201).json(newBooking);
  } catch (err) {
    res.status(500).json({ message: 'حصل خطأ في السيرفر.' });
  }
});

// ── رقم تلفون العميل/الصنايعي بتاعين حجز معين ────────────────
app.get('/bookings/:id/contact', verifyToken, (req, res) => {
  try {
    const db = readDB();
    const booking = (db.bookings || []).find((b) => b.id === req.params.id);
    if (!booking) return res.status(404).json({ message: 'الحجز ده مش موجود.' });

    const worker = (db.workers || []).find((w) => w.id === booking.workerId);
    const workerUserId = worker?.userId ?? null;

    const isClient = req.userId === booking.clientId;
    const isWorker = workerUserId && req.userId === workerUserId;
    if (!isClient && !isWorker) {
      return res.status(403).json({ message: 'مش مسموحلك تشوف بيانات التواصل دي.' });
    }

    const clientUser = (db.users || []).find((u) => u.id === booking.clientId);
    const workerUser = workerUserId ? (db.users || []).find((u) => u.id === workerUserId) : null;

    res.json({
      clientPhone: clientUser?.mobileNumber ?? null,
      workerPhone: workerUser?.mobileNumber ?? null,
    });
  } catch (err) {
    res.status(500).json({ message: 'حصل خطأ في السيرفر.' });
  }
});

// ── تحديث مرحلة الشغل (في الطريق / بدأ الشغل / خلّص) ─────────
const VALID_WORK_STAGES = ['on_the_way', 'in_progress', 'done'];

app.patch('/bookings/:id/work-stage', verifyToken, (req, res) => {
  try {
    const { workStage } = req.body;
    if (!VALID_WORK_STAGES.includes(workStage)) {
      return res.status(400).json({ message: 'مرحلة الشغل المطلوبة مش صحيحة.' });
    }

    const db = readDB();
    const booking = (db.bookings || []).find((b) => b.id === req.params.id);
    if (!booking) return res.status(404).json({ message: 'الحجز ده مش موجود.' });

    const worker = (db.workers || []).find((w) => w.id === booking.workerId);
    if (!worker || worker.userId !== req.userId) {
      return res.status(403).json({ message: 'مش مسموحلك تعدّل الحجز ده.' });
    }

    if (booking.status !== 'active') {
      return res.status(400).json({ message: 'الطلب ده مش شغل جاري دلوقتي.' });
    }

    booking.workStage = workStage;
    writeDB(db);

    res.json(booking);
  } catch (err) {
    res.status(500).json({ message: 'حصل خطأ في السيرفر.' });
  }
});

// ── رد الصنايعي على تقييم ─────────────────────────────────
app.patch('/reviews/:id/reply', verifyToken, (req, res) => {
  try {
    const { reply } = req.body;
    if (!reply || !String(reply).trim()) {
      return res.status(400).json({ message: 'اكتب رد الأول.' });
    }
    if (String(reply).trim().length > 500) {
      return res.status(400).json({ message: 'الرد طويل أوي، حاول تختصره.' });
    }

    const db = readDB();
    const review = (db.reviews || []).find((r) => r.id === req.params.id);
    if (!review) return res.status(404).json({ message: 'التقييم ده مش موجود.' });

    const worker = (db.workers || []).find((w) => w.id === review.workerId);
    if (!worker || worker.userId !== req.userId) {
      return res.status(403).json({ message: 'مش مسموحلك ترد على التقييم ده.' });
    }

    review.workerReply = String(reply).trim();
    review.workerReplyAt = new Date().toISOString();
    writeDB(db);

    res.json(review);
  } catch (err) {
    res.status(500).json({ message: 'حصل خطأ في السيرفر.' });
  }
});

// ── تعديل بروفايل الصنايعي (محمي) ─────────────────────────
const WORKER_EDITABLE_FIELDS = [
  'fullName',
  'trade',
  'tradeLabel',
  'city',
  'hourlyRate',
  'yearsOfExperience',
  'serviceRadius',
  'bio',
  'avatarColor',
  'skills',
  'isAvailable',
];

function updateWorkerProfile(req, res) {
  const db = readDB();
  const worker = (db.workers || []).find((w) => w.id === req.params.id);
  if (!worker) return res.status(404).json({ message: 'مش لاقي بيانات الصنايعي.' });

  const isOwner = worker.userId === req.userId;
  const isAdmin = req.userRole === 'admin';
  if (!isOwner && !isAdmin) {
    return res.status(403).json({ message: 'مش مسموحلك تعدّل البروفايل ده.' });
  }

  for (const field of WORKER_EDITABLE_FIELDS) {
    if (field in req.body) {
      worker[field] = req.body[field];
    }
  }

  writeDB(db);
  res.json(worker);
}

app.put('/workers/:id', verifyToken, updateWorkerProfile);
app.patch('/workers/:id', verifyToken, updateWorkerProfile);

app.post('/workers', verifyToken, (req, res) => {
  const db = readDB();
  if (!db.workers) db.workers = [];
  const newItem = { id: crypto.randomUUID(), ...req.body, userId: req.userId };
  db.workers.push(newItem);
  writeDB(db);
  res.status(201).json(newItem);
});

app.delete('/workers/:id', verifyToken, (req, res) => {
  const db = readDB();
  const item = (db.workers || []).find((w) => w.id === req.params.id);
  if (!item) return res.json({ success: true });
  if (item.userId !== req.userId && req.userRole !== 'admin') {
    return res.status(403).json({ message: 'مش مسموحلك تحذف البروفايل ده.' });
  }
  db.workers = (db.workers || []).filter((w) => w.id !== req.params.id);
  writeDB(db);
  res.json({ success: true });
});

// ============ WORKERS — قراءة عامة (Public) ============
const SPECIAL_QUERY_KEYS = ['_sort', '_order', '_limit', '_page'];

function applyQueryFilters(items, query) {
  let result = items;
  Object.keys(query).forEach((key) => {
    if (SPECIAL_QUERY_KEYS.includes(key)) return;
    result = result.filter((item) => String(item[key]) === String(query[key]));
  });

  if (query._sort) {
    const order = query._order === 'desc' ? -1 : 1;
    result = [...result].sort((a, b) => {
      const field = query._sort;
      if (a[field] < b[field]) return -1 * order;
      if (a[field] > b[field]) return 1 * order;
      return 0;
    });
  }

  if (query._limit) {
    result = result.slice(0, Number(query._limit));
  }

  return result;
}

app.get('/workers', (req, res) => {
  const db = readDB();
  let items = (db.workers || []).filter((worker) => {
    const owner = (db.users || []).find((u) => u.id === worker.userId);
    return !owner || owner.status === 'active';
  });
  items = applyQueryFilters(items, req.query);
  res.json(items);
});

app.get('/workers/:id', (req, res) => {
  const db = readDB();
  const item = (db.workers || []).find((w) => w.id === req.params.id);
  if (!item) return res.status(404).json({ message: 'Not Found' });

  const owner = (db.users || []).find((u) => u.id === item.userId);
  if (owner && owner.status !== 'active') {
    return res.status(404).json({ message: 'Not Found' });
  }

  res.json(item);
});

// ============ REVIEWS ============
function recomputeWorkerRating(db, workerId) {
  const reviews = (db.reviews || []).filter((r) => r.workerId === workerId);
  const reviewsCount = reviews.length;
  const rating = reviewsCount > 0
    ? Math.round((reviews.reduce((sum, r) => sum + r.rating, 0) / reviewsCount) * 10) / 10
    : 0;
  const worker = (db.workers || []).find((w) => w.id === workerId);
  if (worker) {
    worker.rating = rating;
    worker.reviewsCount = reviewsCount;
  }
}

app.get('/reviews', (req, res) => {
  const db = readDB();
  const items = applyQueryFilters(db.reviews || [], req.query);
  res.json(items);
});

app.get('/reviews/:id', (req, res) => {
  const db = readDB();
  const item = (db.reviews || []).find((r) => r.id === req.params.id);
  if (!item) return res.status(404).json({ message: 'Not Found' });
  res.json(item);
});

app.post('/reviews', verifyToken, (req, res) => {
  try {
    const { bookingId, clientName, workerId, rating, comment } = req.body;

    if (!bookingId || !workerId || rating == null) {
      return res.status(400).json({ message: 'بيانات التقييم ناقصة.' });
    }
    const numRating = Number(rating);
    if (!Number.isFinite(numRating) || numRating < 1 || numRating > 5) {
      return res.status(400).json({ message: 'التقييم لازم يكون رقم من 1 لـ 5.' });
    }

    const db = readDB();
    const booking = (db.bookings || []).find((b) => b.id === bookingId);
    if (!booking) return res.status(404).json({ message: 'الحجز ده مش موجود.' });

    if (booking.clientId !== req.userId) {
      return res.status(403).json({ message: 'مش مسموحلك تقيّم الحجز ده.' });
    }
    if (booking.status !== 'completed') {
      return res.status(400).json({ message: 'تقدر تقيّم بس بعد ما الشغل يخلص.' });
    }
    if (booking.workerId !== workerId) {
      return res.status(400).json({ message: 'بيانات التقييم مش متطابقة مع الحجز.' });
    }

    const alreadyReviewed = (db.reviews || []).find((r) => r.bookingId === bookingId);
    if (alreadyReviewed) {
      return res.status(409).json({ message: 'قيّمت الحجز ده قبل كده.' });
    }

    if (!db.reviews) db.reviews = [];
    const newReview = {
      id: crypto.randomUUID(),
      bookingId,
      clientId: req.userId,
      clientName: clientName ?? '',
      workerId,
      rating: numRating,
      comment: comment ?? '',
      createdAt: new Date().toISOString(),
    };
    db.reviews.push(newReview);
    recomputeWorkerRating(db, workerId);
    writeDB(db);

    res.status(201).json(newReview);
  } catch (err) {
    res.status(500).json({ message: 'حصل خطأ في السيرفر.' });
  }
});

app.patch('/reviews/:id', verifyToken, (req, res) => {
  try {
    const db = readDB();
    const review = (db.reviews || []).find((r) => r.id === req.params.id);
    if (!review) return res.status(404).json({ message: 'التقييم ده مش موجود.' });

    if (review.clientId !== req.userId && req.userRole !== 'admin') {
      return res.status(403).json({ message: 'مش مسموحلك تعدّل التقييم ده.' });
    }

    if ('rating' in req.body) {
      const numRating = Number(req.body.rating);
      if (!Number.isFinite(numRating) || numRating < 1 || numRating > 5) {
        return res.status(400).json({ message: 'التقييم لازم يكون رقم من 1 لـ 5.' });
      }
      review.rating = numRating;
    }
    if ('comment' in req.body) {
      review.comment = req.body.comment;
    }
    review.updatedAt = new Date().toISOString();

    recomputeWorkerRating(db, review.workerId);
    writeDB(db);
    res.json(review);
  } catch (err) {
    res.status(500).json({ message: 'حصل خطأ في السيرفر.' });
  }
});

app.delete('/reviews/:id', verifyAdmin, (req, res) => {
  const db = readDB();
  const review = (db.reviews || []).find((r) => r.id === req.params.id);
  if (!review) return res.status(404).json({ message: 'مش لاقي التقييم ده.' });

  db.reviews = (db.reviews || []).filter((r) => r.id !== req.params.id);
  recomputeWorkerRating(db, review.workerId);
  writeDB(db);
  res.json({ success: true });
});

// ============ BOOKINGS — الباقي (GET/PATCH/PUT/DELETE) ============
function canAccessBooking(req, booking, db) {
  if (req.userRole === 'admin') return true;
  if (booking.clientId === req.userId) return true;
  const worker = (db.workers || []).find((w) => w.id === booking.workerId);
  return !!(worker && worker.userId === req.userId);
}

app.get('/bookings', verifyToken, (req, res) => {
  const db = readDB();
  let items = applyQueryFilters(db.bookings || [], req.query);
  if (req.userRole !== 'admin') {
    items = items.filter((b) => canAccessBooking(req, b, db));
  }
  res.json(items);
});

app.get('/bookings/:id', verifyToken, (req, res) => {
  const db = readDB();
  const item = (db.bookings || []).find((b) => b.id === req.params.id);
  if (!item) return res.status(404).json({ message: 'Not Found' });
  if (!canAccessBooking(req, item, db)) {
    return res.status(403).json({ message: 'مش مسموحلك تشوف الحجز ده.' });
  }
  res.json(item);
});

function updateBookingHandler(req, res) {
  const db = readDB();
  const index = (db.bookings || []).findIndex((b) => b.id === req.params.id);
  if (index === -1) return res.status(404).json({ message: 'Not Found' });
  if (!canAccessBooking(req, db.bookings[index], db)) {
    return res.status(403).json({ message: 'مش مسموحلك تعدّل الحجز ده.' });
  }
  const { clientId, workerId, ...safeChanges } = req.body;
  db.bookings[index] = { ...db.bookings[index], ...safeChanges };
  writeDB(db);
  res.json(db.bookings[index]);
}
app.put('/bookings/:id', verifyToken, updateBookingHandler);
app.patch('/bookings/:id', verifyToken, updateBookingHandler);

app.delete('/bookings/:id', verifyToken, (req, res) => {
  const db = readDB();
  const item = (db.bookings || []).find((b) => b.id === req.params.id);
  if (!item) return res.json({ success: true });
  if (!canAccessBooking(req, item, db)) {
    return res.status(403).json({ message: 'مش مسموحلك تحذف الحجز ده.' });
  }
  db.bookings = (db.bookings || []).filter((b) => b.id !== req.params.id);
  writeDB(db);
  res.json({ success: true });
});

// ============ CONVERSATIONS ============
function canAccessConversation(req, conversation) {
  return conversation.clientId === req.userId || conversation.workerId === req.userId;
}

app.get('/conversations', verifyToken, (req, res) => {
  const db = readDB();
  let items = applyQueryFilters(db.conversations || [], req.query);
  items = items.filter((c) => canAccessConversation(req, c));
  res.json(items);
});

app.get('/conversations/:id', verifyToken, (req, res) => {
  const db = readDB();
  const item = (db.conversations || []).find((c) => c.id === req.params.id);
  if (!item) return res.status(404).json({ message: 'Not Found' });
  if (!canAccessConversation(req, item)) {
    return res.status(403).json({ message: 'مش مسموحلك تشوف المحادثة دي.' });
  }
  res.json(item);
});

app.post('/conversations', verifyToken, (req, res) => {
  const { clientId, workerId } = req.body;
  if (req.userId !== clientId && req.userId !== workerId) {
    return res.status(403).json({ message: 'مش مسموحلك تعمل المحادثة دي.' });
  }
  const db = readDB();
  if (!db.conversations) db.conversations = [];
  const newItem = { id: crypto.randomUUID(), ...req.body };
  db.conversations.push(newItem);
  writeDB(db);
  res.status(201).json(newItem);
});

function updateConversationHandler(req, res) {
  const db = readDB();
  const index = (db.conversations || []).findIndex((c) => c.id === req.params.id);
  if (index === -1) return res.status(404).json({ message: 'Not Found' });
  if (!canAccessConversation(req, db.conversations[index])) {
    return res.status(403).json({ message: 'مش مسموحلك تعدّل المحادثة دي.' });
  }
  db.conversations[index] = { ...db.conversations[index], ...req.body };
  writeDB(db);
  res.json(db.conversations[index]);
}
app.put('/conversations/:id', verifyToken, updateConversationHandler);
app.patch('/conversations/:id', verifyToken, updateConversationHandler);

app.delete('/conversations/:id', verifyToken, (req, res) => {
  const db = readDB();
  const item = (db.conversations || []).find((c) => c.id === req.params.id);
  if (!item) return res.json({ success: true });
  if (!canAccessConversation(req, item)) {
    return res.status(403).json({ message: 'مش مسموحلك تحذف المحادثة دي.' });
  }
  db.conversations = (db.conversations || []).filter((c) => c.id !== req.params.id);
  writeDB(db);
  res.json({ success: true });
});

// ============ MESSAGES ============
function canAccessMessage(req, message) {
  return message.senderId === req.userId || message.recipientId === req.userId;
}

app.get('/messages', verifyToken, (req, res) => {
  const db = readDB();
  let items = applyQueryFilters(db.messages || [], req.query);
  items = items.filter((m) => canAccessMessage(req, m));
  res.json(items);
});

app.get('/messages/:id', verifyToken, (req, res) => {
  const db = readDB();
  const item = (db.messages || []).find((m) => m.id === req.params.id);
  if (!item) return res.status(404).json({ message: 'Not Found' });
  if (!canAccessMessage(req, item)) {
    return res.status(403).json({ message: 'مش مسموحلك تشوف الرسالة دي.' });
  }
  res.json(item);
});

app.post('/messages', verifyToken, (req, res) => {
  const { conversationId, senderId, recipientId } = req.body;
  if (req.userId !== senderId) {
    return res.status(403).json({ message: 'مش مسموحلك تبعت رسالة نيابة عن حد تاني.' });
  }
  const db = readDB();
  const conversation = (db.conversations || []).find((c) => c.id === conversationId);
  if (!conversation || !canAccessConversation(req, conversation)) {
    return res.status(403).json({ message: 'المحادثة دي مش موجودة أو مش بتاعتك.' });
  }
  if (!db.messages) db.messages = [];
  const newItem = { id: crypto.randomUUID(), ...req.body };
  db.messages.push(newItem);
  writeDB(db);
  res.status(201).json(newItem);
});

function updateMessageHandler(req, res) {
  const db = readDB();
  const index = (db.messages || []).findIndex((m) => m.id === req.params.id);
  if (index === -1) return res.status(404).json({ message: 'Not Found' });
  const message = db.messages[index];
  if (message.recipientId !== req.userId) {
    return res.status(403).json({ message: 'مش مسموحلك تعدّل الرسالة دي.' });
  }
  db.messages[index] = { ...message, ...req.body };
  writeDB(db);
  res.json(db.messages[index]);
}
app.put('/messages/:id', verifyToken, updateMessageHandler);
app.patch('/messages/:id', verifyToken, updateMessageHandler);

app.delete('/messages/:id', verifyToken, (req, res) => {
  const db = readDB();
  const item = (db.messages || []).find((m) => m.id === req.params.id);
  if (!item) return res.json({ success: true });
  if (!canAccessMessage(req, item)) {
    return res.status(403).json({ message: 'مش مسموحلك تحذف الرسالة دي.' });
  }
  db.messages = (db.messages || []).filter((m) => m.id !== req.params.id);
  writeDB(db);
  res.json({ success: true });
});

// ============ NOTIFICATIONS ============
function canAccessNotification(req, notification) {
  return req.userRole === 'admin' || notification.userId === req.userId;
}

app.get('/notifications', verifyToken, (req, res) => {
  const db = readDB();
  let items = applyQueryFilters(db.notifications || [], req.query);
  if (req.userRole !== 'admin') {
    items = items.filter((n) => n.userId === req.userId);
  }
  res.json(items);
});

app.get('/notifications/:id', verifyToken, (req, res) => {
  const db = readDB();
  const item = (db.notifications || []).find((n) => n.id === req.params.id);
  if (!item) return res.status(404).json({ message: 'Not Found' });
  if (!canAccessNotification(req, item)) {
    return res.status(403).json({ message: 'مش مسموحلك تشوف الإشعار ده.' });
  }
  res.json(item);
});

app.post('/notifications', verifyToken, (req, res) => {
  const db = readDB();
  if (!db.notifications) db.notifications = [];
  const newItem = {
    id: crypto.randomUUID(),
    isRead: false,
    createdAt: new Date().toISOString(),
    ...req.body,
  };
  db.notifications.push(newItem);
  writeDB(db);
  res.status(201).json(newItem);
});

function updateNotificationHandler(req, res) {
  const db = readDB();
  const index = (db.notifications || []).findIndex((n) => n.id === req.params.id);
  if (index === -1) return res.status(404).json({ message: 'Not Found' });
  if (!canAccessNotification(req, db.notifications[index])) {
    return res.status(403).json({ message: 'مش مسموحلك تعدّل الإشعار ده.' });
  }
  db.notifications[index] = { ...db.notifications[index], ...req.body };
  writeDB(db);
  res.json(db.notifications[index]);
}
app.put('/notifications/:id', verifyToken, updateNotificationHandler);
app.patch('/notifications/:id', verifyToken, updateNotificationHandler);

app.delete('/notifications/:id', verifyToken, (req, res) => {
  const db = readDB();
  const item = (db.notifications || []).find((n) => n.id === req.params.id);
  if (!item) return res.json({ success: true });
  if (!canAccessNotification(req, item)) {
    return res.status(403).json({ message: 'مش مسموحلك تحذف الإشعار ده.' });
  }
  db.notifications = (db.notifications || []).filter((n) => n.id !== req.params.id);
  writeDB(db);
  res.json({ success: true });
});

app.get('/', (req, res) => res.send('Sanaye3i Backend is Running 🚀'));

const port = process.env.PORT || 3000;
server.listen(port, () => console.log(`Server running on port ${port}`));
