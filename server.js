const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const app = express();

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

// ============ EMAIL (Brevo HTTP API) ============
// ⚠️ بنستخدم الـ HTTP API بدل SMTP عمدًا — كتير من منصات الاستضافة (زي Railway)
// بتحجب أو بتقيّد بورتات SMTP التقليدية (587/465/25) كإجراء ضد الـ spam، فالاتصال
// بيعمل timeout. الـ API بيشتغل عن طريق HTTPS العادي (بورت 443) اللي مش محجوب أبدًا.
// ⚠️ متغيرات البيئة المطلوبة على Railway:
// BREVO_API_KEY, BREVO_SENDER_EMAIL
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
      mobileNumber, // ⚠️ جديد
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
        // ⚠️ false من الأول — هتتفعّل تلقائي لما الأدمن يوافق (شوف /admin/users/:id/status تحت)
        isAvailable: false,
        completedJobs: 0,
        bio: workerData.bio ?? '',
        avatarColor: workerData.avatarColor ?? '#2563EB',
      };
    }

    db.users.push(newUser);
    if (newWorker) db.workers.push(newWorker);
    writeDB(db);

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

    // ⚠️ رد عام بغض النظر لو الإيميل موجود ولا لأ — عشان محدش يقدر يتأكد
    // مين مسجل عندنا من غيره (نفس المبدأ اللي بنتبعه في register أصلاً)
    const genericResponse = {
      message: 'لو البريد الإلكتروني ده مسجل عندنا، هيوصلك لينك لإعادة تعيين كلمة المرور.',
    };

    if (!user) {
      return res.json(genericResponse);
    }

    // توكن عشوائي طويل، بنبعت الـ raw token في الإيميل وبنخزن نسخة hashed بس
    // (زي الباسورد بالظبط) — عشان لو حد وصل لـ db.json مايقدرش يستخدم التوكنات المخزنة
    const rawToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');

    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpiry = Date.now() + 60 * 60 * 1000; // ساعة واحدة
    writeDB(db);

    const resetLink = `${ALLOWED_ORIGIN}/reset-password?token=${rawToken}&email=${encodeURIComponent(email)}`;

    try {
      await sendResetPasswordEmail(email, user.fullName, resetLink);
    } catch (emailErr) {
      // لو فشل إرسال الإيميل، منسيبش المستخدم يعرف (عشان مانكشفش وجود الحساب) —
      // بس بنلوج الخطأ عندنا عشان نلاحظه
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
    // التوكن بيتحرق بعد الاستخدام — نفس فكرة الـ single-use
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

// تغيير حالة مستخدم — accept / reject / block / unblock
// ⚠️ لو صنايعي، بنزامن worker.isAvailable مع الحالة الجديدة تلقائيًا
app.patch('/admin/users/:id/status', verifyAdmin, (req, res) => {
  const { status } = req.body;
  const validStatuses = ['pending', 'active', 'rejected', 'blocked'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ message: 'الحالة المطلوبة مش صحيحة.' });
  }

  const db = readDB();
  const user = (db.users || []).find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ message: 'مش لاقي المستخدم ده.' });

  user.status = status;

  if (user.role === 'pro') {
    const worker = (db.workers || []).find((w) => w.userId === user.id);
    if (worker) {
      worker.isAvailable = status === 'active';
    }
  }

  writeDB(db);
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

// ============ باقي الـ collections ============
const collections = ['workers', 'bookings', 'reviews', 'messages', 'conversations', 'notifications'];
const SPECIAL_QUERY_KEYS = ['_sort', '_order', '_limit', '_page'];

// ⚠️⚠️ الفيكس الحرج: أي GET عام على /workers لازم يستثني أي صنايعي
// الـ user المرتبط بيه status != 'active' — وإلا صنايعية pending/blocked/rejected
// هيفضلوا ظاهرين للعملاء في find-services وكأن حسابهم متوافق عليه فعليًا
collections.forEach((collection) => {
  app.get(`/${collection}`, (req, res) => {
    const db = readDB();
    let items = db[collection] || [];
    const query = req.query;

    if (collection === 'workers') {
      items = items.filter((worker) => {
        const owner = (db.users || []).find((u) => u.id === worker.userId);
        return !owner || owner.status === 'active';
      });
    }

    Object.keys(query).forEach((key) => {
      if (SPECIAL_QUERY_KEYS.includes(key)) return;
      items = items.filter((item) => String(item[key]) === String(query[key]));
    });

    if (query._sort) {
      const order = query._order === 'desc' ? -1 : 1;
      items = [...items].sort((a, b) => {
        const field = query._sort;
        if (a[field] < b[field]) return -1 * order;
        if (a[field] > b[field]) return 1 * order;
        return 0;
      });
    }

    if (query._limit) {
      items = items.slice(0, Number(query._limit));
    }

    res.json(items);
  });
});

// ⚠️ نفس الفكرة على /workers/:id — وإلا حد يقدر يوصل لبروفايل صنايعي pending
// مباشرة لو عرف رابط الـ id بتاعه (مثلاً لو حفظ اللينك قبل ما يتقبل)
collections.forEach((collection) => {
  app.get(`/${collection}/:id`, (req, res) => {
    const db = readDB();
    const item = (db[collection] || []).find((x) => String(x.id) === req.params.id);
    if (!item) return res.status(404).json({ message: 'Not Found' });

    if (collection === 'workers') {
      const owner = (db.users || []).find((u) => u.id === item.userId);
      if (owner && owner.status !== 'active') {
        return res.status(404).json({ message: 'Not Found' });
      }
    }

    res.json(item);
  });
});

collections.forEach((collection) => {
  app.post(`/${collection}`, (req, res) => {
    const db = readDB();
    if (!db[collection]) db[collection] = [];
    const newItem = { id: Date.now().toString() + Math.random().toString(36).slice(2, 6), ...req.body };
    db[collection].push(newItem);
    writeDB(db);
    res.status(201).json(newItem);
  });
});

collections.forEach((collection) => {
  const updateHandler = (req, res) => {
    const db = readDB();
    const index = (db[collection] || []).findIndex((x) => String(x.id) === req.params.id);
    if (index === -1) return res.status(404).json({ message: 'Not Found' });
    db[collection][index] = { ...db[collection][index], ...req.body };
    writeDB(db);
    res.json(db[collection][index]);
  };
  app.put(`/${collection}/:id`, updateHandler);
  app.patch(`/${collection}/:id`, updateHandler);
});

collections.forEach((collection) => {
  app.delete(`/${collection}/:id`, (req, res) => {
    const db = readDB();
    db[collection] = (db[collection] || []).filter((x) => String(x.id) !== req.params.id);
    writeDB(db);
    res.json({ success: true });
  });
});

app.get('/', (req, res) => res.send('Sanaye3i Backend is Running '));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
