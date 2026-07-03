const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const app = express();

// ⚠️ غيّر ده لدومين الفرونت إند بتاعك الحقيقي وقت الديبلوي
const ALLOWED_ORIGIN = process.env.FRONTEND_URL || 'http://localhost:4200';
app.use(cors({ origin: ALLOWED_ORIGIN }));
app.use(express.json());

// ⚠️ لازم تضيفه كـ environment variable في Railway (Variables tab)، متسيبوش هنا في production
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const DB_FILE = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? `${process.env.RAILWAY_VOLUME_MOUNT_PATH}/db.json`
  : './db.json';

if (!fs.existsSync(DB_FILE)) {
  const initialData = { users: [], workers: [], bookings: [], reviews: [], messages: [], conversations: [], notifications: [] };
  fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
}

// ⚠️ لو الـ Volume عندك متعمل من قبل وفيه بيانات، لازم نضيف مصفوفة notifications
// فاضية لو مش موجودة أصلاً في db.json القديم (وإلا أي كتابة عليها هترمي error)
function ensureNotificationsCollection() {
  const db = readDB();
  if (!db.notifications) {
    db.notifications = [];
    writeDB(db);
  }
}
ensureNotificationsCollection();

function readDB() { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
function writeDB(data) { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }

// بيشيل الباسورد قبل ما نرجع أي user object للفرونت إند
function sanitizeUser(user) {
  const { password, ...safe } = user;
  return safe;
}

// ============ AUTH ENDPOINTS ============

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 5,
  message: { message: 'محاولات كتير غلط، حاول تاني بعد شوية.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// حد أعلى وأخف على التسجيل — يمنع إنشاء حسابات سبام بالجملة من نفس الـ IP
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // ساعة
  max: 10,
  message: { message: 'محاولات تسجيل كتير، حاول تاني بعد شوية.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ── التسجيل: عملية واحدة atomic — user + worker profile (لو pro) بيتكتبوا مع بعض ──
app.post('/auth/register', registerLimiter, async (req, res) => {
  try {
    const { email, password, fullName, role, workerData } = req.body;

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

    const db = readDB();
    const exists = db.users.find((u) => u.email === email);
    if (exists) {
      return res.status(409).json({ message: 'البريد الإلكتروني ده مسجل بالفعل.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: crypto.randomUUID(),
      email,
      password: hashedPassword,
      fullName,
      role,
      createdAt: new Date().toISOString(),
    };

    // لو pro، بنجهز بيانات الـ worker الأول قبل أي كتابة فعلية على الملف
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
        isAvailable: true,
        completedJobs: 0,
        bio: workerData.bio ?? '',
        avatarColor: workerData.avatarColor ?? '#2563EB',
      };
    }

    // الكتابة الفعلية بتحصل مرة واحدة بس، بعد ما كل حاجة جاهزة —
    // يعني إما الاتنين يتسجلوا مع بعض، أو محدش يتسجل خالص
    db.users.push(newUser);
    if (newWorker) db.workers.push(newWorker);
    writeDB(db);

    const token = jwt.sign({ id: newUser.id, role: newUser.role }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ user: sanitizeUser(newUser), token, worker: newWorker });
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

    // نفس رسالة الخطأ للاتنين (إيميل مش موجود / باسورد غلط) عشان منديش معلومة لمهاجم إن الإيميل موجود أو لأ
    if (!user) {
      return res.status(401).json({ message: 'البريد الإلكتروني أو كلمة المرور غلط.' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: 'البريد الإلكتروني أو كلمة المرور غلط.' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ user: sanitizeUser(user), token });
  } catch (err) {
    res.status(500).json({ message: 'حصل خطأ في السيرفر.' });
  }
});

// ── Middleware للتحقق من JWT — هنستخدمه في endpoint رفع الملفات ──
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

// ============ باقي الـ collections ============
// ⚠️ لاحظ إننا شلنا 'users' من هنا خالص عشان محدش يقدر يعمل GET /users
// ويشوف كل المستخدمين بالباسورد الحقيقي بتاعهم
const collections = ['workers', 'bookings', 'reviews', 'messages', 'conversations', 'notifications'];

// query params بتبدأ بـ _ دي أوامر خاصة (ترتيب/تحديد عدد) زي json-server،
// مش فلاتر بيانات فعلية — لازم نستثنيهم من الفلترة العادية
const SPECIAL_QUERY_KEYS = ['_sort', '_order', '_limit', '_page'];

collections.forEach((collection) => {
  app.get(`/${collection}`, (req, res) => {
    const db = readDB();
    let items = db[collection] || [];
    const query = req.query;

    // فلترة عادية (equality) — بتتجاهل الـ special keys
    Object.keys(query).forEach((key) => {
      if (SPECIAL_QUERY_KEYS.includes(key)) return;
      items = items.filter((item) => String(item[key]) === String(query[key]));
    });

    // ترتيب (زي json-server: ?_sort=createdAt&_order=desc)
    if (query._sort) {
      const order = query._order === 'desc' ? -1 : 1;
      items = [...items].sort((a, b) => {
        const field = query._sort;
        if (a[field] < b[field]) return -1 * order;
        if (a[field] > b[field]) return 1 * order;
        return 0;
      });
    }

    // تحديد عدد النتائج (زي json-server: ?_limit=20)
    if (query._limit) {
      items = items.slice(0, Number(query._limit));
    }

    res.json(items);
  });
});

collections.forEach((collection) => {
  app.get(`/${collection}/:id`, (req, res) => {
    const db = readDB();
    const item = (db[collection] || []).find((x) => String(x.id) === req.params.id);
    if (!item) return res.status(404).json({ message: 'Not Found' });
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

app.get('/', (req, res) => res.send('Sanaye3i Backend is Running 🚀'));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
