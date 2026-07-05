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

// ⚠️ غيّر ده لدومين الفرونت إند بتاعك الحقيقي وقت الديبلوي
const ALLOWED_ORIGIN = process.env.FRONTEND_URL || 'http://localhost:4200';
app.use(cors({ origin: ALLOWED_ORIGIN }));
app.use(express.json());

// ⚠️ لازم تضيفه كـ environment variable في Railway (Variables tab)، متسيبوش هنا في production
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

// ⚠️ سيكريت مؤقت لعمل أول حساب أدمن بس — لو مش موجود كـ env var، endpoint البوتستراب بيتعطل تلقائيًا (بيرجع 404)
const BOOTSTRAP_SECRET = process.env.ADMIN_BOOTSTRAP_SECRET;

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

// مجلد رفع الملفات — جوه نفس الـ Volume عشان يفضل موجود بعد أي redeploy
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
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB لكل ملف
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('نوع الملف مش مسموح به. استخدم صورة أو PDF.'));
    }
    cb(null, true);
  },
});

// السماح بالوصول للملفات المرفوعة (عرض الصور)
app.use('/uploads', express.static(UPLOADS_DIR));

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
// ⚠️ كل حساب جديد بيتعمل بـ status: 'pending' ومبيرجعش token — لازم موافقة أدمن الأول
app.post('/auth/register', registerLimiter, async (req, res) => {
  try {
    const { email, password, fullName, role, nationalId, workerData } = req.body;

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

    const db = readDB();

    const emailExists = db.users.find((u) => u.email === email);
    if (emailExists) {
      return res.status(409).json({ message: 'البريد الإلكتروني ده مسجل بالفعل.' });
    }

    // فحص الرقم القومي بغض النظر عن الدور — بيمنع نفس الشخص يسجل كـ client وpro مع بعض
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
      status: 'pending',
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

    // ⚠️ مفيش session token هنا خالص — الحساب pending لحد ما الأدمن يوافق عليه.
    // بس لو pro، بنرجّع docsUploadToken قصير العمر (15 دقيقة) غرضه الوحيد إنه
    // يسمح للفرونت إند يرفع مستندات التحقق فورًا بعد التسجيل. ده مش session
    // token — الفرونت إند ميحفظهوش في localStorage/sessionStorage ولا
    // بيستخدمه كـ "تسجيل دخول"، بيستخدمه مرة واحدة بس في نفس الطلب ده ويرميه
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

    // ⚠️ ملاحظة أمان: فصلنا رسالة "الإيميل مش موجود" عن "الباسورد غلط" بناءً على
    // طلب صريح لتحسين تجربة الاستخدام. ده بيسهّل على أي حد يعرف الإيميلات
    // المسجلة فعليًا (user enumeration)، بس مقبول لمشروع تخرج مش بيتعامل مع
    // بيانات حساسة. لو حبيت ترجعها موحدة تاني، رجّع الرسالتين لنفس النص.
    if (!user) {
      return res.status(401).json({ message: 'الحساب ده مش موجود، سجل حساب جديد الأول.' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: 'كلمة المرور غلط.' });
    }

    // ⚠️ فحص الـ status بعد نجاح الباسورد — لاحظ إننا بنرفض حالات معينة بس (مش
    // بنشترط status === 'active')، عشان أي حساب قديم اتعمل قبل إضافة الحقل ده
    // (status يبقى undefined) يفضل يشتغل عادي من غير ما نحتاج migration script
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

// ── Middleware للتحقق من JWT ──
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

// ── Middleware إضافي فوق verifyToken — بيتأكد إن الدور admin بالظبط ──
function verifyAdmin(req, res, next) {
  verifyToken(req, res, () => {
    if (req.userRole !== 'admin') {
      return res.status(403).json({ message: 'غير مصرح لك بالوصول لده.' });
    }
    next();
  });
}

// ── Endpoint رفع مستندات التحقق (محمي بـ JWT) ────────────
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

      // تأكيد إن اللي بيرفع هو نفسه صاحب البروفايل
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

// معالج أخطاء multer (نوع ملف غلط / حجم كبير) — لازم يتحط بعد الـ routes
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err.message?.includes('نوع الملف')) {
    return res.status(400).json({ message: err.message || 'خطأ في رفع الملف.' });
  }
  next(err);
});

// ============ ADMIN ENDPOINTS ============
// كلهم محميين بـ verifyAdmin — لازم Authorization: Bearer <token> بتوكن أدمن

// إحصائيات عامة للداشبورد
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

// كل المستخدمين + فلاتر (role, status, search بالاسم/الإيميل/الرقم القومي)
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

// تفاصيل مستخدم واحد + بروفايل الصنايعي (لو pro) — عشان الأدمن يشوف صور التحقق
app.get('/admin/users/:id', verifyAdmin, (req, res) => {
  const db = readDB();
  const user = (db.users || []).find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ message: 'مش لاقي المستخدم ده.' });

  const worker =
    user.role === 'pro' ? (db.workers || []).find((w) => w.userId === user.id) : null;

  res.json({ user: sanitizeUser(user), worker });
});

// تغيير حالة مستخدم — accept / reject / block / unblock
app.patch('/admin/users/:id/status', verifyAdmin, (req, res) => {
  const { status } = req.body;
  const validStatuses = ['pending', 'active', 'rejected', 'blocked'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ message: 'الحالة المطلوبة مش صحيحة.' });
  }

  const db = readDB();
  const index = (db.users || []).findIndex((u) => u.id === req.params.id);
  if (index === -1) return res.status(404).json({ message: 'مش لاقي المستخدم ده.' });

  db.users[index].status = status;
  writeDB(db);
  res.json(sanitizeUser(db.users[index]));
});

// ⚠️ Endpoint مؤقت لعمل أول حساب أدمن بس — استخدمه مرة واحدة وبعدين شيل
// ADMIN_BOOTSTRAP_SECRET من الـ environment variables في Railway عشان يتعطل تلقائيًا.
// لو الـ secret مش موجود أو غلط، بنرجع 404 (مش 401/403) عشان محدش يعرف أصلاً إن الـ endpoint موجود.
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
