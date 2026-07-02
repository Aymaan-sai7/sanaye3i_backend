const express = require('express');
const fs = require('fs');
const cors = require('cors');
const app = express();
app.use(cors());
app.use(express.json());

// لو فيه Volume متوصل، استخدم مساره. لو لأ (تطوير محلي)، استخدم الملف اللي جنب الكود
const DB_FILE = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? `${process.env.RAILWAY_VOLUME_MOUNT_PATH}/db.json`
  : './db.json';

// أول تشغيل: لو الملف مش موجود (Volume فاضي)، اعمله بـ collections فاضية
if (!fs.existsSync(DB_FILE)) {
  const initialData = {
    users: [],
    workers: [],
    bookings: [],
    reviews: [],
    messages: [],
    conversations: []
  };
  fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
  console.log('db.json created with empty collections at', DB_FILE);
}

function readDB() {
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

const collections = ['users', 'workers', 'bookings', 'reviews', 'messages', 'conversations'];

// GET All + فلترة بـ query params (زي json-server)
collections.forEach((collection) => {
  app.get(`/${collection}`, (req, res) => {
    const db = readDB();
    let items = db[collection] || [];
    const query = req.query;

    Object.keys(query).forEach((key) => {
      items = items.filter((item) => String(item[key]) === String(query[key]));
    });

    res.json(items);
  });
});

// GET By Id
collections.forEach((collection) => {
  app.get(`/${collection}/:id`, (req, res) => {
    const db = readDB();
    const item = (db[collection] || []).find((x) => String(x.id) === req.params.id);
    if (!item) return res.status(404).json({ message: 'Not Found' });
    res.json(item);
  });
});

// POST
collections.forEach((collection) => {
  app.post(`/${collection}`, (req, res) => {
    const db = readDB();
    if (!db[collection]) db[collection] = [];
    const newItem = {
      id: Date.now().toString() + Math.random().toString(36).slice(2, 6),
      ...req.body,
    };
    db[collection].push(newItem);
    writeDB(db);
    res.status(201).json(newItem);
  });
});

// PUT + PATCH (نفس اللوجيك — تحديث جزئي)
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

// DELETE
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
