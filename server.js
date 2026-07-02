const express = require('express');
const fs = require('fs');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

const DB_FILE = './db.json';

function readDB() {
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// جميع الـ Collections الموجودة في db.json
const collections = [
  'users',
  'workers',
  'bookings',
  'reviews',
  'messages',
  'conversations'
];

// GET All
collections.forEach((collection) => {
  app.get(`/${collection}`, (req, res) => {
    const db = readDB();
    res.json(db[collection] || []);
  });
});

// GET By Id
collections.forEach((collection) => {
  app.get(`/${collection}/:id`, (req, res) => {
    const db = readDB();
    const item = (db[collection] || []).find(
      (x) => String(x.id) === req.params.id
    );

    if (!item) {
      return res.status(404).json({ message: 'Not Found' });
    }

    res.json(item);
  });
});

// POST
collections.forEach((collection) => {
  app.post(`/${collection}`, (req, res) => {
    const db = readDB();

    if (!db[collection]) {
      db[collection] = [];
    }

    const newItem = {
      id: Date.now(),
      ...req.body
    };

    db[collection].push(newItem);

    writeDB(db);

    res.status(201).json(newItem);
  });
});

// PUT
collections.forEach((collection) => {
  app.put(`/${collection}/:id`, (req, res) => {
    const db = readDB();

    const index = db[collection].findIndex(
      (x) => String(x.id) === req.params.id
    );

    if (index === -1) {
      return res.status(404).json({ message: 'Not Found' });
    }

    db[collection][index] = {
      ...db[collection][index],
      ...req.body
    };

    writeDB(db);

    res.json(db[collection][index]);
  });
});

// DELETE
collections.forEach((collection) => {
  app.delete(`/${collection}/:id`, (req, res) => {
    const db = readDB();

    db[collection] = db[collection].filter(
      (x) => String(x.id) !== req.params.id
    );

    writeDB(db);

    res.json({ success: true });
  });
});

app.get('/', (req, res) => {
  res.send('Sanaye3i Backend is Running 🚀');
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
