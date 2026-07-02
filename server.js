const express = require('express');
const fs = require('fs');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const DB_FILE = './db.json';

// helper
const readDB = () => JSON.parse(fs.readFileSync(DB_FILE));
const writeDB = (data) => fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));

// GET all workers
app.get('/workers', (req, res) => {
  const db = readDB();
  res.json(db.workers || []);
});

// GET users
app.get('/users', (req, res) => {
  const db = readDB();
  res.json(db.users || []);
});

// POST booking
app.post('/bookings', (req, res) => {
  const db = readDB();
  db.bookings.push(req.body);
  writeDB(db);
  res.json({ success: true });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log('Server running on port', port);
});
