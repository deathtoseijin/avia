// storage.js — simple JSON persistence so config survives bot restarts
const fs   = require('fs');
const path = require('path');
const FILE = path.join(__dirname, 'data.json');

function load() {
  try {
    if (fs.existsSync(FILE)) return JSON.parse(fs.readFileSync(FILE, 'utf8'));
  } catch {}
  return {};
}

function save(data) {
  try { fs.writeFileSync(FILE, JSON.stringify(data, null, 2)); } catch (e) { console.error('Storage save error:', e.message); }
}

const db = load();

module.exports = {
  get: (key, def = null) => (key in db ? db[key] : def),
  set: (key, val) => { db[key] = val; save(db); },
  del: (key) => { delete db[key]; save(db); },
  all: () => db,
};
