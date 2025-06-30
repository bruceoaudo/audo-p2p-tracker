//=============================================//
// Module Imports
//=============================================//
import Database from "better-sqlite3";
import path from "path";
import fs from "fs";

//===============================//
// Ensure db folder exists
//===============================//
const dbPath = path.join(process.cwd(), "db", "logs.db");
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(dbPath);

db.prepare(
  `CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT,
  timestamp TEXT,
  content TEXT
)`
).run();

export { db };
