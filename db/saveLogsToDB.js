//=============================================//
// Module Imports
//=============================================//
import fs from "fs";
import path from "path";
import { db } from "./db.js";

//=============================================//
// Log File for DB Errors
//=============================================//
const DB_LOG = path.join(process.cwd(), "logs", "db.log");

// Helper to append to db.log
function logDBError(message) {
  const logEntry = `[${new Date().toISOString()}] ${message}\n`;
  fs.appendFile(DB_LOG, logEntry, (err) => {
    if (err) console.error("Failed to write to db.log:", err);
  });
}

//=============================================//
// Save Logs to DB Function
//=============================================//
export const saveLogsToDB = async (file) => {
  try {
    const content = fs.readFileSync(file, "utf8");
    const filename = path.basename(file);
    const timestamp = new Date().toISOString();

    db.prepare(
      "INSERT INTO logs (filename, timestamp, content) VALUES (?, ?, ?)"
    ).run(filename, timestamp, content);
  } catch (err) {
    const errorMsg = `Error reading log file ${file}: ${err.message}`;
    logDBError(errorMsg);
  }
};
