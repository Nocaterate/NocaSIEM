// Imported first by server.js. ES module imports are evaluated before the
// importing file's own code runs, so .env has to be loaded in its own module
// for values like DATA_FILE to be visible when db.js is first evaluated.
import path from "node:path";
import dotenv from "dotenv";

dotenv.config({ path: path.join(import.meta.dirname, "..", ".env") });
