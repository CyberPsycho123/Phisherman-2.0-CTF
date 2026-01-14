import express from 'express'
import cors from 'cors'
import mongoose from 'mongoose'
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import dotenv from "dotenv";
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import { Solved } from './models/Solved.js'
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express()
const PORT = process.env.PORT || 3000
const secretKey = process.env.JWT_SECRET;
const DB_URL = process.env.ATLAS_URL;

let USE_MEMORY_DB = false;

// ==================== REGISTERED USERS (from .env) ====================
// ==================== REGISTERED USERS (from .env) ====================
const REGISTERED_USERS = JSON.parse(process.env.REGISTERED_USERS || '{}');
console.log("DEBUG_USERS:", JSON.stringify(REGISTERED_USERS, null, 2));

// In-memory user storage
let memoryUsers = [];

// ==================== CHALLENGES (from .env) ====================
const CHALLENGES = [
  { id: 0, flag: "Hello_CTF_Player{1m_a_bAs64_exp3rt}", points: 100 },
  { id: 1, flag: "CTF{sql_1nj3ct10n_m4st3r_2024}", points: 500 },
  { id: 2, flag: "CTF{r3v3rs3_mast3r}", points: 300 },
  { id: 3, flag: "CTF{network_forensics_pro}", points: 450 }
];

const LEVEL2_CHALLENGE = {
  id: 0,
  title: "SQL Injection - Juice Shop",
  basePoints: parseInt(process.env.LEVEL2_BASE_POINTS) || 100,
  flag: process.env.LEVEL2_FLAG || ""
};

const LEVEL3_FLAG = "PHISH{R3v_Eng_W1n}";
const LEVEL3_POINTS = 200;

// ==================== RATE LIMITING ====================
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100, // Increased for testing
  message: { success: false, message: "Too many login attempts, please try again later" }
});

const flagLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 10,
  message: { success: false, message: "Too many flag submissions, slow down!" }
});

const generalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 1000 // Increased significantly to handle polling
});

// ==================== JWT MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ success: false, message: "Authentication required" });
  }
  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: "Invalid or expired token" });
    }
    req.userEmail = user.email;
    next();
  });
};

// ==================== DATABASE HELPERS ====================
const findUser = async (email) => {
  if (USE_MEMORY_DB) {
    return memoryUsers.find(u => u.email === email.toLowerCase()) || null;
  }
  return await Solved.findOne({ email: email.toLowerCase() });
};

const findAllUsers = async () => {
  if (USE_MEMORY_DB) {
    return memoryUsers;
  }
  return await Solved.find({});
};

const updateUser = async (email, updates) => {
  if (USE_MEMORY_DB) {
    const userIndex = memoryUsers.findIndex(u => u.email === email.toLowerCase());
    if (userIndex !== -1) {
      memoryUsers[userIndex] = { ...memoryUsers[userIndex], ...updates };
      return true;
    }
    return false;
  }
  await Solved.updateOne({ email: email.toLowerCase() }, { $set: updates });
  return true;
};

// ==================== DATABASE CONNECTION ====================
const connectDB = async () => {
  if (!DB_URL) {
    console.warn("⚠️  ATLAS_URL is undefined - Using in-memory database");
    USE_MEMORY_DB = true;
    return;
  }

  try {
    await mongoose.connect(DB_URL);
    console.log("✅ Connected to MongoDB");
    await seedUsers();
  } catch (error) {
    console.warn("⚠️  MongoDB connection failed - Using in-memory database");
    USE_MEMORY_DB = true;
  }
};

const seedUsers = async () => {
  try {
    const users = Object.entries(REGISTERED_USERS);
    for (const [email, user] of users) {
      const existingUser = await Solved.findOne({ email: email.toLowerCase() });
      if (!existingUser) {
        const hashedPassword = await bcrypt.hash(user.password, 10);
        const newUser = new Solved({
          email: email.toLowerCase(),
          name: user.name,
          password: hashedPassword,
          isAdmin: email.includes('admin') // Auto-detect admin from email for initial seed or name
        });
        if (user.name.toLowerCase().includes('admin')) {
          newUser.isAdmin = true;
        }
        await newUser.save();
        console.log(`User seeded: ${email}`);
      } else if (!existingUser.password) {
        // Update existing user to have password if missing (migration)
        const hashedPassword = await bcrypt.hash(user.password, 10);
        existingUser.password = hashedPassword;
        if (user.name.toLowerCase().includes('admin')) {
          existingUser.isAdmin = true;
        }
        await existingUser.save();
        console.log(`User migrated: ${email}`);
      }
    }
    console.log("✅ Users seeded/migrated successfully");
  } catch (error) {
    console.error("Error seeding users:", error);
  }
};

connectDB();

// ==================== MIDDLEWARE ====================
app.use(cors({
  origin: function (origin, callback) {
    const allowed = ["http://localhost:5173", "http://localhost:5174"];
    // Add production URL from env
    if (process.env.FRONTEND_URL) {
      allowed.push(process.env.FRONTEND_URL);
    }
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowed.indexOf(origin) === -1) {
      // In production, we might want to block. For CTF simplicity, maybe allow all?
      // Sticking to specific origins is safer.
      return callback(new Error('The CORS policy for this site does not allow access from the specified Origin.'), false);
    }
    return callback(null, true);
  },
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
// app.use(generalLimiter);

// ==================== ROUTES ====================

// Download Level 3 (Moved to top for priority)
app.get('/download/level3', (req, res) => {
  console.log("Download request received for Level 3");
  const file = path.join(__dirname, 'challenges', 'secure_validator.py');
  res.download(file, 'secure_validator.py', (err) => {
    if (err) console.error("Download error:", err);
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// Generic Challenge Download
app.get('/download/:filename', (req, res) => {
  const filename = req.params.filename;
  // Sanitize
  const safeName = path.basename(filename);
  const filePath = path.join(__dirname, 'challenges', safeName);

  console.log(`Serving file: ${safeName}`);

  res.download(filePath, safeName, (err) => {
    if (err) {
      console.error(`Error serving ${safeName}:`, err.message);
      if (!res.headersSent) res.status(404).json({ error: "File not found" });
    }
  });
});


app.get("/profile", (req, res) => {
  console.log(req.cookies);          // all cookies
  console.log(req.cookies.token);    // specific cookie

  res.send("Cookie read successfully");
});


// Get user progress
app.get('/debug-reset', async (req, res) => {
  const email = "nivednarayananm2@gmail.com";
  const hashedPassword = await bcrypt.hash("password123", 10);
  await updateUser(email, { password: hashedPassword });
  res.json({ success: true, message: "Password reset to password123" });
});

app.post('/solved', authenticateToken, async (req, res) => {
  const user = await findUser(req.userEmail);
  if (!user) {
    return res.status(404).json({ success: false, message: "User not found" });
  }

  // Admin gets all levels unlocked
  const isAdmin = user.isAdmin === true;

  const solvedArray = [];
  const levelUnlocks = [];

  for (let i = 0; i < 7; i++) {
    const isSolved = isAdmin || user[`flag${i + 1}`] === "SOLVED";
    if (isSolved) {
      solvedArray.push(i);
    }
    levelUnlocks.push(isSolved);
  }

  res.json({
    success: true,
    already_solved: solvedArray,
    solved: {
      name: user.name,
      email: user.email,
      score: user.score || 0,
      solves: user.solves || solvedArray.length
    },
    level: levelUnlocks,
    // Return revealed hints for Level 2 (id=5 in flagX notation implies index 4?)
    // Actually level 2 is index 4 (flag5) based on previous code.
    // Let's just return the dedicated array.
    level2Hints: user.level2Hints || []
  });
});

// Reveal Hint for Level 2
app.post('/reveal-hint', authenticateToken, async (req, res) => {
  const { hintId } = req.body;
  if (![2, 3].includes(hintId)) {
    return res.status(400).json({ success: false, message: "Invalid hint ID" });
  }

  const user = await findUser(req.userEmail);
  if (!user) {
    return res.status(404).json({ success: false, message: "User not found" });
  }

  // Check if already revealed
  if (user.level2Hints && user.level2Hints.includes(hintId)) {
    return res.json({ success: true, message: "Hint already revealed", revealed: true });
  }

  // Add hintId to array
  await updateUser(req.userEmail, {
    level2Hints: [...(user.level2Hints || []), hintId]
  });

  res.json({ success: true, revealed: true });
});

// Submit flag for Level 1
app.post('/solve', authenticateToken, flagLimiter, async (req, res) => {
  const { id, flag } = req.body;
  const challengeId = parseInt(id);

  if (isNaN(challengeId) || challengeId < 0 || challengeId >= CHALLENGES.length) {
    return res.status(400).json({ success: false, message: "Invalid challenge" });
  }

  const challenge = CHALLENGES[challengeId];
  if (flag !== challenge.flag) {
    return res.status(400).json({ success: false, message: "Incorrect flag" });
  }

  const user = await findUser(req.userEmail);
  if (!user) {
    return res.status(404).json({ success: false, message: "User not found" });
  }

  if (user[`flag${challengeId + 1}`] === "SOLVED") {
    return res.status(400).json({ success: false, message: "Already solved" });
  }

  const currentScore = parseInt(user.score) || 0;
  const currentSolves = parseInt(user.solves) || 0;
  const now = new Date();

  await updateUser(req.userEmail, {
    score: currentScore + challenge.points,
    solves: currentSolves + 1,
    lastSolveTime: `${now.getHours()}:${now.getMinutes()}:${now.getSeconds()}`,
    [`flag${challengeId + 1}`]: "SOLVED"
  });

  res.json({ success: true, message: "Correct!", points: challenge.points });
});

// Submit flag for Level 2
app.post('/solve-level2', authenticateToken, flagLimiter, async (req, res) => {
  const { flag, hintPenalty } = req.body;

  if (flag !== LEVEL2_CHALLENGE.flag) {
    return res.status(400).json({ success: false, message: "Incorrect flag" });
  }

  const user = await findUser(req.userEmail);
  if (!user) {
    return res.status(404).json({ success: false, message: "User not found" });
  }

  if (user.flag5 === "SOLVED") {
    return res.status(400).json({ success: false, message: "Already solved" });
  }

  const userHints = user.level2Hints || [];
  let calculatedPenalty = 0;
  if (userHints.includes(2)) calculatedPenalty += 5;
  if (userHints.includes(3)) calculatedPenalty += 10;

  const pointsEarned = Math.max(0, LEVEL2_CHALLENGE.basePoints - calculatedPenalty);
  const currentScore = parseInt(user.score) || 0;
  const currentSolves = parseInt(user.solves) || 0;
  const now = new Date();

  await updateUser(req.userEmail, {
    score: currentScore + pointsEarned,
    solves: currentSolves + 1,
    lastSolveTime: `${now.getHours()}:${now.getMinutes()}:${now.getSeconds()}`,
    flag5: "SOLVED"
  });

  res.json({ success: true, message: "Correct!", points: pointsEarned });
});

// Submit Level 3
app.post('/solve-level3', authenticateToken, async (req, res) => {
  const { flag } = req.body;

  if (flag !== LEVEL3_FLAG) {
    return res.status(400).json({ success: false, message: "Incorrect flag" });
  }

  const user = await findUser(req.userEmail);
  if (!user) return res.status(404).json({ success: false, message: "User not found" });

  if (user.flag6 === "SOLVED") {
    return res.status(400).json({ success: false, message: "Already solved" });
  }

  const currentScore = parseInt(user.score) || 0;
  const currentSolves = parseInt(user.solves) || 0;
  const now = new Date();

  await updateUser(req.userEmail, {
    score: currentScore + LEVEL3_POINTS,
    solves: currentSolves + 1,
    lastSolveTime: `${now.getHours()}:${now.getMinutes()}:${now.getSeconds()}`,
    flag6: "SOLVED"
  });

  res.json({ success: true, message: "Correct!", points: LEVEL3_POINTS });
});

// Submit Level 4
const LEVEL4_FLAG = "CTF{view_source_is_still_op}";
const LEVEL4_POINTS = 500;

app.post('/solve-level4', authenticateToken, async (req, res) => {
  const { flag } = req.body;
  console.log(`[DEBUG] Level 4 Submission: Received flag '${flag}' from user '${req.userEmail}'`);

  if (flag !== LEVEL4_FLAG) {
    console.log(`[DEBUG] Level 4 Failed: Expected '${LEVEL4_FLAG}', got '${flag}'`);
    return res.status(400).json({ success: false, message: "Incorrect flag" });
  }

  const user = await findUser(req.userEmail);
  if (!user) {
    console.log(`[DEBUG] Level 4 Failed: User not found '${req.userEmail}'`);
    return res.status(404).json({ success: false, message: "User not found" });
  }

  if (user.flag7 === "SOLVED") {
    console.log(`[DEBUG] Level 4 Failed: Already solved by '${req.userEmail}'`);
    return res.status(400).json({ success: false, message: "Already solved" });
  }

  const currentScore = parseInt(user.score) || 0;
  await updateUser(req.userEmail, {
    score: currentScore + LEVEL4_POINTS,
    solves: (parseInt(user.solves) || 0) + 1,
    lastSolveTime: new Date().toLocaleTimeString(),
    flag7: "SOLVED"
  });

  console.log(`[DEBUG] Level 4 Success: User '${req.userEmail}' solved Level 4`);
  res.json({ success: true, message: "Correct!", points: LEVEL4_POINTS });
});



// Check Level 2 status
app.post('/check-level2', authenticateToken, async (req, res) => {
  const user = await findUser(req.userEmail);
  if (!user) {
    return res.status(404).json({ success: false, message: "User not found" });
  }
  res.json({ success: true, solved: user.flag5 === "SOLVED" });
});

// Scoreboard
app.post('/scoreboard', async (req, res) => {
  const users = await findAllUsers();

  // Filter out admin users from scoreboard
  const filteredUsers = users.filter(u => !u.email.includes('admin'));

  const toSeconds = (time) => {
    if (!time) return Infinity;
    const [h, m, s = 0] = String(time).split(":").map(Number);
    return h * 3600 + m * 60 + s;
  };

  const sorted = [...filteredUsers].sort((a, b) => {
    const scoreA = parseInt(a.score) || 0;
    const scoreB = parseInt(b.score) || 0;
    if (scoreB !== scoreA) return scoreB - scoreA;
    return toSeconds(a.lastSolveTime) - toSeconds(b.lastSolveTime);
  });

  const collections = sorted.map((user, i) => ({
    rank: i + 1,
    name: user.name,
    score: user.score || 0,
    solves: user.solves || 0
  }));

  res.json({
    success: true,
    collections,
    players: users.length,
    total_solves: collections.reduce((sum, u) => sum + (parseInt(u.solves) || 0), 0)
  });
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: "Email and password required" });
  }

  // Check DB First
  let user = await findUser(email);
  if (user) {
    if (user.email == email) {
      if (user.password == password) {
        const token = jwt.sign({ email: user.email }, secretKey, { expiresIn: '7d' });
        res.cookie("token", token, { maxAge: 1000 * 60 * 60 * 24 * 7, httpOnly: true, secure: true, sameSite: "none" });
        res.cookie("email", user.email, { maxAge: 1000 * 60 * 60 * 24 * 7, httpOnly: true, secure: true, sameSite: "none" });
        return res.status(200).json({ success: true, message: "Authenticated" });
      }
      else {
        return res.status(401).json({ success: false, message: "password is not correct" });
      }

    }
  }
  else {
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }

  res.json({ success: true, name: user.name, isAdmin: user.isAdmin });
});

// Logout
app.post('/logout', (req, res) => {
  res.clearCookie("token", {
    secure: true,
    sameSite: "none"
  });
  res.clearCookie("email", {
    secure: true,
    sameSite: "none"
  });

  res.json({ success: true, message: "Logged out" });
});

// Check login status
app.post('/checklogin', authenticateToken, async (req, res) => {
  const user = await findUser(req.userEmail);
  if (user) {
    res.json({ success: true, username: user.name });
  } else {
    res.status(404).json({ success: false, message: "User not found" });
  }
});

// Time-based availability check
app.post('/unavailable', (req, res) => {
  const now = new Date();
  const totalMinutes = now.getHours() * 60 + now.getMinutes();
  res.json({ success: totalMinutes >= 735 });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`[STARTUP] DB Mode: ${USE_MEMORY_DB ? "IN-MEMORY (Resets on restart)" : "MONGODB (Persistent)"}`);
  console.log(`[STARTUP] Level 1 Ch 4 Flag (ID 3): ${CHALLENGES[3].flag}`);
  console.log(`[STARTUP] Level 4 Flag: ${LEVEL4_FLAG}`);
});
