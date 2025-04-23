import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { initDB, getDB } from './db.js';
import rateLimit from 'express-rate-limit';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(express.json());

// Rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: 'Too many attempts, please try again later'
});

// Initialize database
initDB();

// Middleware to authenticate JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Signup Route
app.post('/signup', authLimiter, async (req, res) => {
  const { username, email, password } = req.body;
  
  // Validation
  if (!email || !username || !password) {
    return res.status(400).json({ error: 'Email, username, and password are required.' });
  }

  const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
  if (!usernameRegex.test(username)) {
    return res.status(400).json({ 
      error: 'Username must be 3-20 characters (letters, numbers, underscores)' 
    });
  }

  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({ 
      error: 'Password must be at least 8 characters with uppercase, lowercase, and number'
    });
  }

  try {
    const db = getDB();
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert into user_profiles
    const result = await db.execute({
      sql: 'INSERT INTO user_profiles (username, email, password_hash) VALUES (?, ?, ?)',
      args: [username, email, hashedPassword],
    });

    // Get the inserted user_id
    const user_id = result.lastInsertRowid;

    // Initialize user_achievements with 0 XP
    await db.execute({
      sql: 'INSERT INTO user_achievements (user_id, xp_points) VALUES (?, ?)',
      args: [user_id, 0],
    });

    return res.status(201).json({ 
      message: 'User registered successfully.',
      user: { user_id, username, email }
    });
  } catch (err) {
    if (err.message && err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Email already exists.' });
    }
    console.error('Signup error:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// Login Route
app.post('/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT * FROM user_profiles WHERE email = ?',
      args: [email],
    });
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Update last_login timestamp
    await db.execute({
      sql: 'UPDATE user_profiles SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?',
      args: [user.user_id],
    });

    const token = jwt.sign(
      { 
        id: user.user_id, 
        email: user.email, 
        username: user.username 
      }, 
      JWT_SECRET, 
      { expiresIn: '1h' }
    );
    
    return res.json({ 
      message: 'Login successful.', 
      token,
      user: {
        id: user.user_id,
        username: user.username,
        email: user.email
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// Progress Tracking Endpoints
app.get('/progress', authenticateJWT, async (req, res) => {
  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT * FROM user_progress WHERE user_id = ?',
      args: [req.user.id],
    });
    
    return res.json(result.rows);
  } catch (err) {
    console.error('Progress fetch error:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

app.post('/progress', authenticateJWT, async (req, res) => {
  const { language, level, module_id, lesson_id, is_completed, current_question_index } = req.body;
  
  if (!language || level === undefined || module_id === undefined || lesson_id === undefined) {
    return res.status(400).json({ error: 'Required fields: language, level, module_id, lesson_id' });
  }

  try {
    const db = getDB();
    
    // Upsert progress
    await db.execute({
      sql: `
        INSERT INTO user_progress 
          (user_id, language, level, module_id, lesson_id, is_completed, current_question_index)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, language, level, module_id, lesson_id) 
        DO UPDATE SET
          is_completed = excluded.is_completed,
          current_question_index = excluded.current_question_index,
          last_accessed = CURRENT_TIMESTAMP
      `,
      args: [
        req.user.id, 
        language, 
        level, 
        module_id, 
        lesson_id, 
        is_completed || false, 
        current_question_index || 0
      ],
    });

    return res.json({ message: 'Progress updated successfully.' });
  } catch (err) {
    console.error('Progress update error:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// Achievements Endpoints
app.get('/achievements', authenticateJWT, async (req, res) => {
  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT xp_points FROM user_achievements WHERE user_id = ?',
      args: [req.user.id],
    });
    
    return res.json(result.rows[0] || { xp_points: 0 });
  } catch (err) {
    console.error('Achievements fetch error:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

app.post('/achievements/add-xp', authenticateJWT, async (req, res) => {
  const { xp } = req.body;
  
  if (!xp || isNaN(xp)) {
    return res.status(400).json({ error: 'Valid xp amount required' });
  }

  try {
    const db = getDB();
    await db.execute({
      sql: 'UPDATE user_achievements SET xp_points = xp_points + ? WHERE user_id = ?',
      args: [xp, req.user.id],
    });

    return res.json({ message: 'XP added successfully.' });
  } catch (err) {
    console.error('XP update error:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// User Profile Endpoint
app.get('/profile', authenticateJWT, async (req, res) => {
  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT user_id, username, email, created_at, last_login FROM user_profiles WHERE user_id = ?',
      args: [req.user.id],
    });
    
    return res.json(result.rows[0]);
  } catch (err) {
    console.error('Profile fetch error:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});