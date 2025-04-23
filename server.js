import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { initDB, getDB } from './db.js';
import cors from 'cors';

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000; // Railway typically uses 5000
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health check endpoint
app.get('/', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    message: 'JLearn API is running',
    timestamp: new Date().toISOString()
  });
});

// Initialize database
await initDB();

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        console.error('JWT verification error:', err);
        return res.status(403).json({ error: 'Invalid or expired token' });
      }
      
      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ error: 'Authorization header missing' });
  }
};

// Signup Route
app.post('/signup', async (req, res) => {
  console.log('Signup request received:', req.body);
  
  const { username, email, password } = req.body;
  
  // Validation
  if (!email) return res.status(400).json({ error: 'Email is required', field: 'email' });
  if (!username) return res.status(400).json({ error: 'Username is required', field: 'username' });
  if (!password) return res.status(400).json({ error: 'Password is required', field: 'password' });

  const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
  if (!usernameRegex.test(username)) {
    return res.status(400).json({ 
      error: 'Username must be 3-20 characters (letters, numbers, underscores)',
      field: 'username'
    });
  }

  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({ 
      error: 'Password must be at least 8 characters with uppercase, lowercase, and number',
      field: 'password'
    });
  }

  try {
    const db = getDB();
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await db.execute({
      sql: 'INSERT INTO user_profiles (username, email, password_hash) VALUES (?, ?, ?)',
      args: [username, email, hashedPassword],
    });

    const user_id = result.lastInsertRowid;

    await db.execute({
      sql: 'INSERT INTO user_achievements (user_id, xp_points) VALUES (?, ?)',
      args: [user_id, 0],
    });

    return res.status(201).json({ 
      success: true,
      message: 'User registered successfully',
      user: { user_id, username, email }
    });
  } catch (err) {
    console.error('Signup error:', err);
    if (err.message && err.message.includes('UNIQUE')) {
      return res.status(409).json({ 
        error: 'Email already exists',
        field: 'email'
      });
    }
    return res.status(500).json({ 
      error: 'Registration failed',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Login Route
app.post('/login', async (req, res) => {
  console.log('Login attempt:', req.body.email);
  
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ 
      error: 'Email and password are required',
      fields: {
        email: !email ? 'Missing' : 'Provided',
        password: !password ? 'Missing' : 'Provided'
      }
    });
  }

  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT * FROM user_profiles WHERE email = ?',
      args: [email],
    });
    
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

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
      { expiresIn: '24h' } // Extended token expiration
    );
    
    return res.json({ 
      success: true,
      message: 'Login successful', 
      token,
      user: {
        id: user.user_id,
        username: user.username,
        email: user.email
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ 
      error: 'Login failed',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
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
    
    res.json({
      success: true,
      progress: result.rows
    });
  } catch (err) {
    console.error('Progress fetch error:', err);
    res.status(500).json({ 
      error: 'Failed to fetch progress',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

app.post('/progress', authenticateJWT, async (req, res) => {
  const { language, level, module_id, lesson_id, is_completed, current_question_index } = req.body;
  
  if (!language || level === undefined || module_id === undefined || lesson_id === undefined) {
    return res.status(400).json({ 
      error: 'Missing required fields',
      required: ['language', 'level', 'module_id', 'lesson_id']
    });
  }

  try {
    const db = getDB();
    
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

    res.json({ 
      success: true,
      message: 'Progress updated successfully' 
    });
  } catch (err) {
    console.error('Progress update error:', err);
    res.status(500).json({ 
      error: 'Failed to update progress',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
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
    
    res.json({
      success: true,
      xp_points: result.rows[0]?.xp_points || 0
    });
  } catch (err) {
    console.error('Achievements fetch error:', err);
    res.status(500).json({ 
      error: 'Failed to fetch achievements',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

app.post('/achievements/add-xp', authenticateJWT, async (req, res) => {
  const { xp } = req.body;
  
  if (!xp || isNaN(xp)) {
    return res.status(400).json({ 
      error: 'Valid XP amount required',
      received: xp
    });
  }

  try {
    const db = getDB();
    await db.execute({
      sql: 'UPDATE user_achievements SET xp_points = xp_points + ? WHERE user_id = ?',
      args: [parseInt(xp), req.user.id],
    });

    res.json({ 
      success: true,
      message: 'XP added successfully' 
    });
  } catch (err) {
    console.error('XP update error:', err);
    res.status(500).json({ 
      error: 'Failed to add XP',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
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
    
    if (!result.rows[0]) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      success: true,
      profile: result.rows[0]
    });
  } catch (err) {
    console.error('Profile fetch error:', err);
    res.status(500).json({ 
      error: 'Failed to fetch profile',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
