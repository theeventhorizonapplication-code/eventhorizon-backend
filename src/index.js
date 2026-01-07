const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'eventhorizon-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());

// API Keys
const RAWG_API_KEY = process.env.RAWG_API_KEY;
const STEAM_API_KEY = process.env.STEAM_API_KEY;

// ============ DATABASE SETUP ============
const DB_PATH = path.join(__dirname, 'data', 'eventhorizon.db');

// Ensure data directory exists
const fs = require('fs');
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('❌ Database connection error:', err.message);
  } else {
    console.log('✅ Connected to SQLite database');
    initializeDatabase();
  }
});

// Promisify database methods
const dbRun = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
};

const dbGet = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

const dbAll = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

// Initialize database tables
async function initializeDatabase() {
  try {
    // Users table
    await dbRun(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // User games table
    await dbRun(`
      CREATE TABLE IF NOT EXISTS user_games (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        game_id INTEGER NOT NULL,
        game_name TEXT NOT NULL,
        game_image TEXT,
        game_data TEXT,
        tracked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id, game_id)
      )
    `);

    // User custom events table
    await dbRun(`
      CREATE TABLE IF NOT EXISTS user_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        game_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        date TEXT NOT NULL,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Auto-discovered events cache table
    await dbRun(`
      CREATE TABLE IF NOT EXISTS auto_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game_id INTEGER NOT NULL,
        steam_gid TEXT UNIQUE,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        date TEXT NOT NULL,
        description TEXT,
        source TEXT,
        source_url TEXT,
        game_name TEXT,
        discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Steam ID cache table
    await dbRun(`
      CREATE TABLE IF NOT EXISTS steam_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game_name TEXT UNIQUE NOT NULL,
        steam_app_id INTEGER,
        steam_name TEXT,
        cached_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('✅ Database tables initialized');
  } catch (error) {
    console.error('❌ Database initialization error:', error.message);
  }
}

// ============ AUTH MIDDLEWARE ============
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Optional auth - doesn't fail if no token, just sets req.user if valid
const optionalAuth = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (!err) {
        req.user = user;
      }
    });
  }
  next();
};

// ============ AUTH ROUTES ============

// Register
app.post('/api/auth/register', async (req, res) => {
  const { email, username, password } = req.body;

  if (!email || !username || !password) {
    return res.status(400).json({ error: 'Email, username, and password are required' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  try {
    // Check if email or username already exists
    const existingUser = await dbGet(
      'SELECT * FROM users WHERE email = ? OR username = ?',
      [email.toLowerCase(), username.toLowerCase()]
    );

    if (existingUser) {
      if (existingUser.email === email.toLowerCase()) {
        return res.status(400).json({ error: 'Email already registered' });
      }
      return res.status(400).json({ error: 'Username already taken' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const result = await dbRun(
      'INSERT INTO users (email, username, password) VALUES (?, ?, ?)',
      [email.toLowerCase(), username.toLowerCase(), hashedPassword]
    );

    // Generate token
    const token = jwt.sign(
      { id: result.lastID, email: email.toLowerCase(), username: username.toLowerCase() },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'Account created successfully',
      token,
      user: {
        id: result.lastID,
        email: email.toLowerCase(),
        username: username.toLowerCase()
      }
    });
  } catch (error) {
    console.error('Register error:', error.message);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    // Find user by email
    const user = await dbGet('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate token
    const token = jwt.sign(
      { id: user.id, email: user.email, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username
      }
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Failed to login' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await dbGet('SELECT id, email, username, created_at FROM users WHERE id = ?', [req.user.id]);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user });
  } catch (error) {
    console.error('Get user error:', error.message);
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// Update profile
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  try {
    // Check if username is taken by someone else
    const existing = await dbGet(
      'SELECT id FROM users WHERE username = ? AND id != ?',
      [username.toLowerCase(), req.user.id]
    );

    if (existing) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    await dbRun('UPDATE users SET username = ? WHERE id = ?', [username.toLowerCase(), req.user.id]);

    res.json({ message: 'Profile updated', username: username.toLowerCase() });
  } catch (error) {
    console.error('Update profile error:', error.message);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Change password
app.put('/api/auth/password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password are required' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }

  try {
    const user = await dbGet('SELECT password FROM users WHERE id = ?', [req.user.id]);

    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await dbRun('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.user.id]);

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Change password error:', error.message);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// ============ USER GAMES ROUTES ============

// Get user's tracked games
app.get('/api/user/games', authenticateToken, async (req, res) => {
  try {
    const games = await dbAll(
      'SELECT * FROM user_games WHERE user_id = ? ORDER BY tracked_at DESC',
      [req.user.id]
    );

    // Parse game_data JSON
    const parsedGames = games.map(g => ({
      ...g,
      game_data: g.game_data ? JSON.parse(g.game_data) : {}
    }));

    res.json(parsedGames);
  } catch (error) {
    console.error('Get user games error:', error.message);
    res.status(500).json({ error: 'Failed to get games' });
  }
});

// Track a game
app.post('/api/user/games', authenticateToken, async (req, res) => {
  const { game } = req.body;

  if (!game || !game.id || !game.name) {
    return res.status(400).json({ error: 'Game data is required' });
  }

  try {
    // Check if already tracked
    const existing = await dbGet(
      'SELECT id FROM user_games WHERE user_id = ? AND game_id = ?',
      [req.user.id, game.id]
    );

    if (existing) {
      return res.status(400).json({ error: 'Game already tracked' });
    }

    await dbRun(
      'INSERT INTO user_games (user_id, game_id, game_name, game_image, game_data) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, game.id, game.name, game.background_image, JSON.stringify(game)]
    );

    // Trigger auto-discovery for this game
    discoverEventsForGame(game.id, game.name).catch(err => 
      console.error('Auto-discovery error:', err.message)
    );

    res.status(201).json({ message: 'Game tracked successfully', game });
  } catch (error) {
    console.error('Track game error:', error.message);
    res.status(500).json({ error: 'Failed to track game' });
  }
});

// Untrack a game
app.delete('/api/user/games/:gameId', authenticateToken, async (req, res) => {
  const gameId = parseInt(req.params.gameId);

  try {
    const result = await dbRun(
      'DELETE FROM user_games WHERE user_id = ? AND game_id = ?',
      [req.user.id, gameId]
    );

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Game not found' });
    }

    // Also delete user's custom events for this game
    await dbRun('DELETE FROM user_events WHERE user_id = ? AND game_id = ?', [req.user.id, gameId]);

    res.json({ message: 'Game untracked successfully' });
  } catch (error) {
    console.error('Untrack game error:', error.message);
    res.status(500).json({ error: 'Failed to untrack game' });
  }
});

// ============ USER EVENTS ROUTES ============

// Get user's custom events
app.get('/api/user/events', authenticateToken, async (req, res) => {
  try {
    const events = await dbAll(
      'SELECT * FROM user_events WHERE user_id = ? ORDER BY date ASC',
      [req.user.id]
    );
    res.json(events);
  } catch (error) {
    console.error('Get user events error:', error.message);
    res.status(500).json({ error: 'Failed to get events' });
  }
});

// Add custom event
app.post('/api/user/events', authenticateToken, async (req, res) => {
  const { game_id, type, title, date, description } = req.body;

  if (!game_id || !type || !title || !date) {
    return res.status(400).json({ error: 'Game ID, type, title, and date are required' });
  }

  try {
    const result = await dbRun(
      'INSERT INTO user_events (user_id, game_id, type, title, date, description) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, game_id, type, title, date, description || '']
    );

    res.status(201).json({
      message: 'Event added',
      event: { id: result.lastID, game_id, type, title, date, description }
    });
  } catch (error) {
    console.error('Add event error:', error.message);
    res.status(500).json({ error: 'Failed to add event' });
  }
});

// Delete custom event
app.delete('/api/user/events/:eventId', authenticateToken, async (req, res) => {
  const eventId = parseInt(req.params.eventId);

  try {
    const result = await dbRun(
      'DELETE FROM user_events WHERE id = ? AND user_id = ?',
      [eventId, req.user.id]
    );

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Event not found' });
    }

    res.json({ message: 'Event deleted' });
  } catch (error) {
    console.error('Delete event error:', error.message);
    res.status(500).json({ error: 'Failed to delete event' });
  }
});

// ============ TIMELINE ROUTE ============

// Get user's timeline (auto events + custom events for tracked games)
app.get('/api/user/timeline', authenticateToken, async (req, res) => {
  try {
    // Get user's tracked game IDs
    const userGames = await dbAll('SELECT game_id, game_name, game_image FROM user_games WHERE user_id = ?', [req.user.id]);
    const gameIds = userGames.map(g => g.game_id);

    if (gameIds.length === 0) {
      return res.json({ events: [], games: [] });
    }

    // Get auto-discovered events for these games
    const placeholders = gameIds.map(() => '?').join(',');
    const autoEvents = await dbAll(
      `SELECT * FROM auto_events WHERE game_id IN (${placeholders}) ORDER BY date DESC`,
      gameIds
    );

    // Get user's custom events
    const customEvents = await dbAll(
      `SELECT *, 'custom' as source FROM user_events WHERE user_id = ? AND game_id IN (${placeholders}) ORDER BY date DESC`,
      [req.user.id, ...gameIds]
    );

    // Combine and add game images
    const gameMap = {};
    userGames.forEach(g => {
      gameMap[g.game_id] = { name: g.game_name, image: g.game_image };
    });

    const allEvents = [...autoEvents, ...customEvents].map(e => ({
      ...e,
      gameName: e.game_name || gameMap[e.game_id]?.name,
      gameImage: gameMap[e.game_id]?.image
    }));

    // Sort by date
    allEvents.sort((a, b) => new Date(b.date) - new Date(a.date));

    res.json({ events: allEvents.slice(0, 50), games: userGames });
  } catch (error) {
    console.error('Get timeline error:', error.message);
    res.status(500).json({ error: 'Failed to get timeline' });
  }
});

// ============ STEAM INTEGRATION ============

// Find Steam App ID
async function findSteamAppId(gameName) {
  try {
    // Check cache first
    const cached = await dbGet('SELECT * FROM steam_cache WHERE game_name = ?', [gameName.toLowerCase()]);
    if (cached) {
      return { appId: cached.steam_app_id, name: cached.steam_name };
    }

    // Search Steam
    const searchUrl = `https://store.steampowered.com/api/storesearch/?term=${encodeURIComponent(gameName)}&l=english&cc=US`;
    const response = await axios.get(searchUrl);

    if (response.data?.items?.length > 0) {
      const steamApp = response.data.items[0];

      // Cache result
      await dbRun(
        'INSERT OR REPLACE INTO steam_cache (game_name, steam_app_id, steam_name) VALUES (?, ?, ?)',
        [gameName.toLowerCase(), steamApp.id, steamApp.name]
      );

      return { appId: steamApp.id, name: steamApp.name };
    }

    return null;
  } catch (error) {
    console.error('Steam search error:', error.message);
    return null;
  }
}

// Fetch Steam news
async function fetchSteamNews(appId, count = 30) {
  try {
    const url = `https://api.steampowered.com/ISteamNews/GetNewsForApp/v2/?appid=${appId}&count=${count}&maxlength=500&format=json`;
    const response = await axios.get(url);
    return response.data?.appnews?.newsitems || [];
  } catch (error) {
    console.error('Steam news error:', error.message);
    return [];
  }
}

// Parse Steam news to events (only patches, seasons, expansions)
function parseSteamNews(newsItems, gameId, gameName) {
  const events = [];

  for (const item of newsItems) {
    const titleLower = item.title.toLowerCase();
    let eventType = null;

    // Detect event type
    if (titleLower.includes('patch') || titleLower.includes('hotfix') || titleLower.includes('bug fix') ||
        titleLower.includes('update notes') || titleLower.match(/v?\d+\.\d+/)) {
      eventType = 'patch';
    } else if (titleLower.includes('season') || titleLower.includes('chapter') || titleLower.match(/season\s*\d+/i)) {
      eventType = 'season';
    } else if (titleLower.includes('expansion') || titleLower.includes('dlc') || titleLower.includes('major update')) {
      eventType = 'expansion';
    }

    if (!eventType) continue;

    const eventDate = new Date(item.date * 1000).toISOString().split('T')[0];

    events.push({
      steam_gid: item.gid,
      game_id: gameId,
      game_name: gameName,
      type: eventType,
      title: item.title,
      description: item.contents?.substring(0, 300) || '',
      date: eventDate,
      source: 'steam',
      source_url: item.url
    });
  }

  return events;
}

// Discover events for a game
async function discoverEventsForGame(gameId, gameName) {
  console.log(`🔍 Discovering events for: ${gameName}`);

  const steamInfo = await findSteamAppId(gameName);
  if (!steamInfo) {
    console.log(`  ⚠️ Not found on Steam`);
    return [];
  }

  console.log(`  🎮 Steam App ID: ${steamInfo.appId}`);
  const news = await fetchSteamNews(steamInfo.appId);
  console.log(`  📰 Raw news: ${news.length}`);

  const events = parseSteamNews(news, gameId, gameName);
  console.log(`  🎯 Filtered events: ${events.length}`);

  // Save to database
  for (const event of events) {
    try {
      await dbRun(
        `INSERT OR IGNORE INTO auto_events (game_id, steam_gid, type, title, date, description, source, source_url, game_name)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [event.game_id, event.steam_gid, event.type, event.title, event.date, event.description, event.source, event.source_url, event.game_name]
      );
    } catch (err) {
      // Ignore duplicate errors
    }
  }

  return events;
}

// ============ PUBLIC ROUTES ============

// Root
app.get('/', (req, res) => {
  res.json({
    message: 'EventHorizon API v5.0',
    features: ['User Auth', 'Game Tracking', 'Auto-Discovery', 'Custom Events']
  });
});

// Search games (public)
app.get('/api/games', async (req, res) => {
  const search = req.query.search;
  if (!search) {
    return res.status(400).json({ error: 'Search query required' });
  }

  try {
    const url = `https://api.rawg.io/api/games?key=${RAWG_API_KEY}&search=${encodeURIComponent(search)}&page_size=20`;
    const response = await axios.get(url);

    const games = response.data.results.map(game => ({
      id: game.id,
      name: game.name,
      released: game.released,
      rating: game.rating,
      background_image: game.background_image,
      genres: game.genres?.map(g => g.name) || [],
      platforms: game.platforms?.map(p => p.platform.name) || []
    }));

    res.json(games);
  } catch (error) {
    console.error('Game search error:', error.message);
    res.status(500).json({ error: 'Search failed' });
  }
});

// Get auto events for a game (public)
app.get('/api/events/:gameId', async (req, res) => {
  const gameId = parseInt(req.params.gameId);

  try {
    const events = await dbAll(
      'SELECT * FROM auto_events WHERE game_id = ? ORDER BY date DESC LIMIT 50',
      [gameId]
    );
    res.json(events);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get events' });
  }
});

// Trigger discovery (authenticated)
app.post('/api/discover/:gameId', authenticateToken, async (req, res) => {
  const gameId = parseInt(req.params.gameId);
  const { gameName } = req.body;

  if (!gameName) {
    return res.status(400).json({ error: 'Game name required' });
  }

  try {
    const events = await discoverEventsForGame(gameId, gameName);
    res.json({ message: 'Discovery complete', eventsFound: events.length });
  } catch (error) {
    res.status(500).json({ error: 'Discovery failed' });
  }
});

// Discover all user's games
app.post('/api/discover/all', authenticateToken, async (req, res) => {
  try {
    const games = await dbAll('SELECT game_id, game_name FROM user_games WHERE user_id = ?', [req.user.id]);

    let totalEvents = 0;
    for (const game of games) {
      const events = await discoverEventsForGame(game.game_id, game.game_name);
      totalEvents += events.length;
      await new Promise(r => setTimeout(r, 500)); // Rate limit
    }

    res.json({ message: 'Discovery complete', gamesProcessed: games.length, eventsFound: totalEvents });
  } catch (error) {
    console.error('Discover all error:', error.message);
    res.status(500).json({ error: 'Discovery failed' });
  }
});

// ============ START SERVER ============
app.listen(PORT, () => {
  console.log(`\n🚀 EventHorizon API v5.0`);
  console.log(`📡 http://localhost:${PORT}`);
  console.log(`🔐 Auth: JWT`);
  console.log(`💾 Database: SQLite`);
  console.log(`\n📋 Auth Endpoints:`);
  console.log(`   POST /api/auth/register`);
  console.log(`   POST /api/auth/login`);
  console.log(`   GET  /api/auth/me`);
  console.log(`\n📋 User Endpoints:`);
  console.log(`   GET/POST/DELETE /api/user/games`);
  console.log(`   GET/POST/DELETE /api/user/events`);
  console.log(`   GET  /api/user/timeline\n`);
});
