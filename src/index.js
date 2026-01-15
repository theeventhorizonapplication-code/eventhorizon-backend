const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'eventhorizon-secret-key-change-in-production';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Middleware
app.use(cors());
app.use(express.json());

// API Keys
const RAWG_API_KEY = process.env.RAWG_API_KEY;

// ============ DATABASE SETUP ============
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const DB_PATH = path.join(dataDir, 'eventhorizon.db');
const db = new Database(DB_PATH);

console.log('✅ Connected to SQLite database');

// Initialize database tables
function initializeDatabase() {
  // Users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password TEXT,
      google_id TEXT UNIQUE,
      avatar TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // User games table
  db.exec(`
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
  db.exec(`
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

  // Auto-discovered events cache table - added event_key for deduplication
  db.exec(`
    CREATE TABLE IF NOT EXISTS auto_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      game_id INTEGER NOT NULL,
      steam_gid TEXT,
      event_key TEXT,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      date TEXT NOT NULL,
      description TEXT,
      source TEXT,
      source_url TEXT,
      game_name TEXT,
      discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(game_id, event_key)
    )
  `);

  // Steam ID cache table
  db.exec(`
    CREATE TABLE IF NOT EXISTS steam_cache (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      game_name TEXT UNIQUE NOT NULL,
      steam_app_id INTEGER,
      steam_name TEXT,
      cached_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  console.log('✅ Database tables initialized');
}

initializeDatabase();

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
    const existingUser = db.prepare('SELECT * FROM users WHERE email = ? OR username = ?').get(email.toLowerCase(), username.toLowerCase());

    if (existingUser) {
      if (existingUser.email === email.toLowerCase()) {
        return res.status(400).json({ error: 'Email already registered' });
      }
      return res.status(400).json({ error: 'Username already taken' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const result = db.prepare('INSERT INTO users (email, username, password) VALUES (?, ?, ?)').run(email.toLowerCase(), username.toLowerCase(), hashedPassword);

    // Generate token
    const token = jwt.sign(
      { id: result.lastInsertRowid, email: email.toLowerCase(), username: username.toLowerCase() },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'Account created successfully',
      token,
      user: {
        id: result.lastInsertRowid,
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
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

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
app.get('/api/auth/me', authenticateToken, (req, res) => {
  try {
    const user = db.prepare('SELECT id, email, username, avatar, created_at FROM users WHERE id = ?').get(req.user.id);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user });
  } catch (error) {
    console.error('Get user error:', error.message);
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// Google Sign-In
app.post('/api/auth/google', async (req, res) => {
  const { credential } = req.body;

  if (!credential) {
    return res.status(400).json({ error: 'Google credential required' });
  }

  try {
    // Verify the Google token
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const googleId = payload['sub'];
    const email = payload['email'];
    const name = payload['name'];
    const picture = payload['picture'];

    // Check if user exists by Google ID or email
    let user = db.prepare('SELECT * FROM users WHERE google_id = ? OR email = ?').get(googleId, email.toLowerCase());

    if (user) {
      // Update Google ID if user exists by email but not Google ID
      if (!user.google_id) {
        db.prepare('UPDATE users SET google_id = ?, avatar = ? WHERE id = ?').run(googleId, picture, user.id);
      }
    } else {
      // Create new user
      // Generate username from email or name
      let baseUsername = email.split('@')[0].toLowerCase().replace(/[^a-z0-9_]/g, '');
      if (baseUsername.length < 3) baseUsername = name.toLowerCase().replace(/[^a-z0-9_]/g, '').substring(0, 10);
      
      let username = baseUsername;
      let counter = 1;
      
      // Ensure unique username
      while (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) {
        username = `${baseUsername}${counter}`;
        counter++;
      }

      const result = db.prepare(
        'INSERT INTO users (email, username, google_id, avatar) VALUES (?, ?, ?, ?)'
      ).run(email.toLowerCase(), username, googleId, picture);

      user = {
        id: result.lastInsertRowid,
        email: email.toLowerCase(),
        username: username,
        avatar: picture
      };
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Google sign-in successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        avatar: user.avatar || picture
      }
    });
  } catch (error) {
    console.error('Google auth error:', error.message);
    res.status(401).json({ error: 'Invalid Google credential' });
  }
});

// ============ USER GAMES ROUTES ============

// Get user's tracked games
app.get('/api/user/games', authenticateToken, (req, res) => {
  try {
    const games = db.prepare('SELECT * FROM user_games WHERE user_id = ? ORDER BY tracked_at DESC').all(req.user.id);

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
app.post('/api/user/games', authenticateToken, (req, res) => {
  const { game } = req.body;

  if (!game || !game.id || !game.name) {
    return res.status(400).json({ error: 'Game data is required' });
  }

  try {
    const existing = db.prepare('SELECT id FROM user_games WHERE user_id = ? AND game_id = ?').get(req.user.id, game.id);

    if (existing) {
      return res.status(400).json({ error: 'Game already tracked' });
    }

    db.prepare('INSERT INTO user_games (user_id, game_id, game_name, game_image, game_data) VALUES (?, ?, ?, ?, ?)').run(
      req.user.id, game.id, game.name, game.background_image, JSON.stringify(game)
    );

    // Trigger auto-discovery
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
app.delete('/api/user/games/:gameId', authenticateToken, (req, res) => {
  const gameId = parseInt(req.params.gameId);

  try {
    const result = db.prepare('DELETE FROM user_games WHERE user_id = ? AND game_id = ?').run(req.user.id, gameId);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Game not found' });
    }

    db.prepare('DELETE FROM user_events WHERE user_id = ? AND game_id = ?').run(req.user.id, gameId);

    res.json({ message: 'Game untracked successfully' });
  } catch (error) {
    console.error('Untrack game error:', error.message);
    res.status(500).json({ error: 'Failed to untrack game' });
  }
});

// ============ TIMELINE ROUTE ============

app.get('/api/user/timeline', authenticateToken, (req, res) => {
  try {
    const userGames = db.prepare('SELECT game_id, game_name, game_image FROM user_games WHERE user_id = ?').all(req.user.id);
    const gameIds = userGames.map(g => g.game_id);

    if (gameIds.length === 0) {
      return res.json({ events: [], games: [] });
    }

    const placeholders = gameIds.map(() => '?').join(',');
    const autoEvents = db.prepare(`SELECT * FROM auto_events WHERE game_id IN (${placeholders}) ORDER BY date DESC`).all(...gameIds);
    const customEvents = db.prepare(`SELECT *, 'custom' as source FROM user_events WHERE user_id = ? AND game_id IN (${placeholders}) ORDER BY date DESC`).all(req.user.id, ...gameIds);

    const gameMap = {};
    userGames.forEach(g => {
      gameMap[g.game_id] = { name: g.game_name, image: g.game_image };
    });

    const allEvents = [...autoEvents, ...customEvents].map(e => ({
      ...e,
      gameName: e.game_name || gameMap[e.game_id]?.name,
      gameImage: gameMap[e.game_id]?.image
    }));

    allEvents.sort((a, b) => new Date(b.date) - new Date(a.date));

    res.json({ events: allEvents.slice(0, 50), games: userGames });
  } catch (error) {
    console.error('Get timeline error:', error.message);
    res.status(500).json({ error: 'Failed to get timeline' });
  }
});

// ============ STEAM INTEGRATION ============

async function findSteamAppId(gameName) {
  try {
    const cached = db.prepare('SELECT * FROM steam_cache WHERE game_name = ?').get(gameName.toLowerCase());
    if (cached) {
      return { appId: cached.steam_app_id, name: cached.steam_name };
    }

    const searchUrl = `https://store.steampowered.com/api/storesearch/?term=${encodeURIComponent(gameName)}&l=english&cc=US`;
    const response = await axios.get(searchUrl);

    if (response.data?.items?.length > 0) {
      const steamApp = response.data.items[0];

      db.prepare('INSERT OR REPLACE INTO steam_cache (game_name, steam_app_id, steam_name) VALUES (?, ?, ?)').run(
        gameName.toLowerCase(), steamApp.id, steamApp.name
      );

      return { appId: steamApp.id, name: steamApp.name };
    }

    return null;
  } catch (error) {
    console.error('Steam search error:', error.message);
    return null;
  }
}

async function fetchSteamNews(appId, count = 50) {
  try {
    const url = `https://api.steampowered.com/ISteamNews/GetNewsForApp/v2/?appid=${appId}&count=${count}&maxlength=1000&format=json`;
    const response = await axios.get(url);
    return response.data?.appnews?.newsitems || [];
  } catch (error) {
    console.error('Steam news error:', error.message);
    return [];
  }
}

// ============ IMPROVED EVENT PARSING ============

// Patterns that indicate news/opinion articles (NOT actual events)
const NEWS_ARTICLE_PATTERNS = [
  /could be/i,
  /might be/i,
  /may be/i,
  /looks like/i,
  /seems like/i,
  /here's (a|what|how|why)/i,
  /everything you need to know/i,
  /what we know/i,
  /rumors?/i,
  /leak(s|ed)?/i,
  /reportedly/i,
  /allegedly/i,
  /speculation/i,
  /predict(s|ed|ion)/i,
  /expect(s|ed|ing)?/i,
  /should you/i,
  /is it worth/i,
  /best .* in/i,
  /top \d+/i,
  /guide to/i,
  /how to/i,
  /tips (for|and)/i,
  /grab .* for cheap/i,
  /first (major )?sale/i,
  /on sale/i,
  /discount/i,
  /deal(s)?/i,
  /perfect reason/i,
  /reasons to/i,
  /incredibly close/i,
  /looks great/i,
  /nerds and/i,
  /pre-.*patch/i,
];

// Official sources we trust (prioritize these)
const OFFICIAL_SOURCES = [
  'steam_community_announcements',
];

// Extract a clean event identifier for deduplication
function extractEventKey(title, type) {
  const titleLower = title.toLowerCase();
  
  // Extract version numbers: "Patch 1.16.1" -> "patch-1.16.1"
  const versionMatch = titleLower.match(/(?:patch|update|version|hotfix|v)[\s\-]*(\d+(?:\.\d+)+(?:\.\d+)?)/i);
  if (versionMatch) {
    return `patch-${versionMatch[1]}`;
  }
  
  // Extract season numbers: "Season 11" -> "season-11"
  const seasonMatch = titleLower.match(/season[\s\-]*(\d+)/i);
  if (seasonMatch) {
    return `season-${seasonMatch[1]}`;
  }
  
  // Extract chapter numbers: "Chapter 5" -> "chapter-5"
  const chapterMatch = titleLower.match(/chapter[\s\-]*(\d+)/i);
  if (chapterMatch) {
    return `chapter-${chapterMatch[1]}`;
  }
  
  // Extract expansion/DLC names
  const expansionPatterns = [
    /expansion[:\s]+([^|]+)/i,
    /dlc[:\s]+([^|]+)/i,
  ];
  for (const pattern of expansionPatterns) {
    const match = titleLower.match(pattern);
    if (match) {
      return `expansion-${match[1].trim().substring(0, 30).replace(/\s+/g, '-')}`;
    }
  }
  
  // Fallback: use first 40 chars of title, normalized
  const normalized = titleLower
    .replace(/[^a-z0-9\s]/g, '')
    .replace(/\s+/g, '-')
    .substring(0, 40);
  return `${type}-${normalized}`;
}

// Clean up event title (remove game name prefix, standardize format)
function cleanEventTitle(title, gameName) {
  let cleaned = title;
  
  // Remove common prefixes like "ELDEN RING - " or "Diablo IV | "
  const prefixPatterns = [
    new RegExp(`^${gameName}[\\s\\-|:]+`, 'i'),
    /^[A-Z\s]+[\-|:]\s*/,  // All caps prefix
  ];
  
  for (const pattern of prefixPatterns) {
    cleaned = cleaned.replace(pattern, '');
  }
  
  return cleaned.trim();
}

// Determine if this is an official announcement vs news article
function isOfficialAnnouncement(item) {
  // Check if from official Steam announcements
  if (item.feedname && OFFICIAL_SOURCES.some(s => item.feedname.includes(s))) {
    return true;
  }
  
  // Check if author looks official (not a news site)
  const newsAuthors = ['editor@', 'steam', 'pcgamesn', 'rockpapershotgun', 'vg247', 'kotaku', 'ign', 'gamespot'];
  const authorLower = (item.author || '').toLowerCase();
  if (newsAuthors.some(n => authorLower.includes(n))) {
    return false;
  }
  
  return true;
}

// Check if title looks like a news article (not an actual event)
function isNewsArticle(title) {
  return NEWS_ARTICLE_PATTERNS.some(pattern => pattern.test(title));
}

// Improved event parsing with deduplication
function parseSteamNews(newsItems, gameId, gameName) {
  const eventMap = new Map(); // key -> event (for deduplication)
  
  for (const item of newsItems) {
    const title = item.title;
    const titleLower = title.toLowerCase();
    
    // Skip news articles and opinion pieces
    if (isNewsArticle(title)) {
      continue;
    }
    
    // Determine event type
    let eventType = null;
    
    // Patch detection
    if (titleLower.includes('patch notes') || 
        titleLower.includes('hotfix') || 
        titleLower.includes('bug fix') ||
        titleLower.match(/patch[\s\-]*v?\d+/i) ||
        titleLower.match(/version[\s\-]*\d+\.\d+/i) ||
        titleLower.match(/update[\s\-]*\d+\.\d+/i) ||
        (titleLower.includes('patch') && titleLower.match(/\d+\.\d+/))) {
      eventType = 'patch';
    }
    // Season detection  
    else if (titleLower.match(/season[\s\-]*\d+/i) && 
             (titleLower.includes('now live') || 
              titleLower.includes('available') || 
              titleLower.includes('launch') ||
              titleLower.includes('begins') ||
              titleLower.includes('start'))) {
      eventType = 'season';
    }
    // Expansion/DLC detection
    else if ((titleLower.includes('expansion') || titleLower.includes('dlc')) &&
             (titleLower.includes('now') || 
              titleLower.includes('available') || 
              titleLower.includes('launch') ||
              titleLower.includes('release'))) {
      eventType = 'expansion';
    }
    
    if (!eventType) continue;
    
    // Generate deduplication key
    const eventKey = extractEventKey(title, eventType);
    
    // Check if we already have this event
    const existing = eventMap.get(eventKey);
    
    if (existing) {
      // Prefer official announcements over news articles
      const existingIsOfficial = isOfficialAnnouncement(existing._raw);
      const newIsOfficial = isOfficialAnnouncement(item);
      
      if (newIsOfficial && !existingIsOfficial) {
        // Replace with official version
      } else {
        // Keep existing, skip this one
        continue;
      }
    }
    
    const eventDate = new Date(item.date * 1000).toISOString().split('T')[0];
    const cleanedTitle = cleanEventTitle(title, gameName);
    
    eventMap.set(eventKey, {
      steam_gid: item.gid,
      event_key: eventKey,
      game_id: gameId,
      game_name: gameName,
      type: eventType,
      title: cleanedTitle,
      description: item.contents?.substring(0, 500) || '',
      date: eventDate,
      source: 'steam',
      source_url: item.url,
      _raw: item // Keep for comparison, won't be stored
    });
  }
  
  // Convert map to array and remove _raw
  return Array.from(eventMap.values()).map(({ _raw, ...event }) => event);
}

async function discoverEventsForGame(gameId, gameName) {
  console.log(`🔍 Discovering events for: ${gameName}`);

  const steamInfo = await findSteamAppId(gameName);
  if (!steamInfo) {
    console.log(`  ⚠️ Not found on Steam`);
    return [];
  }

  console.log(`  🎮 Steam App ID: ${steamInfo.appId}`);
  const news = await fetchSteamNews(steamInfo.appId);
  console.log(`  📰 Raw news items: ${news.length}`);

  const events = parseSteamNews(news, gameId, gameName);
  console.log(`  🎯 Deduplicated events: ${events.length}`);

  // Clear old events for this game and insert new ones
  db.prepare('DELETE FROM auto_events WHERE game_id = ?').run(gameId);

  const insertStmt = db.prepare(`
    INSERT OR REPLACE INTO auto_events (game_id, steam_gid, event_key, type, title, date, description, source, source_url, game_name)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const event of events) {
    try {
      insertStmt.run(
        event.game_id, 
        event.steam_gid, 
        event.event_key,
        event.type, 
        event.title, 
        event.date, 
        event.description, 
        event.source, 
        event.source_url, 
        event.game_name
      );
    } catch (err) {
      console.error(`  ❌ Insert error: ${err.message}`);
    }
  }

  return events;
}

// ============ SMART SEARCH HELPER ============

function smartSortGames(games, searchQuery) {
  const query = searchQuery.toLowerCase().trim();
  const queryWords = query.split(/\s+/);
  
  // Filter out junk (DLCs, soundtracks, editions unless specifically searched)
  const junkPatterns = [
    /soundtrack/i,
    /ost\b/i,
    /\bmusic\b/i,
    /artbook/i,
    /art book/i,
    /wallpaper/i,
    /demo$/i,
    /\bbeta\b/i,
    /test server/i,
    /pts\b/i,
  ];
  
  // Only filter DLC/edition if not searching for them
  if (!query.includes('dlc') && !query.includes('edition') && !query.includes('pack')) {
    junkPatterns.push(/\bdlc\b/i);
    junkPatterns.push(/season pass/i);
    junkPatterns.push(/expansion pass/i);
  }
  
  const filteredGames = games.filter(game => {
    const name = game.name.toLowerCase();
    
    // Filter out junk
    if (junkPatterns.some(pattern => pattern.test(name))) {
      return false;
    }
    
    // Filter out very old games (before 2010) unless exact match
    if (game.released) {
      const year = parseInt(game.released.split('-')[0]);
      if (year < 2010 && name !== query) {
        return false;
      }
    }
    
    return true;
  });
  
  // Score each game
  const scoredGames = filteredGames.map(game => {
    const name = game.name.toLowerCase();
    let score = 0;
    
    // Exact match (huge boost)
    if (name === query) {
      score += 10000;
    }
    
    // Starts with query (big boost)
    if (name.startsWith(query)) {
      score += 5000;
    }
    
    // Contains all query words
    const containsAllWords = queryWords.every(word => name.includes(word));
    if (containsAllWords) {
      score += 2000;
    }
    
    // Shorter names are usually the main game, not "Game: Subtitle: DLC: Edition"
    const nameLengthPenalty = Math.min(name.length * 2, 200);
    score -= nameLengthPenalty;
    
    // Recency boost - newer games ranked higher
    if (game.released) {
      const year = parseInt(game.released.split('-')[0]);
      if (year >= 2024) score += 2000;
      else if (year >= 2023) score += 1500;
      else if (year >= 2020) score += 1000;
      else if (year >= 2015) score += 500;
      else if (year >= 2010) score += 200;
    }
    
    // Rating boost (0-5 scale from RAWG)
    if (game.rating) {
      score += game.rating * 100;
    }
    
    // Ratings count boost (popularity)
    if (game.ratings_count) {
      score += Math.min(Math.log10(game.ratings_count + 1) * 200, 800);
    }
    
    // Metacritic boost
    if (game.metacritic) {
      score += game.metacritic * 5;
    }
    
    // If it has a number that matches a number in the query, boost it
    const queryNumbers = query.match(/\d+/g) || [];
    const nameNumbers = name.match(/\d+/g) || [];
    if (queryNumbers.length > 0 && nameNumbers.some(n => queryNumbers.includes(n))) {
      score += 1000;
    }
    
    // Penalize games with lots of colons/subtitles (usually special editions)
    const colonCount = (name.match(/:/g) || []).length;
    score -= colonCount * 100;
    
    return { ...game, _score: score };
  });
  
  // Sort by score descending
  scoredGames.sort((a, b) => b._score - a._score);
  
  // Remove score from output
  return scoredGames.map(({ _score, ...game }) => game);
}

// ============ PUBLIC ROUTES ============

app.get('/', (req, res) => {
  res.json({
    message: 'EventHorizon API v7.0',
    features: ['User Auth', 'Game Tracking', 'Smart Event Discovery', 'Deduplication', 'Custom Events', 'Smart Search']
  });
});

// Smart game search
app.get('/api/games', async (req, res) => {
  const search = req.query.search;
  if (!search) {
    return res.status(400).json({ error: 'Search query required' });
  }

  try {
    // Fetch more results from RAWG to have better selection for smart sorting
    const url = `https://api.rawg.io/api/games?key=${RAWG_API_KEY}&search=${encodeURIComponent(search)}&page_size=40&search_precise=true`;
    const response = await axios.get(url);

    const games = response.data.results.map(game => ({
      id: game.id,
      name: game.name,
      released: game.released,
      rating: game.rating,
      ratings_count: game.ratings_count,
      metacritic: game.metacritic,
      background_image: game.background_image,
      genres: game.genres?.map(g => g.name) || [],
      platforms: game.platforms?.map(p => p.platform.name) || []
    }));

    // Apply smart sorting
    const sortedGames = smartSortGames(games, search);
    
    // Return top 15
    res.json(sortedGames.slice(0, 15));
  } catch (error) {
    console.error('Game search error:', error.message);
    res.status(500).json({ error: 'Search failed' });
  }
});

// Browse games by genre or tag
app.get('/api/games/browse', async (req, res) => {
  const { genres, tags } = req.query;
  
  if (!genres && !tags) {
    return res.status(400).json({ error: 'Genre or tag required' });
  }

  try {
    let url = `https://api.rawg.io/api/games?key=${RAWG_API_KEY}&ordering=-rating&page_size=24`;
    
    if (genres) {
      url += `&genres=${encodeURIComponent(genres)}`;
    }
    if (tags) {
      url += `&tags=${encodeURIComponent(tags)}`;
    }
    
    // Only get recent-ish games (2015+)
    url += '&dates=2015-01-01,2030-12-31';
    
    const response = await axios.get(url);

    const games = response.data.results.map(game => ({
      id: game.id,
      name: game.name,
      released: game.released,
      rating: game.rating,
      ratings_count: game.ratings_count,
      metacritic: game.metacritic,
      background_image: game.background_image,
      genres: game.genres?.map(g => g.name) || [],
      platforms: game.platforms?.map(p => p.platform.name) || []
    }));

    res.json(games);
  } catch (error) {
    console.error('Genre browse error:', error.message);
    res.status(500).json({ error: 'Browse failed' });
  }
});

app.post('/api/discover/all', authenticateToken, async (req, res) => {
  try {
    const games = db.prepare('SELECT game_id, game_name FROM user_games WHERE user_id = ?').all(req.user.id);

    let totalEvents = 0;
    for (const game of games) {
      const events = await discoverEventsForGame(game.game_id, game.game_name);
      totalEvents += events.length;
      await new Promise(r => setTimeout(r, 500));
    }

    res.json({ message: 'Discovery complete', gamesProcessed: games.length, eventsFound: totalEvents });
  } catch (error) {
    console.error('Discover all error:', error.message);
    res.status(500).json({ error: 'Discovery failed' });
  }
});

// ============ START SERVER ============
app.listen(PORT, () => {
  console.log(`\n🚀 EventHorizon API v7.0`);
  console.log(`📡 http://localhost:${PORT}`);
  console.log(`🔐 Auth: JWT`);
  console.log(`💾 Database: SQLite (better-sqlite3)`);
  console.log(`🔍 Smart Search: Enabled`);
  console.log(`🎯 Event Deduplication: Enabled`);
});
