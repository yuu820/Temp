const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { randomUUID } = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'data.sqlite');

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database(DB_PATH);

const generationQueue = [];
const reviewQueue = [];
let generationHits = [];
let reviewHits = [];

const config = {
  longPerSecond: 1,
  reviewPerSecond: 1,
  thresholdPerMinute: 5,
};

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE,
      password TEXT,
      displayName TEXT,
      accessRole TEXT,
      dailyLimit INTEGER,
      priority TEXT,
      userType TEXT,
      proAccess INTEGER,
      dailyUsed INTEGER DEFAULT 0,
      lastReset TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS long_tasks (
      id TEXT PRIMARY KEY,
      userId TEXT,
      wordCount INTEGER,
      difficulty TEXT,
      questionTypes TEXT,
      theme TEXT,
      generated TEXT,
      questions TEXT,
      answers TEXT,
      correction TEXT,
      status TEXT,
      createdAt TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS essay_tasks (
      id TEXT PRIMARY KEY,
      userId TEXT,
      theme TEXT,
      content TEXT,
      correction TEXT,
      status TEXT,
      createdAt TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS config (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `);

  db.get('SELECT value FROM config WHERE key = ?', ['limits'], (err, row) => {
    if (err) return;
    if (!row) {
      db.run(
        'INSERT OR REPLACE INTO config(key, value) VALUES(?, ?)',
        ['limits', JSON.stringify(config)]
      );
    } else {
      Object.assign(config, JSON.parse(row.value));
    }
  });

  db.get('SELECT id FROM users WHERE username = ?', ['admin'], (err, row) => {
    if (err) return;
    const today = currentJstDate();
    if (!row) {
      const adminId = randomUUID();
      db.run(
        `INSERT INTO users(id, username, password, displayName, accessRole, dailyLimit, priority, userType, proAccess, dailyUsed, lastReset)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          adminId,
          'admin',
          'admin123',
          'Administrator',
          'unlimited',
          null,
          'priority',
          'admin',
          1,
          0,
          today,
        ]
      );
    }
  });
});

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function sanitize(value) {
  if (typeof value !== 'string') return value;
  return value.replace(/[<>]/g, '');
}

function currentJstDate() {
  return new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Tokyo' });
}

async function ensureDailyReset(userId) {
  const row = await get('SELECT dailyUsed, lastReset FROM users WHERE id = ?', [userId]);
  if (!row) return;
  const today = currentJstDate();
  if (row.lastReset !== today) {
    await run('UPDATE users SET dailyUsed = 0, lastReset = ? WHERE id = ?', [today, userId]);
  }
}

async function incrementDailyUsage(userId) {
  await ensureDailyReset(userId);
  await run('UPDATE users SET dailyUsed = dailyUsed + 1 WHERE id = ?', [userId]);
}

async function canUse(user) {
  if (!user) return false;
  await ensureDailyReset(user.id);
  if (user.accessRole !== 'limited') return true;
  const updated = await get('SELECT dailyUsed, dailyLimit FROM users WHERE id = ?', [user.id]);
  if (!updated.dailyLimit) return true;
  return updated.dailyUsed < updated.dailyLimit;
}

function trackHits(list) {
  const now = Date.now();
  const cutoff = now - 60 * 1000;
  list.push(now);
  list = list.filter((ts) => ts >= cutoff);
  return list;
}

function enqueue(queue, job, priority) {
  if (priority === 'priority') {
    queue.unshift(job);
  } else {
    queue.push(job);
  }
}

function generateLongContent(wordCount, theme, difficulty) {
  const safeTheme = theme || 'general interest';
  const base = `This is a ${difficulty} English passage about ${safeTheme}. It is designed for learners to practice comprehension and vocabulary.`;
  const words = [];
  while (words.length < wordCount) {
    words.push(
      'The content highlights perspectives, examples, and contrasts to make the reading engaging and educational.'
    );
  }
  return [base, words.join(' ')].join(' ');
}

function buildQuestions(types, passageId) {
  const questions = [];
  const mapping = {
    grammarChoice: 'Grammar 4-choice',
    vocabChoice: 'Vocabulary 4-choice',
    contentChoice: 'Content comprehension 4-choice',
    ordering: 'Sentence ordering',
    grammarWrite: 'Grammar fill-in',
    vocabWrite: 'Vocabulary fill-in',
    translation: 'Japanese translation',
  };
  Object.entries(types || {}).forEach(([key, count]) => {
    const safeCount = Number(count) || 0;
    for (let i = 0; i < safeCount; i += 1) {
      questions.push({
        id: `${passageId}-${key}-${i + 1}`,
        type: mapping[key] || key,
        prompt: `Q${i + 1}: ${mapping[key] || key} based on the passage.`,
      });
    }
  });
  return questions;
}

function buildCorrection(answerList) {
  const translation = '日本語訳: 内容は概ね適切です。主要なポイントが含まれています。';
  const keyPoints = '要点: 主張・理由・まとめが明確で、論理の流れが自然です。';
  const grammar = '重要文法: 時制の整合性と関係詞の使い分けを確認しましょう。';
  return {
    translation,
    keyPoints,
    grammar,
    scoring: answerList.length ? 'All answers reviewed.' : 'No answers provided.',
  };
}

async function processGeneration() {
  let capacity = config.longPerSecond;
  while (capacity > 0 && generationQueue.length) {
    const job = generationQueue.shift();
    const passage = generateLongContent(job.wordCount, job.theme, job.difficulty);
    const questions = buildQuestions(job.questionTypes, job.id);
    await run(
      'UPDATE long_tasks SET generated = ?, questions = ?, status = ? WHERE id = ?',
      [sanitize(passage), JSON.stringify(questions), 'awaiting_answers', job.id]
    );
    capacity -= 1;
  }
}

async function processReview() {
  let capacity = config.reviewPerSecond;
  while (capacity > 0 && reviewQueue.length) {
    const job = reviewQueue.shift();
    const correction = buildCorrection(job.answers || []);
    await run(
      'UPDATE long_tasks SET correction = ?, status = ? WHERE id = ?',
      [JSON.stringify(correction), 'review_complete', job.id]
    );
    capacity -= 1;
  }
}

setInterval(() => {
  processGeneration();
  processReview();
}, 1000);

function stripPassword(user) {
  if (!user) return null;
  const { password, ...rest } = user;
  return { ...rest, proAccess: !!rest.proAccess };
}

async function loadUser(userId) {
  return get('SELECT * FROM users WHERE id = ?', [userId]);
}

function requireManager(req, res, next) {
  const type = req.headers['x-user-type'];
  if (!type || (type !== 'admin' && type !== 'helper')) {
    return res.status(403).json({ message: 'Manager access required' });
  }
  req.requesterType = type;
  next();
}

function requireAdmin(req, res, next) {
  const type = req.headers['x-user-type'];
  if (type !== 'admin') {
    return res.status(403).json({ message: 'Admin only' });
  }
  next();
}

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = await get('SELECT * FROM users WHERE username = ?', [sanitize(username)]);
  if (!user || user.password !== password) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  await ensureDailyReset(user.id);
  res.json(stripPassword(user));
});

app.get('/api/users', requireManager, async (req, res) => {
  const users = await all('SELECT * FROM users');
  res.json(users.map(stripPassword));
});

app.post('/api/users', requireAdmin, async (req, res) => {
  const payload = req.body || {};
  const id = randomUUID();
  const today = currentJstDate();
  try {
    await run(
      `INSERT INTO users(id, username, password, displayName, accessRole, dailyLimit, priority, userType, proAccess, dailyUsed, lastReset)
       VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
      [
        id,
        sanitize(payload.username),
        sanitize(payload.password),
        sanitize(payload.displayName || payload.username),
        payload.accessRole || 'limited',
        payload.dailyLimit || 10,
        payload.priority || 'normal',
        payload.userType || 'user',
        payload.proAccess ? 1 : 0,
        0,
        today,
      ]
    );
    const user = await get('SELECT * FROM users WHERE id = ?', [id]);
    res.json(stripPassword(user));
  } catch (err) {
    res.status(400).json({ message: 'Failed to create user', detail: err.message });
  }
});

app.put('/api/users/:id', requireManager, async (req, res) => {
  if (req.requesterType !== 'admin' && req.requesterType !== 'helper') {
    return res.status(403).json({ message: 'Insufficient role' });
  }
  const updates = req.body || {};
  const user = await get('SELECT * FROM users WHERE id = ?', [req.params.id]);
  if (!user) return res.status(404).json({ message: 'User not found' });
  const next = {
    displayName: sanitize(updates.displayName || user.displayName),
    accessRole: updates.accessRole || user.accessRole,
    dailyLimit: updates.dailyLimit ?? user.dailyLimit,
    priority: updates.priority || user.priority,
    userType: req.requesterType === 'helper' ? user.userType : updates.userType || user.userType,
    proAccess: updates.proAccess ? 1 : 0,
  };
  await run(
    `UPDATE users
     SET displayName = ?, accessRole = ?, dailyLimit = ?, priority = ?, userType = ?, proAccess = ?
     WHERE id = ?`,
    [
      next.displayName,
      next.accessRole,
      next.dailyLimit,
      next.priority,
      next.userType,
      next.proAccess,
      req.params.id,
    ]
  );
  const refreshed = await get('SELECT * FROM users WHERE id = ?', [req.params.id]);
  res.json(stripPassword(refreshed));
});

app.get('/api/config', requireManager, (req, res) => {
  res.json(config);
});

app.post('/api/config', requireAdmin, async (req, res) => {
  const incoming = req.body || {};
  config.longPerSecond = Number(incoming.longPerSecond) || config.longPerSecond;
  config.reviewPerSecond = Number(incoming.reviewPerSecond) || config.reviewPerSecond;
  config.thresholdPerMinute = Number(incoming.thresholdPerMinute) || config.thresholdPerMinute;
  await run('INSERT OR REPLACE INTO config(key, value) VALUES(?, ?)', [
    'limits',
    JSON.stringify(config),
  ]);
  res.json(config);
});

app.get('/api/queue', (req, res) => {
  const now = Date.now();
  const filterRecent = (list) => list.filter((ts) => ts >= now - 60 * 1000).length;
  res.json({
    generationQueue: generationQueue.length,
    reviewQueue: reviewQueue.length,
    generationRecent: filterRecent(generationHits),
    reviewRecent: filterRecent(reviewHits),
    limits: config,
  });
});

app.post('/api/longtasks', async (req, res) => {
  const { userId, wordCount, difficulty, questionTypes, theme } = req.body || {};
  const user = await loadUser(userId);
  if (!user) return res.status(400).json({ message: 'User not found' });
  const allowed = await canUse(user);
  if (!allowed) return res.status(429).json({ message: 'Daily limit exceeded' });

  const cappedWordCount = Math.min(Number(wordCount) || 0, 1000);
  if (!cappedWordCount || !difficulty || !questionTypes) {
    return res.status(400).json({ message: 'Required fields missing' });
  }

  const id = randomUUID();
  const createdAt = new Date().toISOString();
  await run(
    `INSERT INTO long_tasks(id, userId, wordCount, difficulty, questionTypes, theme, generated, questions, answers, correction, status, createdAt)
     VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
    [
      id,
      userId,
      cappedWordCount,
      difficulty,
      JSON.stringify(questionTypes),
      sanitize(theme || ''),
      null,
      null,
      null,
      null,
      'queued_generation',
      createdAt,
    ]
  );

  generationHits = trackHits(generationHits);
  const shouldQueue = generationHits.length > config.thresholdPerMinute;
  if (shouldQueue) {
    enqueue(generationQueue, { id, wordCount: cappedWordCount, difficulty, questionTypes, theme }, user.priority);
    await incrementDailyUsage(userId);
    return res.json({ queued: true, taskId: id, position: generationQueue.length });
  }

  const passage = generateLongContent(cappedWordCount, theme, difficulty);
  const questions = buildQuestions(questionTypes, id);
  await run(
    'UPDATE long_tasks SET generated = ?, questions = ?, status = ? WHERE id = ?',
    [sanitize(passage), JSON.stringify(questions), 'awaiting_answers', id]
  );
  await incrementDailyUsage(userId);
  res.json({ queued: false, taskId: id, passage, questions });
});

app.post('/api/longtasks/:id/submit', async (req, res) => {
  const { answers, userId } = req.body || {};
  const task = await get('SELECT * FROM long_tasks WHERE id = ?', [req.params.id]);
  if (!task) return res.status(404).json({ message: 'Task not found' });
  const parsedAnswers = Array.isArray(answers) ? answers.map(sanitize) : [];
  if (!parsedAnswers.length) return res.status(400).json({ message: 'Answers required' });
  await run('UPDATE long_tasks SET answers = ?, status = ? WHERE id = ?', [
    JSON.stringify(parsedAnswers),
    'queued_review',
    req.params.id,
  ]);
  if (userId) await incrementDailyUsage(userId);
  reviewHits = trackHits(reviewHits);
  const shouldQueue = reviewHits.length > config.thresholdPerMinute;
  if (shouldQueue) {
    const user = userId ? await loadUser(userId) : null;
    enqueue(reviewQueue, { id: req.params.id, answers: parsedAnswers }, user?.priority || 'normal');
    return res.json({ queued: true, taskId: req.params.id, position: reviewQueue.length });
  }
  const correction = buildCorrection(parsedAnswers);
  await run(
    'UPDATE long_tasks SET correction = ?, status = ? WHERE id = ?',
    [JSON.stringify(correction), 'review_complete', req.params.id]
  );
  res.json({ queued: false, correction });
});

app.post('/api/essay', async (req, res) => {
  const { userId, theme, content } = req.body || {};
  const user = await loadUser(userId);
  if (!user) return res.status(400).json({ message: 'User not found' });
  const allowed = await canUse(user);
  if (!allowed) return res.status(429).json({ message: 'Daily limit exceeded' });
  const id = randomUUID();
  const createdAt = new Date().toISOString();
  await run(
    `INSERT INTO essay_tasks(id, userId, theme, content, correction, status, createdAt)
     VALUES(?,?,?,?,?,?,?)`,
    [
      id,
      userId,
      sanitize(theme || '自由テーマ'),
      sanitize(content || ''),
      null,
      'awaiting_review',
      createdAt,
    ]
  );
  const answers = content ? [content] : [];
  const correction = buildCorrection(answers);
  await run('UPDATE essay_tasks SET correction = ?, status = ? WHERE id = ?', [
    JSON.stringify(correction),
    'review_complete',
    id,
  ]);
  await incrementDailyUsage(userId);
  res.json({ taskId: id, correction });
});

app.get('/api/tasks', async (req, res) => {
  const { userId } = req.query;
  const user = userId ? await loadUser(userId) : null;
  if (!user) return res.status(400).json({ message: 'User not found' });
  const longs = await all('SELECT * FROM long_tasks WHERE userId = ? ORDER BY createdAt DESC', [userId]);
  const essays = await all('SELECT * FROM essay_tasks WHERE userId = ? ORDER BY createdAt DESC', [userId]);
  const normalizedLongs = longs.map((t) => ({
    ...t,
    type: 'long',
    questionTypes: t.questionTypes ? JSON.parse(t.questionTypes) : {},
    questions: t.questions ? JSON.parse(t.questions) : [],
    answers: t.answers ? JSON.parse(t.answers) : [],
    correction: t.correction ? JSON.parse(t.correction) : null,
  }));
  const normalizedEssays = essays.map((t) => ({
    ...t,
    type: 'essay',
    questionTypes: {},
    questions: [],
    answers: t.content ? [t.content] : [],
    correction: t.correction ? JSON.parse(t.correction) : null,
  }));
  res.json([...normalizedLongs, ...normalizedEssays]);
});

app.use((req, res, next) => {
  if (req.method === 'GET' && !req.path.startsWith('/api')) {
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
  next();
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
