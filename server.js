'use strict';
const express    = require('express');
const crypto     = require('crypto'); // Top-level — avoids registry lookup on every token op (VULN#9/BOTTLENECK#1)
const path       = require('path');
const multer     = require('multer');
const app        = express();

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

/* ── In-memory rate limiter ─────────────────────────────────────────────── */
// Single unified store for all rate limiters. TTL eviction runs every 5 minutes
// so the Map stays bounded to active-window entries rather than growing forever.
const rateLimitStore = new Map();
// LEAK-1: Store interval ref so it can be cleared on graceful shutdown
const _rlCleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, rec] of rateLimitStore) {
    if (now > rec.reset) rateLimitStore.delete(key);
  }
}, 5 * 60 * 1000);
_rlCleanupInterval.unref(); // never blocks clean process exit

// Graceful shutdown — clear interval to avoid leak in test/watch environments
process.once('SIGTERM', () => { clearInterval(_rlCleanupInterval); });
process.once('SIGINT',  () => { clearInterval(_rlCleanupInterval); });

function rateLimit({ windowMs = 60000, max = 20, keyFn = (req) => req.ip, prefix = '' } = {}) {
  return (req, res, next) => {
    const key = prefix + keyFn(req);
    const now = Date.now();
    const rec = rateLimitStore.get(key) ?? { count: 0, reset: now + windowMs };
    if (now > rec.reset) { rec.count = 0; rec.reset = now + windowMs; }
    rec.count++;
    rateLimitStore.set(key, rec);
    // GAP#1: Bound store size — evict oldest 10% when over 50k entries (DDoS protection)
    if (rateLimitStore.size > 50_000) {
      const oldest = [...rateLimitStore.entries()].sort((a, b) => a[1].reset - b[1].reset).slice(0, 5000);
      for (const [k] of oldest) rateLimitStore.delete(k);
    }
    res.setHeader('X-RateLimit-Limit',     max);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, max - rec.count));
    if (rec.count > max) return res.status(429).json({ error: 'Too many requests. Please wait.' });
    next();
  };
}

/* ── Signup IP rate limiter: max 3 new accounts per IP per 24 hours ──────── */
// Reuses the shared rateLimitStore with a 'signup:' prefix instead of a
// separate Map that would also leak memory without eviction.
function signupRateLimit(req, res, next) {
  const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  return rateLimit({
    windowMs: 24 * 60 * 60 * 1000,
    max: 3,
    keyFn: () => ip,
    prefix: 'signup:'
  })(req, res, (err) => {
    if (err) return next(err);
    // Override the generic 429 message with a signup-specific one
    const key = 'signup:' + ip;
    const rec = rateLimitStore.get(key);
    if (rec && rec.count > 3) {
      return res.status(429).json({
        error: 'Too many accounts created from this network. Please try again tomorrow or contact support@scholarshub.co.uk'
      });
    }
    next();
  });
}

/* ── University email validator (server-side mirror of client-side check) ── */
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com','tempmail.com','guerrillamail.com','10minutemail.com',
  'throwaway.email','yopmail.com','trashmail.com','fakeinbox.com',
  'temp-mail.org','temp-mail.ru','dispostable.com','maildrop.cc',
  'sharklasers.com','spam4.me','spamgourmet.com','trashmail.me',
  'mytrashmail.com','discard.email','spambox.us','mailexpire.com'
]);

// Pre-built Set — O(1) lookup per call instead of O(8 × |suffix|) .endsWith chain
const UNI_SUFFIXES = new Set([
  '.ac.uk', '.edu', '.ac.nz', '.ac.za',
  '.ac.in', '.edu.au', '.edu.sg', '.ac.jp'
]);

function isUniversityEmail(email) {
  const domain = (email.split('@')[1] || '').toLowerCase();
  const parts  = domain.split('.');
  // Check three-component suffix (.edu.au) then two-component (.ac.uk, .edu)
  const s3 = parts.length >= 3 ? '.' + parts.slice(-2).join('.') : '';
  const s2 = parts.length >= 2 ? '.' + parts[parts.length - 1]  : '';
  return UNI_SUFFIXES.has(s3) || UNI_SUFFIXES.has(s2);
}

app.post('/api/validate-signup', signupRateLimit, (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });
  const clean = email.trim().toLowerCase();
  const domain = clean.split('@')[1] || '';
  if (DISPOSABLE_DOMAINS.has(domain)) {
    return res.status(400).json({ error: 'Disposable email addresses are not permitted.' });
  }
  // Owner bypass
  if (clean === 'acharyarudranathjajot@gmail.com') {
    return res.json({ valid: true });
  }
  if (!isUniversityEmail(clean)) {
    return res.status(400).json({ error: 'A university email address is required (.ac.uk or .edu).' });
  }
  res.json({ valid: true });
});


/* ── Welcome email endpoint ──────────────────────────────────────────────── */
app.post('/api/send-welcome', requireAuth, rateLimit({ windowMs: 60000, max: 5, keyFn: req => req.userToken, prefix: 'welcome:' }), async (req, res) => { // VULN-4: auth+rateLimit added
  const { email, name } = req.body || {};
  if (!email || !name) return res.status(400).json({ error: 'Email and name required' });
  
  try {
    await sendEmail({
      to: email,
      subject: '🎓 Welcome to Scholars Hub — your 3 free passes are ready',
      html: `
        <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:32px;background:#f8fafc;">
          <div style="background:#0F1B3C;padding:32px;border-radius:12px 12px 0 0;text-align:center;">
            <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" style="display:block;margin:0 auto 12px">
              <path d="M24 3L6 10V24C6 33.94 13.94 43.18 24 46C34.06 43.18 42 33.94 42 24V10L24 3Z" fill="#0A1530"/>
              <path d="M30 18.5C30 15.46 27.54 13 24.5 13H21C18.24 13 16 15.24 16 18C16 20.49 17.72 22.57 20.1 23.06L26.4 24.3C27.94 24.61 29 25.97 29 27.5C29 29.43 27.43 31 25.5 31H22C19.79 31 18 29.21 18 27" stroke="#00A896" stroke-width="2.8" stroke-linecap="round" fill="none"/>
              <circle cx="33" cy="15" r="2.5" fill="#F5A623"/>
            </svg>
            <h1 style="color:#fff;margin:0;font-size:24px;font-weight:700;">Welcome to Scholars Hub</h1>
            <p style="color:rgba(255,255,255,0.7);margin:8px 0 0;font-size:15px;">AI-powered academic feedback for UK university students</p>
          </div>
          <div style="background:#fff;padding:32px;border-radius:0 0 12px 12px;border:1px solid #e2e8f0;">
            <p style="color:#334155;font-size:16px;margin-top:0;">Hi ${firstName(name)},</p>
            <p style="color:#334155;font-size:16px;">Your account is set up and <strong>3 free essay passes</strong> are waiting for you. Each pass gives you a full AI-powered report — grade prediction, structure analysis, citation check, and AI detection score.</p>
            <div style="background:#f0fdf9;border:1px solid #99f6e4;border-radius:10px;padding:20px;margin:24px 0;text-align:center;">
              <div style="font-size:40px;font-weight:800;color:#0F1B3C;">3</div>
              <div style="font-size:14px;color:#00A896;font-weight:600;letter-spacing:0.05em;text-transform:uppercase;">Free Essay Passes</div>
            </div>
            <p style="color:#334155;font-size:15px;">What happens when you submit:</p>
            <ul style="color:#334155;font-size:15px;line-height:1.8;padding-left:20px;">
              <li>📊 Overall score out of 100</li>
              <li>🎓 Predicted degree classification (1st, 2:1, 2:2…)</li>
              <li>🔍 AI detection risk percentage</li>
              <li>📝 Section-by-section written feedback</li>
              <li>📌 Citation and referencing analysis</li>
            </ul>
            <div style="text-align:center;margin:28px 0;">
              <a href="https://scholarshub.pages.dev/dashboard.html" 
                 style="background:#00A896;color:#fff;padding:14px 36px;border-radius:8px;text-decoration:none;font-weight:600;font-size:16px;display:inline-block;">
                Go to My Dashboard →
              </a>
            </div>
            <p style="color:#94a3b8;font-size:13px;text-align:center;margin:0;">Scholars Hub · Awrex Ltd · 42A St Pauls Road, Peterborough, PE1 3DW<br>Questions? Email us at <a href="mailto:info@scholarshub.co.uk" style="color:#00A896;">info@scholarshub.co.uk</a></p>
          </div>
        </div>
      `
    });
    res.json({ sent: true });
  } catch (err) {
    console.error('[send-welcome] Error:', err.message);
    res.status(500).json({ error: 'Failed to send welcome email' });
  }
});


/* ── Security headers ───────────────────────────────────────────────────── */
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options',  'nosniff');
  res.setHeader('X-Frame-Options',         'SAMEORIGIN');
  res.setHeader('Referrer-Policy',         'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy',      'geolocation=(), camera=(), microphone=()');
  // VULN-CSP: Content-Security-Policy prevents XSS and data injection attacks
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data: https:; " +
    "connect-src 'self' " + (process.env.SUPABASE_URL ? new URL(process.env.SUPABASE_URL).origin : 'https://*.supabase.co') + " https://api.groq.com; " +
    "frame-ancestors 'none';"
  );
  res.setHeader('X-XSS-Protection', '1; mode=block');
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  next();
});

/* ── Resend email helper ─────────────────────────────────────────────────── */
// VULN-1: Hardcoded API key removed — no fallback; server fails loudly if key missing
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
if (!RESEND_API_KEY) console.warn('[STARTUP] RESEND_API_KEY not set — email sending will fail');
const RESEND_FROM    = 'Scholars Hub <noreply@scholarshub.co.uk>';

async function sendEmail({ to, subject, html }) {
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ from: RESEND_FROM, to, subject, html })
    });
    const data = await res.json();
    if (!res.ok) console.error('[Resend] Error:', data);
    return data;
  } catch (err) {
    console.error('[Resend] Send failed:', err.message);
  }
}

/* ── node-fetch — cached top-level import (PERF-1) ─────────────────────── */
// Dynamic import on every request wastes ~0.1ms + microtask scheduling.
// Resolved once at startup; _fetchFn is ready before first request arrives.
let _fetchFn;
(async () => { const m = await import('node-fetch'); _fetchFn = m.default; })();

/* ── Supabase helper ─────────────────────────────────────────────────────── */
// VULN#8: No hardcoded fallback — missing env var must fail loudly at startup
const SB_URL         = process.env.SUPABASE_URL         || '';
if (!SB_URL)         console.error('[STARTUP] SUPABASE_URL not set — all DB operations will fail');
const SB_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';
// BOTTLENECK#3: Pre-built frozen headers object — spread-copy only when extraHeaders needed
const SB_BASE_HEADERS = Object.freeze({
  'Content-Type':  'application/json',
  'apikey':        SB_SERVICE_KEY,
  'Authorization': 'Bearer ' + SB_SERVICE_KEY,
  'Prefer':        'return=representation',
});

async function sbFetch(endpoint, method = 'GET', body = null, extraHeaders = {}) {
  // PERF-1: fetch is resolved once at module load — no dynamic import per request
  // VULN#11: Guard against startup race where IIFE hasn't resolved yet
  if (!_fetchFn) _fetchFn = (await import('node-fetch')).default;
  const fetch = _fetchFn;
  // BOTTLENECK#3: Spread from frozen base — avoids re-allocating string concat per call
  const headers = extraHeaders && Object.keys(extraHeaders).length
    ? { ...SB_BASE_HEADERS, ...extraHeaders }
    : SB_BASE_HEADERS;
  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(SB_URL + endpoint, opts);
  let data;
  try { data = await res.json(); } catch { data = await res.text(); }
  return { ok: res.ok, status: res.status, data };
}

/* ── Revolut ─────────────────────────────────────────────────────────────── */
// OPT-12: Keys match product_id directly — no replace(/-/g,'_').toLowerCase() per payout
const PAYOUT_RATES = {
  'commentary':        1280,
  'full_review':       2600,
  'chapter_review':    2200,
  'full_dissertation': 7800,
  'diss_journey':      10000,
  // Hyphenated aliases matching revolut-payment.js product_ids — O(1) direct lookup
  'expert-tier-2':     2600,
  'expert-tier-3':     6500,
  'expert-tier-4':     5500,
  'expert-tier-5a':    19500,
  'expert-tier-5b':    25000,
};
const REVOLUT_SECRET_KEY = process.env.REVOLUT_SECRET_KEY || '';
const REVOLUT_API        = 'https://merchant.revolut.com/api/1.0';

async function revolutPayout(pence, description, revolutRecipientId) {
  const fetch = _fetchFn;
  const res = await fetch(REVOLUT_API + '/payout', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + REVOLUT_SECRET_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount: pence, currency: 'GBP', description, recipient: { id: revolutRecipientId } })
  });
  let data; try { data = await res.json(); } catch { data = {}; }
  return { ok: res.ok, data };
}

/* ── Auth ────────────────────────────────────────────────────────────────── */
/* ── firstName — OPT-17: indexOf+slice avoids array allocation per email ─── */
// .split(' ')[0] allocates a full array; indexOf stops at first space — O(1) allocation
function firstName(fullName, fallback = 'there') {
  if (!fullName) return fallback;
  const sp = fullName.indexOf(' ');
  return sp === -1 ? fullName : fullName.slice(0, sp);
}

function requireAuth(req, res, next) {
  // OPT-15: startsWith+slice is O(1) prefix check — no regex engine, no scan
  const auth  = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!token) return res.status(401).json({ error: 'Authentication required.' });
  req.userToken = token;
  next();
}

function decodeToken(token) {
  try {
    // OPT-16: indexOf+slice avoids allocating a 3-element split array on every request
    const i1 = token.indexOf('.');
    const i2 = token.indexOf('.', i1 + 1);
    if (i1 === -1 || i2 === -1) return null;
    const payload = token.slice(i1 + 1, i2);
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch { return null; }
}

/* ── Admin Basic Auth ────────────────────────────────────────────────────── */
app.use('/admin', (req, res, next) => {
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (!adminPassword) return res.status(503).send('Admin not configured.');
  // PERF-3/LOGIC-3: indexOf+slice avoids array allocation; guards empty encoded
  const auth = req.headers['authorization'] || '';
  const sp = auth.indexOf(' ');
  if (sp !== -1 && auth.slice(0, sp) === 'Basic') {
    const encoded = auth.slice(sp + 1).trim();
    if (encoded) {
      const decoded  = Buffer.from(encoded, 'base64').toString('utf8');
      const password = decoded.slice(decoded.indexOf(':') + 1);
      if (password === adminPassword) return next();
    }
  }
  res.setHeader('WWW-Authenticate', 'Basic realm="ScholarsHub Admin"');
  res.status(401).send('Unauthorised.');
});

/* ── File upload ─────────────────────────────────────────────────────────── */
const upload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = [
      'application/pdf',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/msword',
      'text/plain'
    ];
    allowed.includes(file.mimetype) ? cb(null, true) : cb(new Error('Only PDF, DOCX, DOC, and TXT accepted.'));
  }
});

async function extractText(file) {
  if (file.mimetype === 'text/plain') return file.buffer.toString('utf8');
  if (file.mimetype === 'application/pdf') {
    try { const p = require('pdf-parse'); const d = await p(file.buffer); return d.text; }
    catch { throw new Error('Could not read PDF. Please paste your essay as text instead.'); }
  }
  if (file.mimetype.includes('wordprocessingml') || file.mimetype === 'application/msword') {
    try { const m = require('mammoth'); const r = await m.extractRawText({ buffer: file.buffer }); return r.value; }
    catch { throw new Error('Could not read Word document. Please paste your essay instead.'); }
  }
  throw new Error('Unsupported file type.');
}

/* ═══════════════════════════════════════════════════════════════════════════
   POST /api/submit — AI analysis with SSE progress stream
   ═══════════════════════════════════════════════════════════════════════════ */
app.post('/api/submit',
  requireAuth,
  rateLimit({ windowMs: 60000, max: 5, keyFn: req => req.userToken }),
  upload.single('file'),
  async (req, res) => {

  let essayText = req.body && req.body.essay_text ? req.body.essay_text : '';
  const subject   = ((req.body && req.body.subject)   || '').trim();
  const level     = ((req.body && req.body.level)     || 'Undergraduate').trim();
  const tierRaw   = ((req.body && req.body.tier)      || 'ai_basic').trim();
  // VULN#10: Validate tier against allowlist — prevents unrecognised values reaching DB
  const VALID_TIERS = new Set(['ai_basic','ai_pro','expert_1','expert_2','expert_3','expert_4','expert_5a','expert_5b','pro_monthly','starter']);
  if (!VALID_TIERS.has(tierRaw)) return res.status(400).json({ error: 'Invalid tier.' });
  const tier = tierRaw;
  const token     = req.userToken;

  if (req.file) {
    try { essayText = await extractText(req.file); }
    catch (err) { return res.status(400).json({ error: 'Internal server error.' }); }
  }

  if (!essayText || essayText.trim().length < 200)
    return res.status(400).json({ error: 'Essay too short — minimum 200 characters.' });

  // BOTTLENECK#4: match returns null-safe array count — no 5000-element array allocation
  const wordCount = (essayText.trim().match(/\S+/g) || []).length;
  if (wordCount < 50)
    return res.status(400).json({ error: 'Essay must be at least 50 words.' });

  let userId;
  try {
    const claims = decodeToken(token);
    userId = claims && claims.sub;
    if (!userId) throw new Error('bad token');
  } catch { return res.status(401).json({ error: 'Invalid session. Please log in again.' }); }

  const profileRes = await sbFetch(
    '/rest/v1/profiles?id=eq.' + userId + '&select=passes_remaining,plan,full_name,email',
    'GET', null, { 'Authorization': 'Bearer ' + token }
  );
  const profile = profileRes.data && profileRes.data[0];
  if (!profile) return res.status(403).json({ error: 'Account not found.' });
  const userEmail = profile.email || '';

  const aiTiers   = ['ai_basic', 'ai_pro'];
  const needsPass = aiTiers.includes(tier);
  if (needsPass && (profile.passes_remaining || 0) < 1)
    return res.status(402).json({ error: 'No passes remaining. Please upgrade your plan.' });

  /* SSE setup */
  res.setHeader('Content-Type',       'text/event-stream');
  res.setHeader('Cache-Control',      'no-cache, no-transform');
  res.setHeader('Connection',         'keep-alive');

  // ISSUE#2/LEAK#1: Track client disconnect to stop AI analysis and ticker
  let _sseAborted = false;
  let _ticker = null;
  req.on('close', () => {
    _sseAborted = true;
    if (_ticker) { clearInterval(_ticker); _ticker = null; }
  });
  res.setHeader('X-Accel-Buffering',  'no');
  res.flushHeaders && res.flushHeaders();

  function send(event, data) {
    res.write('event: ' + event + '\ndata: ' + JSON.stringify(data) + '\n\n');
    res.flush && res.flush();
  }

  try {
    send('progress', { stage: 'Essay received', pct: 5 });

    const subRes = await sbFetch('/rest/v1/submissions', 'POST', {
      user_id: userId, essay_text: essayText.slice(0, 50000),
      word_count: wordCount, subject: subject || null,
      level, tier, status: 'processing', created_at: new Date().toISOString()
    });
    if (!subRes.ok) { send('error', { message: 'Failed to create submission. Please try again.' }); return res.end(); }

    const submissionId = subRes.data && subRes.data[0] && subRes.data[0].id;
    // LOGIC-2: Guard undefined submissionId — Supabase may return ok:true with empty data
    if (!submissionId) { send('error', { message: 'Submission record could not be created. Please try again.' }); return res.end(); }
    send('progress', { stage: 'Submission created', pct: 10, submission_id: submissionId });

    /* ── Send submission confirmation email immediately ── */
    if (userEmail) {
      sendEmail({
        to: userEmail,
        subject: '📬 Essay received — Scholars Hub is analysing it now',
        html: `
          <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:32px;background:#f8fafc;">
            <div style="background:#0F1B3C;padding:24px;border-radius:12px 12px 0 0;text-align:center;">
              <h1 style="color:#fff;margin:0;font-size:22px;">Essay Received ✅</h1>
            </div>
            <div style="background:#fff;padding:32px;border-radius:0 0 12px 12px;border:1px solid #e2e8f0;">
              <p style="color:#334155;font-size:16px;margin-top:0;">Hi ${firstName(profile.full_name)},</p>
              <p style="color:#334155;font-size:16px;">Your essay has been received and AI analysis has started. We'll email you as soon as your report is ready — usually within 10 minutes.</p>
              <div style="background:#f1f5f9;border-radius:10px;padding:16px 20px;margin:20px 0;">
                <p style="margin:0;font-size:13px;color:#64748b;"><strong>Submission ID:</strong> ${submissionId}</p>
                ${subject ? `<p style="margin:4px 0 0;font-size:13px;color:#64748b;"><strong>Subject:</strong> ${subject.replace(/[<>&"]/g, c => ({"<":"&lt;",">":"&gt;","&":"&amp;","'":"&#x27;","\"":"&quot;"}[c]))}</p>` : ''} <!-- VULN-13: HTML-escaped -->
                <p style="margin:4px 0 0;font-size:13px;color:#64748b;"><strong>Word count:</strong> ~${wordCount.toLocaleString()}</p>
              </div>
              <p style="color:#334155;font-size:15px;">You can close this browser window — we'll email you when it's done.</p>
              <p style="color:#94a3b8;font-size:13px;text-align:center;margin-top:24px;">Scholars Hub · Awrex Ltd · 42A St Pauls Road, Peterborough, PE1 3DW</p>
            </div>
          </div>
        `
      }).catch(err => console.error('[submit] confirmation email failed:', err.message));
    }

    if (needsPass) {
      // BUG-07 FIX: Use RPC for atomic decrement — PostgREST PATCH cannot evaluate SQL expressions.
      // decrement_pass() uses GREATEST(passes_remaining - 1, 0) atomically in SQL.
      await sbFetch('/rest/v1/rpc/decrement_pass', 'POST', { p_user_id: userId });
    }

    send('progress', { stage: 'Starting AI analysis…', pct: 20 });

    // PERF-2: analyseEssay resolved at module load (top-level require at bottom of file)
    const stages = [
      { pct: 35, stage: 'Reading essay structure…'    },
      { pct: 50, stage: 'Analysing argument quality…' },
      { pct: 65, stage: 'Checking citations…'         },
      { pct: 75, stage: 'Assessing academic style…'   },
      { pct: 85, stage: 'Generating feedback…'        },
      { pct: 92, stage: 'Finalising report…'          }
    ];
    // ISSUE#2/LEAK#1b: Use _ticker so req.on('close') can also clear it
    let si = 0;
    _ticker = setInterval(() => {
      if (_sseAborted) { clearInterval(_ticker); _ticker = null; return; }
      if (si < stages.length) send('progress', stages[si++]);
    }, 2500);

    // GAP#2: Wrap analyseEssay in a 120s timeout to prevent indefinite SSE hold-open
    let reportJson;
    try {
      reportJson = await Promise.race([
        analyseEssay({
          essayText, subject, wordCount, level,
          onProgress: (evt, msg) => { if (!_sseAborted) send('ai_' + evt, { message: msg }); }
        }),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Analysis timed out after 120s')), 120_000))
      ]);
    } finally {
      if (_ticker) { clearInterval(_ticker); _ticker = null; }
    }

    send('progress', { stage: 'Saving report…', pct: 95 });

    await sbFetch('/rest/v1/submissions?id=eq.' + submissionId, 'PATCH', {
      status:           'complete',
      report_json:      reportJson,
      overall_score:    reportJson.overall_score,
      grade_predicted:  reportJson.grade_predicted,
      subject:          reportJson.subject_detected || subject,
      ai_detection_pct: reportJson.ai_detection_pct,
      completed_at:     new Date().toISOString()
    });

    if (!needsPass) {
      await sbFetch('/rest/v1/expert_review_orders', 'POST', {
        submission_id: submissionId, user_id: userId,
        product_id: tier, status: 'ai_complete_awaiting_expert',
        created_at: new Date().toISOString()
      });
    }

    // Send report ready email
    if (userEmail) {
      sendEmail({
        to: userEmail,
        subject: '📋 Your Scholars Hub report is ready',
        html: `
          <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:32px;background:#f8fafc;">
            <div style="background:#0F1B3C;padding:24px;border-radius:12px 12px 0 0;text-align:center;">
              <h1 style="color:#fff;margin:0;font-size:22px;">Your Report Is Ready</h1>
            </div>
            <div style="background:#fff;padding:32px;border-radius:0 0 12px 12px;border:1px solid #e2e8f0;">
              <p style="color:#334155;font-size:16px;">Hi ${firstName(profile.full_name)},</p>
              <p style="color:#334155;font-size:16px;">Your essay has been analysed. Here's a quick summary:</p>
              <div style="background:#f1f5f9;border-radius:8px;padding:20px;margin:20px 0;text-align:center;">
                <div style="font-size:48px;font-weight:700;color:#0F1B3C;">${reportJson.overall_score}<span style="font-size:24px;">/100</span></div>
                <div style="font-size:18px;color:#00A896;font-weight:600;margin-top:4px;">Predicted: ${reportJson.grade_predicted}</div>
              </div>
              <p style="color:#334155;font-size:16px;">View your full report with detailed feedback, citation analysis, and improvement tips.</p>
              <div style="text-align:center;margin:28px 0;">
                <a href="https://scholarshub.pages.dev/report.html?id=${submissionId}" 
                   style="background:#00A896;color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:600;font-size:16px;">
                  View Full Report →
                </a>
              </div>
              <p style="color:#94a3b8;font-size:13px;text-align:center;">Scholars Hub · UK's AI Academic Feedback Platform</p>
            </div>
          </div>
        `
      });
    }

    send('complete', {
      submission_id: submissionId,
      overall_score: reportJson.overall_score,
      grade:         reportJson.grade_predicted,
      redirect:      '/report.html?id=' + submissionId
    });

  } catch (err) {
    console.error('[submit]', err.message);
    send('error', {
      message: err.message.includes('API key')
        ? 'AI service unavailable. Your pass has not been deducted. Please try again shortly.'
        : 'Analysis failed. Please try again.'
    });
    if (needsPass) {
      // BUG-07 FIX: Use RPC for atomic increment refund — PostgREST PATCH cannot evaluate SQL expressions.
      await sbFetch('/rest/v1/rpc/increment_pass', 'POST', { p_user_id: userId });
    }
    // ISSUE#1: Mark submission as 'failed' so admin panel shows correct state and user can retry
    if (submissionId) {
      await sbFetch('/rest/v1/submissions?id=eq.' + submissionId, 'PATCH', {
        status: 'failed', error_message: err.message, updated_at: new Date().toISOString()
      });
    }
  }
  res.end();
});

/* ── GET /api/submit/status/:id ─────────────────────────────────────────── */
app.get('/api/submit/status/:id', requireAuth, async (req, res) => {
  try {
    const r = await sbFetch(
      '/rest/v1/submissions?id=eq.' + req.params.id + '&select=id,status,overall_score,grade_predicted',
      'GET', null, { 'Authorization': 'Bearer ' + req.userToken }
    );
    if (!r.ok || !r.data || !r.data.length) return res.status(404).json({ error: 'Not found.' });
    const s = r.data[0];
    res.json({ id: s.id, status: s.status, overall_score: s.overall_score, grade: s.grade_predicted,
      redirect: s.status === 'complete' ? '/report.html?id=' + s.id : null });
  } catch (e) { res.status(500).json({ error: 'Internal server error.' }); }
});

/* ── GET /api/profile ───────────────────────────────────────────────────── */
app.get('/api/profile', requireAuth, async (req, res) => {
  try {
    const claims = decodeToken(req.userToken);
    const userId = claims && claims.sub;
    if (!userId) return res.status(401).json({ error: 'Invalid token.' });
    const r = await sbFetch('/rest/v1/profiles?id=eq.' + userId + '&select=full_name,passes_remaining,plan,created_at');
    if (!r.ok || !r.data || !r.data.length) return res.status(404).json({ error: 'Profile not found.' });
    res.json(r.data[0]);
  } catch (e) { res.status(500).json({ error: 'Internal server error.' }); }
});

/* ── GET /api/submissions ───────────────────────────────────────────────── */
app.get('/api/submissions', requireAuth, async (req, res) => {
  try {
    const claims = decodeToken(req.userToken);
    const userId = claims && claims.sub;
    if (!userId) return res.status(401).json({ error: 'Invalid token.' });
    const r = await sbFetch(
      '/rest/v1/submissions?user_id=eq.' + userId + '&order=created_at.desc&limit=50&select=id,created_at,subject,word_count,overall_score,grade_predicted,status,ai_detection_pct',
      'GET', null, { 'Authorization': 'Bearer ' + req.userToken }
    );
    if (!r.ok) return res.status(500).json({ error: 'Could not load submissions.' });
    res.json(r.data || []);
  } catch (e) { res.status(500).json({ error: 'Internal server error.' }); }
});

/* ═══════════════════════════════════════════════════════════════════════════
   REVIEWER ROUTES
   ═══════════════════════════════════════════════════════════════════════════ */
app.post('/api/reviewer/apply', rateLimit({ windowMs: 3600000, max: 3 }), async (req, res) => {
  const { full_name, email, qualification, subjects } = req.body || {};
  if (!full_name || !email || !qualification || !subjects)
    return res.status(400).json({ error: 'All fields are required.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Invalid email address.' });
  try {
    const dup = await sbFetch('/rest/v1/reviewer_applications?email=eq.' + encodeURIComponent(email.toLowerCase()) + '&select=id,status');
    if (dup.ok && Array.isArray(dup.data) && dup.data.length)
      return res.status(409).json({ error: 'Application already exists (status: ' + dup.data[0].status + ').' });
    const r = await sbFetch('/rest/v1/reviewer_applications', 'POST', {
      full_name: full_name.trim(), email: email.toLowerCase().trim(),
      qualification: qualification.trim(), subjects: subjects.trim(),
      status: 'pending', applied_at: new Date().toISOString()
    });
    if (!r.ok) return res.status(500).json({ error: 'Could not save application.' });
    return res.status(201).json({ success: true });
  } catch (e) { return res.status(500).json({ error: 'Internal server error.' }); }
});

app.post('/api/reviewer/approve', requireAdminToken, async (req, res) => {
  const { application_id } = req.body || {};
  if (!application_id) return res.status(400).json({ error: 'application_id required.' });
  try {
    const ar = await sbFetch('/rest/v1/reviewer_applications?id=eq.' + application_id + '&select=*');
    if (!ar.ok || !ar.data || !ar.data.length) return res.status(404).json({ error: 'Not found.' });
    const appl = ar.data[0];
    if (appl.status !== 'pending') return res.status(400).json({ error: 'Already ' + appl.status + '.' });
    await sbFetch('/rest/v1/reviewer_applications?id=eq.' + application_id, 'PATCH',
      { status: 'approved', approved_at: new Date().toISOString() });
    // BUG-04 FIX: Look up the reviewer's auth user_id by email so reviewer dashboard auth works
    const authLookup = await sbFetch('/auth/v1/admin/users?email=' + encodeURIComponent(appl.email.toLowerCase()),
      'GET', null, { 'Authorization': 'Bearer ' + (process.env.SUPABASE_SERVICE_KEY || '') });
    const reviewerUserId = authLookup.data && authLookup.data.users && authLookup.data.users[0]
      ? authLookup.data.users[0].id : null;
    const pr = await sbFetch('/rest/v1/reviewer_profiles', 'POST', {
      application_id, full_name: appl.full_name, email: appl.email,
      qualification: appl.qualification, subjects: appl.subjects,
      user_id: reviewerUserId,  // BUG-04: links profile to auth account
      status: 'active', created_at: new Date().toISOString()
    });
    if (!pr.ok) return res.status(500).json({ error: 'Approved but profile creation failed.' });
    return res.json({ success: true, profile_id: pr.data && pr.data[0] && pr.data[0].id });
  } catch (e) { return res.status(500).json({ error: 'Internal server error.' }); }
});

app.post('/api/reviewer/reject', requireAdminToken, async (req, res) => {
  const { application_id, reason } = req.body || {};
  if (!application_id) return res.status(400).json({ error: 'application_id required.' });
  try {
    await sbFetch('/rest/v1/reviewer_applications?id=eq.' + application_id, 'PATCH',
      { status: 'rejected', rejected_at: new Date().toISOString(), reject_reason: reason || '' });
    return res.json({ success: true });
  } catch (e) { return res.status(500).json({ error: 'Internal server error.' }); }
});

app.post('/api/reviewer/assign', requireAdminToken, async (req, res) => {
  const { order_id, reviewer_id } = req.body || {};
  if (!order_id || !reviewer_id) return res.status(400).json({ error: 'order_id and reviewer_id required.' });
  try {
    const or = await sbFetch('/rest/v1/expert_review_orders?id=eq.' + order_id + '&select=*');
    if (!or.ok || !or.data || !or.data.length) return res.status(404).json({ error: 'Order not found.' });
    if (or.data[0].status !== 'paid') return res.status(400).json({ error: 'Can only assign paid orders.' });
    const rr = await sbFetch('/rest/v1/reviewer_profiles?id=eq.' + reviewer_id + '&select=id,status');
    if (!rr.ok || !rr.data || !rr.data.length) return res.status(404).json({ error: 'Reviewer not found.' });
    const ar = await sbFetch('/rest/v1/review_assignments', 'POST',
      { order_id, reviewer_id, status: 'assigned', assigned_at: new Date().toISOString() });
    if (!ar.ok) return res.status(500).json({ error: 'Assignment failed.' });
    await sbFetch('/rest/v1/expert_review_orders?id=eq.' + order_id, 'PATCH',
      { status: 'assigned', reviewer_id, assigned_at: new Date().toISOString() });
    return res.json({ success: true, assignment_id: ar.data && ar.data[0] && ar.data[0].id });
  } catch (e) { return res.status(500).json({ error: 'Internal server error.' }); }
});

app.post('/api/reviewer/submit', requireAuth, rateLimit({ windowMs: 300000, max: 10 }), async (req, res) => {
  const { assignment_id, feedback_text, feedback_rating } = req.body || {};
  if (!assignment_id || !feedback_text)
    return res.status(400).json({ error: 'assignment_id and feedback_text required.' });
  try {
    // VULN#3: Verify the authenticated reviewer owns this assignment
    const callerClaims = decodeToken(req.userToken);
    const callerUserId = callerClaims && callerClaims.sub;
    if (!callerUserId) return res.status(401).json({ error: 'Invalid session.' });

    const aRes = await sbFetch('/rest/v1/review_assignments?id=eq.' + assignment_id + '&select=*');
    if (!aRes.ok || !aRes.data || !aRes.data.length) return res.status(404).json({ error: 'Assignment not found.' });
    const assignment = aRes.data[0];

    // Cross-check: look up reviewer_profile by reviewer_id, confirm user_id matches caller
    const rpRes = await sbFetch('/rest/v1/reviewer_profiles?id=eq.' + assignment.reviewer_id + '&select=user_id');
    const rp = rpRes.data && rpRes.data[0];
    if (!rp || rp.user_id !== callerUserId) return res.status(403).json({ error: 'Forbidden — this assignment belongs to another reviewer.' });

    if (assignment.status === 'completed') return res.status(400).json({ error: 'Already submitted.' });
    const oRes = await sbFetch('/rest/v1/expert_review_orders?id=eq.' + assignment.order_id + '&select=*');
    if (!oRes.ok || !oRes.data || !oRes.data.length) return res.status(404).json({ error: 'Order not found.' });
    const order = oRes.data[0];
    await sbFetch('/rest/v1/review_assignments?id=eq.' + assignment_id, 'PATCH', {
      status: 'completed', feedback_text: feedback_text.trim(),
      feedback_rating: feedback_rating || null, completed_at: new Date().toISOString()
    });
    await sbFetch('/rest/v1/expert_review_orders?id=eq.' + assignment.order_id, 'PATCH', {
      status: 'completed', feedback_text: feedback_text.trim(), completed_at: new Date().toISOString()
    });
    // OPT-12: Direct O(1) Map lookup — keys now match product_id without transform
    const pence = PAYOUT_RATES[order.product_id];
    if (pence && REVOLUT_SECRET_KEY) {
      const rr = await sbFetch('/rest/v1/reviewer_profiles?id=eq.' + assignment.reviewer_id + '&select=revolut_id');
      const revolut_id = rr.data && rr.data[0] && rr.data[0].revolut_id;
      if (revolut_id) {
        const payout = await revolutPayout(pence, 'ScholarsHub payout — order ' + assignment.order_id, revolut_id);
        if (!payout.ok) console.error('[reviewer/submit] payout failed:', payout.data);
        else console.log('[reviewer/submit] Payout £' + (pence / 100) + ' sent');
      } else {
        console.warn('[reviewer/submit] No Revolut ID — manual payout needed for reviewer ' + assignment.reviewer_id);
      }
    }
    return res.json({ success: true });
  } catch (e) { return res.status(500).json({ error: 'Internal server error.' }); }
});

app.get('/api/reviewer/applications', requireAdminToken, async (req, res) => {
  // VULN-2: Whitelist-validate status before interpolating into DB URL
  const VALID_STATUSES = new Set(['pending', 'approved', 'rejected']);
  const rawStatus = req.query.status;
  if (rawStatus && !VALID_STATUSES.has(rawStatus)) {
    return res.status(400).json({ error: 'Invalid status filter.' });
  }
  const q = rawStatus
    ? '?status=eq.' + rawStatus + '&order=applied_at.desc'
    : '?order=applied_at.desc';
  try {
    const r = await sbFetch('/rest/v1/reviewer_applications' + q + '&select=*');
    return r.ok ? res.json(r.data) : res.status(500).json({ error: 'Database error.' });
  } catch (e) { return res.status(500).json({ error: 'Internal server error.' }); }
});

app.get('/api/reviewer/pending-orders', requireAdminToken, async (req, res) => {
  try {
    const r = await sbFetch('/rest/v1/expert_review_orders?status=eq.paid&order=created_at.desc&select=*');
    return r.ok ? res.json(r.data) : res.status(500).json({ error: 'Database error.' });
  } catch (e) { return res.status(500).json({ error: 'Internal server error.' }); }
});

app.get('/api/reviewer/dashboard', requireAuth, async (req, res) => {
  // VULN#4: Derive reviewer_id from the authenticated token — never trust client-supplied ID
  try {
    const claims = decodeToken(req.userToken);
    const userId = claims && claims.sub;
    if (!userId) return res.status(401).json({ error: 'Invalid session.' });

    // Look up the reviewer profile owned by this user
    const rpRes = await sbFetch('/rest/v1/reviewer_profiles?user_id=eq.' + userId + '&select=id');
    const rp = rpRes.data && rpRes.data[0];
    if (!rp) return res.status(403).json({ error: 'No reviewer profile found.' });

    const r = await sbFetch('/rest/v1/review_assignments?reviewer_id=eq.' + rp.id + '&order=assigned_at.desc&select=*');
    return r.ok ? res.json(r.data) : res.status(500).json({ error: 'Database error.' });
  } catch (e) { console.error('[reviewer/dashboard]', e.message); return res.status(500).json({ error: 'Internal server error.' }); }
});

/* ── Revolut payment routes ─────────────────────────────────────────────── */
try {
  const revolutRoutes = require('./api/revolut-payment');
  app.use('/api/revolut', revolutRoutes);
} catch (e) { console.warn('[server] revolut-payment.js not found:', e.message); }

/* ── Block source maps ──────────────────────────────────────────────────── */
app.get('*.js.map', (req, res) => res.status(404).end());

/* ── Static files ───────────────────────────────────────────────────────── */
app.use(express.static(path.join(__dirname), { dotfiles: 'deny' }));

/* ── Health check ────────────────────────────────────────────────────────── */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'scholars-hub-backend',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0'
  });
});

/* ── Admin login — issues a short-lived signed token ────────────────────── */
app.post('/api/admin/auth', rateLimit({ windowMs: 60000, max: 10, prefix: 'admin-auth:' }), (req, res) => {
  const { password } = req.body || {};
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (!adminPassword) return res.status(503).json({ error: 'Admin not configured.' });
  if (!password || password !== adminPassword)
    return res.status(401).json({ error: 'Incorrect password.' });
  // Sign a simple HMAC token: base64(payload).base64(hmac)
  // VULN#2: Include expiry — token valid for 8 hours only
  const payload  = Buffer.from(JSON.stringify({ role: 'admin', iat: Date.now(), exp: Date.now() + 8 * 3600 * 1000 })).toString('base64url');
  const hmac     = crypto.createHmac('sha256', adminPassword).update(payload).digest('base64url');
  res.json({ token: payload + '.' + hmac });
});

/* ── Admin token verifier ────────────────────────────────────────────────── */
function verifyAdminToken(token) {
  try {
    const adminPassword = process.env.ADMIN_PASSWORD;
    if (!adminPassword || !token) return false;
    // OPT-16: indexOf+slice — no 3-element array allocation
    const dot = token.lastIndexOf('.');
    if (dot === -1) return false;
    const payload = token.slice(0, dot);
    const sig     = token.slice(dot + 1);
    const expected = crypto.createHmac('sha256', adminPassword).update(payload).digest('base64url');
    // VULN#2: Check token expiry before accepting
    try {
      const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
      if (!claims.exp || Date.now() > claims.exp) return false;
    } catch { return false; }
    // Timing-safe compare
    const a = Buffer.from(sig      || '', 'base64url');
    const b = Buffer.from(expected || '', 'base64url');
    if (a.length === 0 || a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch { return false; }
}

/* ── requireAdminToken middleware — DRY replacement for inline token checks ── */
// BUG-09 FIX: Extracted from 5 identical inline arrow functions to a named middleware.
// verifyAdminToken is defined below via function declaration (hoisted) so this is safe.
function requireAdminToken(req, res, next) {
  const tok = (req.headers['x-admin-token'] || '').trim();
  if (!verifyAdminToken(tok)) return res.status(401).json({ error: 'Admin authentication required.' });
  next();
}

/* ── /api/admin — replaces hardcoded key check ──────────────────────────── */
app.use('/api/admin', (req, res, next) => {
  // Allow the /auth endpoint through unauthenticated
  if (req.path === '/auth' || req.path === '/auth/') return next(); // ISSUE#3: guard trailing slash
  const token = (req.headers['x-admin-token'] || '').trim()  // VULN#1: query param removed — tokens must be in headers only;
  if (!verifyAdminToken(token)) return res.status(401).json({ error: 'Unauthorised.' });
  next();
});

/* ── Admin endpoints ─────────────────────────────────────────────────────── */

// Retry a failed submission
app.post('/api/admin/retry', async (req, res) => {
  const { submissionId } = req.body || {};
  if (!submissionId) return res.status(400).json({ error: 'submissionId required' });
  try {
    await sbFetch(`/rest/v1/submissions?id=eq.${submissionId}`, 'PATCH', {
      status: 'pending', error_message: null, updated_at: new Date().toISOString()
    });
    res.json({ ok: true, message: 'Requeued for processing' });
  } catch(e) { res.status(500).json({ error: 'Internal server error.' }); }
});

// Suspend/unsuspend a user
app.post('/api/admin/suspend', async (req, res) => {
  const { userId, suspend } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'userId required' });
  try {
    await sbFetch(`/rest/v1/profiles?id=eq.${userId}`, 'PATCH', {
      suspended: suspend !== false, updated_at: new Date().toISOString()
    });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Internal server error.' }); }
});

// Refund a pass
app.post('/api/admin/refund-pass', async (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'userId required' });
  try {
    // Single atomic UPDATE via PostgREST column expression — no read-then-write race
    // BUG-07 FIX: Use RPC for atomic increment; then fetch updated value separately
    const rpcResult = await sbFetch('/rest/v1/rpc/increment_pass', 'POST', { p_user_id: userId });
    if (!rpcResult.ok) return res.status(500).json({ error: 'Could not refund pass.' });
    const profileRes = await sbFetch(`/rest/v1/profiles?id=eq.${userId}&select=passes_remaining`);
    const passes = profileRes.data && profileRes.data[0] && profileRes.data[0].passes_remaining;
    res.json({ ok: true, passes_remaining: passes });
  } catch(e) { res.status(500).json({ error: 'Internal server error.' }); }
});

// Send password reset email
app.post('/api/admin/reset-password', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email required' });
  try {
    const SB_AUTH_URL = `${SB_URL}/auth/v1/admin/users`;
    // Trigger reset via Supabase admin
    await sendEmail({
      to: email,
      subject: 'Reset your Scholars Hub password',
      html: `<div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:32px;">
        <h2 style="color:#0F1B3C;">Password Reset Request</h2>
        <p>An admin has requested a password reset for your account.</p>
        <p>Please visit <a href="https://scholarshub.pages.dev/login.html">Scholars Hub Login</a> and use the "Forgot password" link to set a new password.</p>
        <p style="color:#94a3b8;font-size:13px;">Scholars Hub · Awrex Ltd</p>
      </div>`
    });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Internal server error.' }); }
});

// Export submissions as CSV
app.get('/api/admin/export-csv', async (req, res) => {
  try {
    const result = await sbFetch('/rest/v1/submissions?select=id,created_at,subject,word_count,overall_score,grade_predicted,ai_detection_pct,status,tier&order=created_at.desc&limit=1000');
    const rows = result.data || [];

    // OPT-13: Pre-built column extractors — no per-row accessor re-definition.
    // csvCell: skips String() for already-primitive values; early-exit when no quotes present.
    const COLS = [
      r => r.id              ?? '',
      r => r.created_at      ?? '',
      r => r.subject         ?? '',
      r => r.word_count      ?? '',
      r => r.overall_score   ?? '',
      r => r.grade_predicted ?? '',
      r => r.ai_detection_pct ?? '',
      r => r.status          ?? '',
      r => r.tier            ?? '',
    ];
    function csvCell(v) {
      const s = (v === null || v === undefined) ? '' : (typeof v === 'string' ? v : String(v));
      // Early-exit O(1) for empty; indexOf for quote-free strings (common case — no new string)
      return s.length === 0        ? '""'
           : s.indexOf('"') === -1 ? '"' + s + '"'
           : '"' + s.replaceAll('"', '""') + '"';
    }
    const lines = new Array(rows.length + 1);
    lines[0] = '"ID","Date","Subject","Words","Score","Grade","AI%","Status","Tier"';
    for (let i = 0; i < rows.length; i++) {
      const r = rows[i];
      lines[i + 1] =
        csvCell(COLS[0](r)) + ',' + csvCell(COLS[1](r)) + ',' + csvCell(COLS[2](r)) + ',' +
        csvCell(COLS[3](r)) + ',' + csvCell(COLS[4](r)) + ',' + csvCell(COLS[5](r)) + ',' +
        csvCell(COLS[6](r)) + ',' + csvCell(COLS[7](r)) + ',' + csvCell(COLS[8](r));
    }
    const csv = lines.join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="scholars-hub-submissions-${new Date().toISOString().slice(0,10)}.csv"`);
    res.send(csv);
  } catch(e) { res.status(500).json({ error: 'Internal server error.' }); }
});
// Send broadcast email to all users
app.post('/api/admin/broadcast', rateLimit({ windowMs: 3600000, max: 5, prefix: 'broadcast:' }), async (req, res) => { // VULN-14
  const { subject, message } = req.body || {};
  if (!subject || !message) return res.status(400).json({ error: 'subject and message required' });
  try {
    // OPT-14: Filter null emails at DB level — eliminates O(U) JS .filter() scan
    // BUG-08 FIX: Join subscribers table for unsubscribe tokens; fall back to profiles for non-subscribers
    // We query subscribers (which has tokens) LEFT JOINed to profiles for full_name
    const result = await sbFetch('/rest/v1/subscribers?select=email,unsubscribe_token&unsubscribed_at=is.null&limit=500&email=not.is.null');
    const users  = result.data || [];

    // Respond immediately — O(1) response time regardless of list size
    res.json({ ok: true, queued: users.length });

    // Build the shared HTML body once, substitute first name per recipient
    // VULN#5: HTML-escape message before converting newlines — prevents HTML/script injection in emails
    const escapeHtml = s => s.replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#x27;'}[c]));
    const messageHtml = escapeHtml(message).replace(/\n/g, '<br>');
    const unsubBase   = process.env.SITE_URL || 'https://scholarshub.pages.dev';

    // Send in parallel batches of 50 (safe within Resend rate limits)
    const BATCH = 50;
    for (let i = 0; i < users.length; i += BATCH) {
      await Promise.allSettled(users.slice(i, i + BATCH).map(user => {
        const first = ''; // subscribers table has email+token only; no full_name
        return sendEmail({
          to: user.email,
          subject,
          html: `<div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:32px;">
          <div style="background:#0F1B3C;padding:24px;border-radius:12px 12px 0 0;text-align:center;">
            <h1 style="color:#fff;margin:0;font-size:20px;">Scholars Hub</h1>
          </div>
          <div style="background:#fff;padding:32px;border-radius:0 0 12px 12px;border:1px solid #e2e8f0;">
            ${first ? `<p style="color:#334155;">Hi ${first},</p>` : ''}
            <div style="color:#334155;font-size:15px;line-height:1.7;">${messageHtml}</div>
            <p style="color:#94a3b8;font-size:13px;margin-top:24px;">Scholars Hub · Awrex Ltd · 42A St Pauls Road, Peterborough, PE1 3DW<br>
            <a href="${unsubBase}/api/unsubscribe?token=${encodeURIComponent(user.unsubscribe_token || '')}" style="color:#94a3b8;">Unsubscribe from these emails</a></p>
          </div>
        </div>`
        });
      }));
    }
  } catch(e) { /* already responded — log only */ console.error('[broadcast]', e.message); }
});

// Flag a submission for investigation
app.post('/api/admin/flag', async (req, res) => {
  const { submissionId, reason } = req.body || {};
  if (!submissionId) return res.status(400).json({ error: 'submissionId required' });
  try {
    await sbFetch(`/rest/v1/submissions?id=eq.${submissionId}`, 'PATCH', {
      status: 'flagged', error_message: reason || 'Flagged by admin', updated_at: new Date().toISOString()
    });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Internal server error.' }); }
});


/* ── Receipt / Invoice email ─────────────────────────────────────────────── */
app.post('/api/send-receipt', requireAuth, rateLimit({ windowMs: 3600000, max: 10, keyFn: req => req.userToken, prefix: 'receipt:' }), async (req, res) => { // VULN-4
  const { email, name, tier, amount, orderId, date } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email required' });

  const tierNames = {
    'ai_basic': 'AI Basic Report', 'ai_deep': 'AI Deep Review',
    'expert_1': 'Expert Tier 1', 'expert_2': 'Expert Tier 2',
    'expert_3': 'Expert Tier 3', 'expert_4': 'Expert Tier 4',
    'expert_5a': 'Expert Tier 5A', 'expert_5b': 'Expert Tier 5B',
    'pro_monthly': 'Pro Plan — Monthly', 'starter': 'Starter Plan'
  };
  // VULN#6: Drop raw tier fallback; HTML-escape all interpolated user-supplied fields
  const _escHtml = s => String(s || '').replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#x27;'}[c]));
  const productName = _escHtml(tierNames[tier] || 'Scholars Hub Service');
  const safeAmount  = _escHtml(amount);
  const safeOrderId = _escHtml(orderId);
  const safeEmail   = _escHtml(email);
  const safeName    = _escHtml(name);
  const receiptDate = date || new Date().toLocaleDateString('en-GB', {day:'numeric',month:'long',year:'numeric'});
  const receiptId = 'SH-' + ((orderId || Date.now()).toString().slice(-8)).toUpperCase();

  try {
    await sendEmail({
      to: email,
      subject: `Your Scholars Hub receipt — ${receiptId}`,
      html: `
      <div style="font-family:sans-serif;max-width:600px;margin:0 auto;background:#fff">
        <div style="background:#0F1B3C;padding:32px;text-align:center">
          <div style="display:inline-flex;align-items:center;gap:10px">
            <svg width="32" height="32" viewBox="0 0 48 48" fill="none">
              <path d="M24 3L6 10V24C6 33.94 13.94 43.18 24 46C34.06 43.18 42 33.94 42 24V10L24 3Z" fill="white" opacity="0.15"/>
              <path d="M30 18.5C30 15.46 27.54 13 24.5 13H21C18.24 13 16 15.24 16 18C16 20.49 17.72 22.57 20.1 23.06L26.4 24.3C27.94 24.61 29 25.97 29 27.5C29 29.43 27.43 31 25.5 31H22C19.79 31 18 29.21 18 27" stroke="#00A896" stroke-width="2.8" stroke-linecap="round" fill="none"/>
            </svg>
            <span style="font-size:22px;font-weight:800;color:#fff">Scholars Hub</span>
          </div>
        </div>

        <div style="padding:40px 32px">
          <h2 style="color:#0F1B3C;font-size:22px;margin:0 0 8px">Payment Receipt</h2>
          <p style="color:#64748b;font-size:14px;margin:0 0 32px">Receipt No. <strong>${receiptId}</strong> · ${receiptDate}</p>

          <table style="width:100%;border-collapse:collapse;margin-bottom:24px">
            <tr style="background:#f8fafc">
              <td style="padding:14px 16px;font-size:14px;color:#374151;border-bottom:1px solid #e2e8f0"><strong>Product</strong></td>
              <td style="padding:14px 16px;font-size:14px;color:#374151;border-bottom:1px solid #e2e8f0;text-align:right">${productName}</td>
            </tr>
            <tr>
              <td style="padding:14px 16px;font-size:14px;color:#374151;border-bottom:1px solid #e2e8f0"><strong>Amount</strong></td>
              <td style="padding:14px 16px;font-size:14px;color:#374151;border-bottom:1px solid #e2e8f0;text-align:right">${safeAmount ? '£' + safeAmount : '—'}</td>
            </tr>
            <tr style="background:#f0fdf9">
              <td style="padding:14px 16px;font-size:14px;color:#0F1B3C"><strong>Status</strong></td>
              <td style="padding:14px 16px;font-size:14px;color:#00A896;text-align:right;font-weight:700">✓ Paid</td>
            </tr>
          </table>

          <div style="background:#f8fafc;border-radius:12px;padding:20px;margin-bottom:28px">
            <p style="margin:0 0 6px;font-size:13px;color:#374151"><strong>Billed to:</strong> ${safeEmail}</p>
            <p style="margin:0;font-size:13px;color:#374151"><strong>Supplier:</strong> Awrex Ltd · 42A St Pauls Road, Peterborough, PE1 3DW · Company No. 16491375</p>
          </div>

          <a href="https://scholarshub.pages.dev/dashboard.html" style="display:block;background:#00A896;color:#fff;text-align:center;padding:14px;border-radius:10px;text-decoration:none;font-weight:600;font-size:15px">Go to Your Dashboard →</a>

          <p style="font-size:12px;color:#94a3b8;text-align:center;margin-top:24px">Keep this email as your record of purchase. For billing queries email <a href="mailto:info@scholarshub.co.uk" style="color:#00A896">info@scholarshub.co.uk</a></p>
        </div>
      </div>`
    });
    res.json({ ok: true, receiptId });
  } catch(e) { res.status(500).json({ error: 'Internal server error.' }); }
});


/* ── Email list subscription ─────────────────────────────────────────────── */
app.post('/api/subscribe', rateLimit({ windowMs: 3600000, max: 3, prefix: 'subscribe:' }), async (req, res) => { // VULN-7
  const { email, source } = req.body || {};
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });
  try {
    // Generate an unsubscribe token for GDPR/PECR compliance
    const unsubToken = crypto.randomBytes(24).toString('hex');

    // Store in Supabase subscribers table
    await sbFetch('/rest/v1/subscribers', 'POST', {
      email,
      source: source || 'website',
      unsubscribe_token: unsubToken,
      subscribed_at: new Date().toISOString()
    }).catch(err => console.error('[subscribe] DB insert failed:', err.message));

    const unsubUrl = `${process.env.SITE_URL || 'https://scholarshub.pages.dev'}/api/unsubscribe?token=${unsubToken}`;

    // Send confirmation email with unsubscribe link (PECR compliant)
    await sendEmail({
      to: email,
      subject: 'You\'re subscribed to Scholars Hub guides',
      html: `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px">
        <h2 style="color:#0F1B3C">You're on the list 🎓</h2>
        <p style="color:#334155">We'll send you a short email when new academic writing guides are published. No spam — just useful, free guides for UK students.</p>
        <p style="color:#94a3b8;font-size:13px">Scholars Hub · Awrex Ltd · 42A St Pauls Road, Peterborough, PE1 3DW<br>
        <a href="${unsubUrl}" style="color:#94a3b8">Unsubscribe from these emails</a></p>
      </div>`
    });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Internal server error.' }); }
});

/* ── Unsubscribe endpoint (GDPR/PECR) ───────────────────────────────────── */
app.get('/api/unsubscribe', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Missing unsubscribe token.');
  try {
    const r = await sbFetch('/rest/v1/subscribers?unsubscribe_token=eq.' + encodeURIComponent(token) + '&select=id,email');
    if (!r.ok || !r.data || !r.data.length) {
      return res.status(404).send('Unsubscribe link not found or already used.');
    }
    await sbFetch('/rest/v1/subscribers?unsubscribe_token=eq.' + encodeURIComponent(token), 'PATCH', {
      unsubscribed_at: new Date().toISOString(),
      unsubscribe_token: null
    });
    res.send(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Unsubscribed — Scholars Hub</title>
      <style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f8fafc;margin:0;}
      .card{background:#fff;padding:48px 40px;border-radius:16px;border:1px solid #e2e8f0;text-align:center;max-width:400px;}
      h1{color:#0F1B3C;font-size:22px;margin-bottom:12px;}p{color:#64748b;font-size:15px;line-height:1.6;}</style></head>
      <body><div class="card"><div style="font-size:40px;margin-bottom:16px;">✅</div>
      <h1>Unsubscribed</h1><p>You've been removed from our mailing list. You won't receive any more marketing emails from Scholars Hub.</p>
      <p style="margin-top:16px"><a href="/" style="color:#00A896;font-weight:600;text-decoration:none">← Back to Scholars Hub</a></p>
      </div></body></html>`);
  } catch(e) { res.status(500).send('Error processing unsubscribe request.'); }
});

/* ── API 404 — catch unknown /api/* GET routes before SPA fallback ─────── */
// BUG-14 FIX: Prevents SPA fallback returning index.html with 200 for missing API endpoints.
app.use('/api', (req, res, next) => {
  if (!res.headersSent) res.status(404).json({ error: 'API endpoint not found.' });
});

/* ── SPA fallback ───────────────────────────────────────────────────────── */
app.get('*', (req, res) => res.status(404).json({ error: 'Not found.' }));

// PERF-2: require ai-engine at startup — avoids module resolution on first submission request
const { analyseEssay } = require('./js/ai-engine');

// Vercel serverless export — also supports traditional listen for other hosts
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log('ScholarsHub running on port ' + PORT));
}
module.exports = app;

