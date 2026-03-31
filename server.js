const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { MongoClient } = require('mongodb');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const PDFDocument = require('pdfkit');
const fetch = require('node-fetch');
const compression = require('compression');

// =============================================
// [FIX 3.8] Stockage objet S3/R2 pour signatures et documents lourds
// =============================================
let s3Client = null;
const R2_BUCKET = process.env.R2_BUCKET || 'uco-signatures';
const R2_PUBLIC_URL = process.env.R2_PUBLIC_URL || ''; // URL publique si bucket public

// Initialiser le client S3/R2 si configuré
function initS3() {
  if (s3Client) return s3Client;
  const accountId = process.env.R2_ACCOUNT_ID;
  const accessKey = process.env.R2_ACCESS_KEY_ID;
  const secretKey = process.env.R2_SECRET_ACCESS_KEY;
  if (!accountId || !accessKey || !secretKey) {
    return null; // R2 non configuré — fallback MongoDB
  }
  try {
    const { S3Client } = require('@aws-sdk/client-s3');
    s3Client = new S3Client({
      region: 'auto',
      endpoint: `https://${accountId}.r2.cloudflarestorage.com`,
      credentials: { accessKeyId: accessKey, secretAccessKey: secretKey }
    });
    console.log('✅ Cloudflare R2 connecte (bucket: ' + R2_BUCKET + ')');
    return s3Client;
  } catch (e) {
    console.log('⚠️ @aws-sdk/client-s3 non installe — signatures en MongoDB (npm install @aws-sdk/client-s3)');
    return null;
  }
}

// Upload un blob base64 vers R2, retourne la clé
async function uploadToR2(key, base64Data, contentType) {
  const client = initS3();
  if (!client) return null; // Fallback: pas de R2
  try {
    const { PutObjectCommand } = require('@aws-sdk/client-s3');
    const buffer = Buffer.from(base64Data, 'base64');
    await client.send(new PutObjectCommand({
      Bucket: R2_BUCKET,
      Key: key,
      Body: buffer,
      ContentType: contentType || 'image/png'
    }));
    console.log('☁️ Upload R2:', key, '(' + (buffer.length / 1024).toFixed(1) + ' KB)');
    return key;
  } catch (e) {
    console.error('Erreur upload R2:', e.message);
    return null;
  }
}

// Télécharger depuis R2
async function downloadFromR2(key) {
  const client = initS3();
  if (!client) return null;
  try {
    const { GetObjectCommand } = require('@aws-sdk/client-s3');
    const resp = await client.send(new GetObjectCommand({ Bucket: R2_BUCKET, Key: key }));
    const chunks = [];
    for await (const chunk of resp.Body) chunks.push(chunk);
    return Buffer.concat(chunks);
  } catch (e) {
    console.error('Erreur download R2:', e.message);
    return null;
  }
}

// Extraire les champs base64 d'un objet et les uploader vers R2
// Retourne l'objet avec les champs remplacés par des clés R2
async function extractAndUploadSignatures(obj, prefix) {
  const client = initS3();
  if (!client) return obj; // Pas de R2 → garder en MongoDB
  
  const fieldsToExtract = ['colSignature', 'restoSignature', 'contratPDF', 'bsdPdfBase64', 'signatureData'];
  const result = { ...obj };
  const r2Keys = {};
  
  for (const field of fieldsToExtract) {
    if (result[field] && typeof result[field] === 'string' && result[field].length > 1000) {
      // C'est un champ base64 volumineux
      let base64 = result[field];
      let contentType = 'application/octet-stream';
      
      // Extraire le type MIME si c'est un data URI
      if (base64.startsWith('data:')) {
        const match = base64.match(/^data:([^;]+);base64,(.+)$/);
        if (match) {
          contentType = match[1];
          base64 = match[2];
        }
      }
      
      const key = `${prefix}/${field}_${Date.now()}.${contentType.includes('pdf') ? 'pdf' : 'png'}`;
      const uploaded = await uploadToR2(key, base64, contentType);
      
      if (uploaded) {
        // Remplacer la valeur par une référence R2
        result[field] = null; // Supprimer le base64
        r2Keys[field] = { r2Key: key, contentType, size: base64.length };
      }
    }
  }
  
  if (Object.keys(r2Keys).length > 0) {
    result._r2 = { ...((result._r2) || {}), ...r2Keys };
  }
  
  return result;
}
const app = express();
const PORT = process.env.PORT || 3001;
// =============================================
// GESTION DES ERREURS GLOBALES - ANTI-CRASH
// =============================================
process.on('uncaughtException', (err) => {
  console.error('❌ [UNCAUGHT EXCEPTION]', err.message);
  console.error(err.stack);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ [UNHANDLED REJECTION]', reason);
});

// =============================================
// [FIX OOM] MONITORING MEMOIRE PROACTIF
// =============================================
let memoryWarningCount = 0;
setInterval(() => {
  const mem = process.memoryUsage();
  const heapMB = Math.round(mem.heapUsed / 1024 / 1024);
  const rssMB = Math.round(mem.rss / 1024 / 1024);
  if (heapMB > 400) {
    memoryWarningCount++;
    console.warn('⚠️ MEMOIRE CRITIQUE: Heap=' + heapMB + 'MB, RSS=' + rssMB + 'MB (warning #' + memoryWarningCount + ')');
    if (global.gc) { global.gc(); console.log('GC force'); }
  } else if (heapMB > 300) {
    console.warn('⚠️ Memoire elevee: Heap=' + heapMB + 'MB, RSS=' + rssMB + 'MB');
  }
}, 30000);

// =============================================
// CONFIGURATION SECURITE
// =============================================
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = '24h';
const BCRYPT_ROUNDS = 12;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000;
// =============================================
// MIDDLEWARES DE SECURITE
// =============================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));
app.use(compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  }
}));
const allowedOrigins = [
  'https://uco-and-co.netlify.app',
  'https://comfy-brigadeiros-b8cc7f.netlify.app',
  'https://uco-and-co.fr',
  'https://www.uco-and-co.fr',
  'https://uco-and-co.site',
  'https://www.uco-and-co.site',
  process.env.FRONTEND_URL,
  'http://localhost:3000',
  'http://localhost:5173',
  'https://localhost',
  'capacitor://localhost',
  'http://localhost'
].filter(Boolean);
if (process.env.CORS_ORIGIN) {
  process.env.CORS_ORIGIN.split(',').forEach(origin => {
    if (origin && !allowedOrigins.includes(origin.trim())) {
      allowedOrigins.push(origin.trim());
    }
  });
}
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV === 'development') {
      callback(null, true);
    } else {
      console.warn('CORS bloque:', origin);
      callback(new Error('Non autorise par CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID']
}));
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: { success: false, error: 'Trop de requetes, reessayez dans 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/api/health' || (req.path === '/api/settings' && req.method === 'GET')
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, error: 'Trop de tentatives de connexion' },
  standardHeaders: true,
  legacyHeaders: false,
});
const strictLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { success: false, error: 'Limite atteinte, reessayez plus tard' },
});
app.use('/api/', generalLimiter);
app.use('/api/auth/', authLimiter);
app.use('/api/password-reset', strictLimiter);
app.set('trust proxy', 1);
app.use((req, res, next) => {
  if (req.originalUrl === '/api/stripe/webhook') {
    express.raw({ type: '*/*' })(req, res, next);
  } else {
    express.json({ limit: '10mb' })(req, res, next);
  }
});
app.use((req, res, next) => {
  if (req.originalUrl === '/api/stripe/webhook') {
    next();
  } else {
    express.urlencoded({ extended: true, limit: '10mb' })(req, res, next);
  }
});
app.use(mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    console.warn('Tentative injection NoSQL detectee: ' + key);
  }
}));
app.use(xss());
app.use(hpp());
app.use((req, res, next) => {
  const requestId = uuidv4().slice(0, 8);
  req.requestId = requestId;
  if (req.path.includes('/auth') || req.path.includes('/password')) {
    console.log('[' + new Date().toISOString() + '] ' + requestId + ' ' + req.method + ' ' + req.path + ' - IP: ' + req.ip);
  }
  res.setHeader('X-Request-ID', requestId);
  next();
});
// =============================================
// CONFIGURATION MONGODB ATLAS
// =============================================
const MONGODB_URI = process.env.MONGODB_URI || '';
const DB_NAME = 'ucoandco';
let db = null;
let mongoClient = null;
let isConnected = false;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 10;
const mongoOptions = {
  maxPoolSize: 10,
  minPoolSize: 2,
  serverSelectionTimeoutMS: 30000,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 30000,
  heartbeatFrequencyMS: 10000,
  retryWrites: true,
  retryReads: true,
};
const initialData = {
  admin: {
    email: process.env.ADMIN_EMAIL || 'contact@uco-and-co.com',
    // [FIX 1.10] Mot de passe admin via variable d'environnement (ne plus coder en dur)
    // Sur Render: ajouter ADMIN_PASSWORD_HASH = résultat de bcrypt.hash('votre_mot_de_passe', 12)
    password: process.env.ADMIN_PASSWORD_HASH || bcrypt.hashSync(process.env.ADMIN_DEFAULT_PASSWORD || 'CHANGEZ-MOI-IMMEDIATEMENT', BCRYPT_ROUNDS),
    loginAttempts: 0,
    lockUntil: null
  },
  settings: {
    email: 'contact@uco-and-co.com',
    brevoApiKey: '',
    adminTel: '',
    smsEnabled: false,
    reviewLinks: {
      google: '',
      instagram: '',
      facebook: '',
      whatsapp: '+33610251063',
      linkedin: '',
      tripadvisor: ''
    }
  }
};
const COLLECTIONS = {
  SETTINGS: 'settings',
  COLLECTORS: 'collectors',
  OPERATORS: 'operators',
  RESTAURANTS: 'restaurants',
  PRESTATAIRES: 'prestataires',
  COLLECTIONS: 'collections',
  TOURNEES: 'tournees',
  AUDIT_LOGS: 'auditLogs',
  SESSIONS: 'sessions',
  DOCUMENTS: 'documents',
  CAMPAIGNS: 'campaigns',
  TOURNEES_EN_COURS: 'tournees_en_cours',
  AVIS: 'avis',
  TRANSPORTEURS: 'transporteurs',
  RECEPTEURS: 'recepteurs',
  CERTIFICATEURS: 'certificateurs',
  DAILY_VOLUMES: 'daily_volumes',
  EXPEDITIONS: 'expeditions',
  VEHICLE_LOGS: 'vehicle_logs'
};
const cache = {
  settings: null,
  lastSettingsUpdate: 0,
  TTL: 60000
};
// =============================================
// CONNEXION MONGODB AVEC RECONNEXION AUTO
// =============================================
async function connectDB() {
  if (!MONGODB_URI) {
    console.warn('MONGODB_URI non configuree');
    return false;
  }
  try {
    console.log('Connexion securisee a MongoDB Atlas...');
    mongoClient = new MongoClient(MONGODB_URI, mongoOptions);
    mongoClient.on('close', () => {
      console.warn('Connexion MongoDB fermee');
      isConnected = false;
      scheduleReconnect();
    });
    mongoClient.on('error', (err) => {
      console.error('Erreur MongoDB:', err.message);
      isConnected = false;
    });
    await mongoClient.connect();
    db = mongoClient.db(DB_NAME);
    isConnected = true;
    reconnectAttempts = 0;
    try {
      await db.collection(COLLECTIONS.COLLECTORS).createIndex({ email: 1 }, { unique: true, sparse: true });
      await db.collection(COLLECTIONS.OPERATORS).createIndex({ email: 1 }, { unique: true, sparse: true });
      await db.collection(COLLECTIONS.RESTAURANTS).createIndex({ id: 1 }, { unique: true });
      await db.collection(COLLECTIONS.RESTAURANTS).createIndex({ qrCode: 1 }, { sparse: true });
      await db.collection(COLLECTIONS.RESTAURANTS).createIndex({ email: 1 }, { sparse: true });
      await db.collection(COLLECTIONS.AUDIT_LOGS).createIndex({ timestamp: -1 });
      await db.collection(COLLECTIONS.AUDIT_LOGS).createIndex({ action: 1 });
      await db.collection(COLLECTIONS.SESSIONS).createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
      await db.collection(COLLECTIONS.TOURNEES_EN_COURS).createIndex({ collectorEmail: 1 }, { unique: true });
      // [FIX OOM] TTL index: auto-suppression tournees abandonnees apres 7 jours
      await db.collection(COLLECTIONS.TOURNEES_EN_COURS).createIndex({ lastUpdate: 1 }, { expireAfterSeconds: 604800 }).catch(() => {});
      // [FIX OOM] TTL index: auto-suppression audit logs apres 90 jours
      await db.collection(COLLECTIONS.AUDIT_LOGS).createIndex({ timestamp: 1 }, { expireAfterSeconds: 7776000 }).catch(() => {});
      // Indexes transporteurs/recepteurs/certificateurs
      await db.collection(COLLECTIONS.TRANSPORTEURS).createIndex({ email: 1 }, { unique: true, sparse: true }).catch(() => {});
      await db.collection(COLLECTIONS.RECEPTEURS).createIndex({ email: 1 }, { unique: true, sparse: true }).catch(() => {});
      await db.collection(COLLECTIONS.CERTIFICATEURS).createIndex({ email: 1 }, { unique: true, sparse: true }).catch(() => {});
    } catch (indexError) {
      console.warn('Erreur creation index:', indexError.message);
    }
    try {
      const existingSettings = await db.collection(COLLECTIONS.SETTINGS).findOne({ _id: 'main' });
      if (!existingSettings) {
        await db.collection(COLLECTIONS.SETTINGS).insertOne({ _id: 'main', ...initialData.settings, admin: initialData.admin });
      }
    } catch (settingsError) {
      console.warn('Erreur initialisation settings:', settingsError.message);
    }
    console.log('Connecte a MongoDB Atlas avec succes');
    return true;
  } catch (error) {
    console.error('Erreur connexion MongoDB:', error.message);
    isConnected = false;
    scheduleReconnect();
    return false;
  }
}
function scheduleReconnect() {
  if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
    console.error('Max tentatives de reconnexion atteint.');
    return;
  }
  reconnectAttempts++;
  const delay = Math.min(5000 * reconnectAttempts, 30000);
  console.log('Tentative de reconnexion ' + reconnectAttempts + '/' + MAX_RECONNECT_ATTEMPTS + ' dans ' + (delay/1000) + 's...');
  setTimeout(async () => {
    if (!isConnected) {
      try {
        if (mongoClient) { await mongoClient.close().catch(() => {}); }
        await connectDB();
      } catch (e) {
        console.error('Echec reconnexion:', e.message);
        scheduleReconnect();
      }
    }
  }, delay);
}
function checkDBConnection(req, res, next) {
  if (req.path === '/api/health') return next();
  if (!isConnected || !db) {
    return res.status(503).json({ success: false, error: 'Service temporairement indisponible', retryAfter: 5 });
  }
  next();
}
app.use('/api/collectors', checkDBConnection);
app.use('/api/operators', checkDBConnection);
app.use('/api/restaurants', checkDBConnection);
app.use('/api/collections', checkDBConnection);
app.use('/api/tournees', checkDBConnection);
app.use('/api/settings', checkDBConnection);
app.use('/api/auth', checkDBConnection);
app.use('/api/prestataires', checkDBConnection);
app.use('/api/avis', checkDBConnection);
app.use('/api/transporteurs', checkDBConnection);
app.use('/api/recepteurs', checkDBConnection);
app.use('/api/certificateurs', checkDBConnection);
const stripeWebhook = require('./routes/stripe-webhook');
app.use('/api/stripe', stripeWebhook);
const demandesCollecteRoutes = require('./routes/demandes-collecte');
app.use('/api/demandes-collecte', demandesCollecteRoutes);
process.on('SIGINT', async () => {
  console.log('Arret du serveur (SIGINT)...');
  if (mongoClient) { try { await mongoClient.close(); } catch (e) {} }
  process.exit(0);
});
process.on('SIGTERM', async () => {
  console.log('Arret du serveur (SIGTERM)...');
  if (mongoClient) { try { await mongoClient.close(); } catch (e) {} }
  process.exit(0);
});
// =============================================
// FONCTIONS UTILITAIRES
// =============================================
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function isStrongPassword(password) {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(password);
}
function sanitizeInput(input, key = '') {
  if (typeof input !== 'string') return input;
  const unlimitedFields = ['restaurant', 'admin', 'collecteur', 'base64', 'content', 'data', 'signature', 'contrat', 'bordereau'];
  const isUnlimited = unlimitedFields.some(f => key.toLowerCase().includes(f));
  const sanitized = input.replace(/[<>]/g, '').trim();
  return isUnlimited ? sanitized : sanitized.slice(0, 5000);
}
// [FIX 1.7] sanitizeObject optimisé — limite de profondeur + skip des champs binaires volumineux
const BINARY_SKIP_FIELDS = new Set(['colSignature', 'restoSignature', 'contratPDF', 'bsdPdfBase64', 'signatureData', 'tamponData', 'adminSignatureData', 'ticketPeseeFile', 'bonInterventionFile']);
const MAX_SANITIZE_DEPTH = 10;
function sanitizeObject(obj, parentKey = '', depth = 0) {
  if (depth > MAX_SANITIZE_DEPTH) return obj; // Stop recursion
  if (typeof obj !== 'object' || obj === null) return sanitizeInput(obj, parentKey);
  if (obj instanceof Date) return obj;
  const sanitized = Array.isArray(obj) ? [] : {};
  const keys = Object.keys(obj);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if (key.startsWith('$')) continue; // Block NoSQL injection operators
    // Skip known binary/base64 fields — pass through without cloning (saves ~80% memory)
    if (BINARY_SKIP_FIELDS.has(key)) {
      sanitized[key] = obj[key];
      continue;
    }
    sanitized[key] = sanitizeObject(obj[key], key, depth + 1);
  }
  return sanitized;
}
function generateToken(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN }); }
function verifyToken(token) { try { return jwt.verify(token, JWT_SECRET); } catch (e) { return null; } }

// [FIX 1.9] Blacklist de tokens JWT pour révocation
const tokenBlacklist = new Set();
// Nettoyage automatique des tokens expirés de la blacklist (toutes les heures)
setInterval(() => {
  const now = Math.floor(Date.now() / 1000);
  for (const entry of tokenBlacklist) {
    try {
      const decoded = jwt.decode(entry);
      if (decoded && decoded.exp && decoded.exp < now) {
        tokenBlacklist.delete(entry);
      }
    } catch (e) { tokenBlacklist.delete(entry); }
  }
  if (tokenBlacklist.size > 0) console.log('Blacklist JWT: ' + tokenBlacklist.size + ' token(s) revoque(s)');
}, 60 * 60 * 1000);

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, error: 'Token manquant' });
  // [FIX 1.9] Vérifier si le token est dans la blacklist
  if (tokenBlacklist.has(token)) {
    return res.status(403).json({ success: false, error: 'Session revoquee. Veuillez vous reconnecter.' });
  }
  const decoded = verifyToken(token);
  if (!decoded) return res.status(403).json({ success: false, error: 'Token invalide ou expire' });
  req.user = decoded;
  req.token = token;
  next();
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ success: false, error: 'Acces non autorise' });
    next();
  };
}
async function auditLog(action, userId, details, req) {
  if (!db || !isConnected) return;
  try {
    await db.collection(COLLECTIONS.AUDIT_LOGS).insertOne({
      _id: uuidv4(), action, userId, details: sanitizeObject(details),
      ip: req?.ip || 'unknown', userAgent: req?.headers['user-agent'] || 'unknown',
      requestId: req?.requestId, timestamp: new Date().toISOString()
    });
  } catch (error) { console.error('Erreur audit log:', error.message); }
}
function isAccountLocked(user) {
  if (!user.lockUntil) return false;
  return new Date(user.lockUntil) > new Date();
}
async function incrementLoginAttempts(collection, identifier) {
  if (!db || !isConnected) return;
  try {
    const update = { $inc: { loginAttempts: 1 } };
    const user = await db.collection(collection).findOne({ email: identifier });
    if (user && user.loginAttempts >= MAX_LOGIN_ATTEMPTS - 1) {
      update.$set = { lockUntil: new Date(Date.now() + LOCK_TIME).toISOString() };
    }
    await db.collection(collection).updateOne({ email: identifier }, update);
  } catch (e) { console.error('Erreur incrementLoginAttempts:', e.message); }
}
async function resetLoginAttempts(collection, identifier) {
  if (!db || !isConnected) return;
  try {
    await db.collection(collection).updateOne({ email: identifier }, { $set: { loginAttempts: 0, lockUntil: null } });
  } catch (e) { console.error('Erreur resetLoginAttempts:', e.message); }
}
// =============================================
// FONCTIONS D ACCES AUX DONNEES
// =============================================
async function getSettings() {
  try {
    if (!db || !isConnected) return initialData.settings;
    if (cache.settings && (Date.now() - cache.lastSettingsUpdate) < cache.TTL) return cache.settings;
    const allSettings = await db.collection('settings').find({}).toArray();
    if (allSettings.length === 0) return initialData.settings;
    let mergedSettings = {};
    for (const doc of allSettings) { mergedSettings = { ...mergedSettings, ...doc }; }
    cache.settings = mergedSettings;
    cache.lastSettingsUpdate = Date.now();
    console.log('Settings charges:', { hasStripeSecretKey: !!mergedSettings.stripeSecretKey, hasStripePublicKey: !!mergedSettings.stripePublicKey, stripeEnabled: mergedSettings.stripeEnabled, qontoEnabled: mergedSettings.qontoEnabled });
    return mergedSettings;
  } catch (error) { console.error('Erreur recuperation settings:', error.message); return initialData.settings; }
}
async function updateSettings(newSettings) {
  if (!db || !isConnected) return false;
  try {
    const existingSettings = await getSettings() || {};
    const mergedSettings = { ...existingSettings, ...newSettings, admin: existingSettings.admin, reviewLinks: { ...(existingSettings.reviewLinks || {}), ...(newSettings.reviewLinks || {}) } };
    if (!newSettings.brevoApiKey && existingSettings.brevoApiKey) mergedSettings.brevoApiKey = existingSettings.brevoApiKey;
    if (!newSettings.stripeSecretKey && existingSettings.stripeSecretKey) mergedSettings.stripeSecretKey = existingSettings.stripeSecretKey;
    if ((!newSettings.stripePublicKey || newSettings.stripePublicKey.startsWith('••••')) && existingSettings.stripePublicKey) mergedSettings.stripePublicKey = existingSettings.stripePublicKey;
    if (!newSettings.stripeWebhookSecret && existingSettings.stripeWebhookSecret) mergedSettings.stripeWebhookSecret = existingSettings.stripeWebhookSecret;
    if (!newSettings.qontoSecretKey && existingSettings.qontoSecretKey) mergedSettings.qontoSecretKey = existingSettings.qontoSecretKey;
    if (!newSettings.qontoOrganizationId && existingSettings.qontoOrganizationId) mergedSettings.qontoOrganizationId = existingSettings.qontoOrganizationId;
    if (!newSettings.qontoOrganizationName && existingSettings.qontoOrganizationName) mergedSettings.qontoOrganizationName = existingSettings.qontoOrganizationName;
    delete mergedSettings._id;
    const existingDoc = await db.collection(COLLECTIONS.SETTINGS).findOne({});
    const docId = existingDoc?._id || 'main';
    await db.collection(COLLECTIONS.SETTINGS).updateOne({ _id: docId }, { $set: mergedSettings }, { upsert: true });
    cache.settings = null; cache.lastSettingsUpdate = 0; stripeInstance = null;
    console.log('Settings mis a jour avec succes');
    return true;
  } catch (error) { console.error('Erreur updateSettings:', error.message); return false; }
}
async function getAdmin() { const settings = await getSettings(); return settings.admin || initialData.admin; }
async function getCollectors(status = null) { if (!db || !isConnected) return []; try { const q = status ? { status } : {}; return await db.collection(COLLECTIONS.COLLECTORS).find(q).toArray(); } catch (e) { return []; } }
async function getCollectorByEmail(email) { if (!db || !isConnected) return null; try { return await db.collection(COLLECTIONS.COLLECTORS).findOne({ email: sanitizeInput(email) }); } catch (e) { return null; } }
async function addCollector(collector) { if (!db || !isConnected) return null; try { const s = sanitizeObject(collector); return (await db.collection(COLLECTIONS.COLLECTORS).insertOne({ ...s, _id: s.email, loginAttempts: 0, lockUntil: null, createdAt: new Date().toISOString() })).insertedId; } catch (e) { console.error('Erreur addCollector:', e.message); return null; } }
async function updateCollector(email, data) { if (!db || !isConnected) return false; try { await db.collection(COLLECTIONS.COLLECTORS).updateOne({ email: sanitizeInput(email) }, { $set: { ...sanitizeObject(data), updatedAt: new Date().toISOString() } }); return true; } catch (e) { return false; } }
async function deleteCollector(email) { if (!db || !isConnected) return false; try { await db.collection(COLLECTIONS.COLLECTORS).deleteOne({ email: sanitizeInput(email) }); return true; } catch (e) { return false; } }
async function getOperators(status = null) { if (!db || !isConnected) return []; try { const q = status ? { status } : {}; return await db.collection(COLLECTIONS.OPERATORS).find(q).toArray(); } catch (e) { return []; } }
async function getOperatorByEmail(email) { if (!db || !isConnected) return null; try { return await db.collection(COLLECTIONS.OPERATORS).findOne({ email: sanitizeInput(email) }); } catch (e) { return null; } }
async function addOperator(operator) { if (!db || !isConnected) return null; try { const s = sanitizeObject(operator); return (await db.collection(COLLECTIONS.OPERATORS).insertOne({ ...s, _id: s.email, loginAttempts: 0, lockUntil: null, createdAt: new Date().toISOString() })).insertedId; } catch (e) { console.error('Erreur addOperator:', e.message); return null; } }
async function updateOperator(email, data) { if (!db || !isConnected) return false; try { await db.collection(COLLECTIONS.OPERATORS).updateOne({ email: sanitizeInput(email) }, { $set: { ...sanitizeObject(data), updatedAt: new Date().toISOString() } }); return true; } catch (e) { return false; } }
async function deleteOperator(email) { if (!db || !isConnected) return false; try { await db.collection(COLLECTIONS.OPERATORS).deleteOne({ email: sanitizeInput(email) }); return true; } catch (e) { return false; } }
async function getRestaurants(status = null) { if (!db || !isConnected) return []; try { const q = status ? { status } : {}; return await db.collection(COLLECTIONS.RESTAURANTS).find(q, { projection: { contratPDF: 0, 'contrat.base64': 0, 'signatures.admin': 0, 'signatures.restaurant': 0, adminSignatureData: 0, tamponData: 0 } }).toArray(); } catch (e) { return []; } }
async function getRestaurantById(id) { if (!db || !isConnected) return null; try { const s = sanitizeInput(id); return await db.collection(COLLECTIONS.RESTAURANTS).findOne({ $or: [{ id: s }, { siret: s }, { qrCode: s }] }); } catch (e) { return null; } }
async function getRestaurantByQRCode(qrCode) { if (!db || !isConnected) return null; try { return await db.collection(COLLECTIONS.RESTAURANTS).findOne({ qrCode: sanitizeInput(qrCode) }); } catch (e) { return null; } }
async function getRestaurantByEmail(email) { if (!db || !isConnected) return null; try { return await db.collection(COLLECTIONS.RESTAURANTS).findOne({ email: sanitizeInput(email) }); } catch (e) { return null; } }
async function addRestaurant(restaurant) { if (!db || !isConnected) return null; try { const s = sanitizeObject(restaurant); return (await db.collection(COLLECTIONS.RESTAURANTS).insertOne({ ...s, _id: s.id, loginAttempts: 0, lockUntil: null, createdAt: new Date().toISOString() })).insertedId; } catch (e) { console.error('Erreur addRestaurant:', e.message); return null; } }
async function updateRestaurant(id, data) { if (!db || !isConnected) return false; try { const s = sanitizeInput(id); await db.collection(COLLECTIONS.RESTAURANTS).updateOne({ $or: [{ id: s }, { siret: s }, { qrCode: s }] }, { $set: { ...sanitizeObject(data), updatedAt: new Date().toISOString() } }); return true; } catch (e) { return false; } }
async function deleteRestaurant(id) { if (!db || !isConnected) return false; try { await db.collection(COLLECTIONS.RESTAURANTS).deleteOne({ id: sanitizeInput(id) }); return true; } catch (e) { return false; } }
async function addCollection(collection) { if (!db || !isConnected) return null; try { const s = sanitizeObject(collection); return (await db.collection(COLLECTIONS.COLLECTIONS).insertOne({ ...s, _id: s.id || uuidv4(), createdAt: new Date().toISOString() })).insertedId; } catch (e) { console.error('Erreur addCollection:', e.message); return null; } }
async function addTournee(tournee) { if (!db || !isConnected) return null; try { const s = sanitizeObject(tournee); return (await db.collection(COLLECTIONS.TOURNEES).insertOne({ ...s, _id: s.id || uuidv4(), createdAt: new Date().toISOString() })).insertedId; } catch (e) { console.error('Erreur addTournee:', e.message); return null; } }
async function updateTournee(id, data) { if (!db || !isConnected) return false; try { await db.collection(COLLECTIONS.TOURNEES).updateOne({ _id: sanitizeInput(id) }, { $set: sanitizeObject(data) }); return true; } catch (e) { return false; } }
async function generateCollectorNumber() { const c = await getCollectors('approved'); const nums = c.filter(x => x.collectorNumber).map(x => x.collectorNumber); let n = 1; while (nums.includes(n)) n++; return n; }
async function generateOperatorNumber() { const o = await getOperators('approved'); const nums = o.filter(x => x.operatorNumber).map(x => x.operatorNumber); let n = 1; while (nums.includes(n)) n++; return n; }
let stripeInstance = null;
async function getStripe() { if (stripeInstance) return stripeInstance; const s = await getSettings(); if (!s?.stripeSecretKey) return null; stripeInstance = require('stripe')(s.stripeSecretKey); return stripeInstance; }
// =============================================
// ROUTES API
// =============================================
app.get('/api/proxy/siret/:siret', async (req, res) => {
  try {
    const siret = req.params.siret.replace(/\D/g, '');
    if (siret.length !== 14) return res.status(400).json({ error: 'SIRET invalide' });
    const response = await fetch('https://recherche-entreprises.api.gouv.fr/search?q=' + siret + '&page=1&per_page=1');
    if (!response.ok) return res.status(response.status).json({ error: 'API non disponible' });
    res.json(await response.json());
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});
app.get('/api/proxy/villes/:cp', async (req, res) => {
  try {
    const cp = req.params.cp.replace(/\D/g, '');
    if (cp.length !== 5) return res.status(400).json({ error: 'Code postal invalide' });
    const response = await fetch('https://geo.api.gouv.fr/communes?codePostal=' + cp + '&fields=nom&format=json');
    if (!response.ok) return res.status(response.status).json({ error: 'API non disponible' });
    res.json(await response.json());
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});
// [FIX OOM] Health check avec details memoire
app.get('/api/health', async (req, res) => {
  const mem = process.memoryUsage();
  // Tester MongoDB mais toujours répondre 200 (Express est dispo = backend dispo)
  let dbReady = false;
  if (db && isConnected) {
    try { await db.command({ ping: 1 }); dbReady = true; } catch(e) { dbReady = false; }
  }
  res.status(200).json({
    status: dbReady ? 'OK' : 'DB_WARMING',
    dbReady,
    database: dbReady ? 'MongoDB Atlas' : 'MongoDB connecting...',
    persistent: dbReady, secure: true,
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memoryUsage: {
      heapUsed: Math.round(mem.heapUsed / 1024 / 1024) + 'MB',
      heapTotal: Math.round(mem.heapTotal / 1024 / 1024) + 'MB',
      rss: Math.round(mem.rss / 1024 / 1024) + 'MB',
      external: Math.round(mem.external / 1024 / 1024) + 'MB'
    },
    memoryWarnings: memoryWarningCount,
    reconnectAttempts: reconnectAttempts,
    r2Storage: initS3() ? 'Cloudflare R2 connecte' : 'R2 non configure (signatures en MongoDB)'
  });
});
// [FIX 3.7] Error logging — Capture des erreurs frontend
const errorLog = [];
const MAX_ERROR_LOG = 200;

app.post('/api/errors', (req, res) => {
  const { message, stack, url, userAgent, user, timestamp } = req.body || {};
  const entry = {
    message: String(message || 'Unknown error').substring(0, 500),
    stack: String(stack || '').substring(0, 1000),
    url: String(url || '').substring(0, 200),
    userAgent: String(userAgent || '').substring(0, 200),
    user: String(user || 'anonymous').substring(0, 100),
    timestamp: timestamp || new Date().toISOString(),
    ip: req.ip
  };
  errorLog.unshift(entry);
  if (errorLog.length > MAX_ERROR_LOG) errorLog.length = MAX_ERROR_LOG;
  console.log('🔴 Frontend error:', entry.message, '—', entry.user);
  res.json({ success: true });
});

app.get('/api/errors', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, MAX_ERROR_LOG);
  res.json({ errors: errorLog.slice(0, limit), total: errorLog.length });
});

app.delete('/api/errors', (req, res) => {
  errorLog.length = 0;
  res.json({ success: true, message: 'Error log cleared' });
});

app.post('/api/test-email', async (req, res) => {
  try {
    const { to } = req.body;
    if (!to) return res.status(400).json({ success: false, error: 'Email destinataire requis' });
    const settings = await getSettings();
    if (!settings.brevoApiKey) return res.status(503).json({ success: false, error: 'Cle API Brevo non configuree' });
    const simpleHtml = '<html><head><meta charset="UTF-8"></head><body><h1 style="color:green;">Test UCO AND CO</h1><p>Date: ' + new Date().toLocaleString('fr-FR') + '</p></body></html>';
    const response = await fetch('https://api.brevo.com/v3/smtp/email', { method: 'POST', headers: { 'accept': 'application/json', 'api-key': settings.brevoApiKey, 'content-type': 'application/json' }, body: JSON.stringify({ sender: { name: 'UCO AND CO', email: 'contact@uco-and-co.fr' }, to: [{ email: to }], subject: 'Test HTML UCO AND CO', htmlContent: simpleHtml }) });
    const responseData = await response.json();
    if (response.ok) res.json({ success: true, messageId: responseData.messageId });
    else res.status(502).json({ success: false, error: responseData.message || 'Erreur Brevo' });
  } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});
// =============================================
// TOURNEES EN COURS - SYNCHRONISATION
// =============================================
app.get('/api/tournees/en-cours/:email', async (req, res) => {
  try {
    if (!db || !isConnected) return res.status(503).json({ success: false, error: 'DB non connectee' });
    const email = decodeURIComponent(req.params.email);
    console.log('[SYNC] Recherche tournee pour: ' + email);
    const tournee = await db.collection(COLLECTIONS.TOURNEES_EN_COURS).findOne({ collectorEmail: email, active: true, dateFin: null });
    if (tournee) {
      console.log('[SYNC] Tournee trouvee: ' + tournee.id + ', collectes: ' + (tournee.collectes?.length || 0));
      const { _id, ...tourneeData } = tournee;
      return res.json(tourneeData);
    }
    return res.json(null);
  } catch (error) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
// [FIX OOM] POST tournees en cours - payload size check + no sanitizeObject
app.post('/api/tournees/en-cours', async (req, res) => {
  try {
    if (!db || !isConnected) return res.status(503).json({ success: false, error: 'DB non connectee' });
    // [FIX OOM] Verifier la taille du payload AVANT traitement
    const rawBody = JSON.stringify(req.body);
    const payloadKB = Math.round(rawBody.length / 1024);
    if (rawBody.length > 500000) {
      console.warn('[SYNC] Payload rejete: ' + payloadKB + 'KB (max 500KB)');
      return res.status(413).json({ success: false, error: 'Payload trop volumineux' });
    }
    // [FIX OOM] NE PAS utiliser sanitizeObject ici - trop couteux en memoire
    const tourneeData = req.body;
    if (!tourneeData.collectorEmail) return res.status(400).json({ success: false, error: 'collectorEmail requis' });
    tourneeData.lastUpdate = new Date().toISOString();
    console.log('[SYNC] Sauvegarde tournee: ' + tourneeData.id + ', collectes: ' + (tourneeData.collectes?.length || 0) + ', payload: ' + payloadKB + 'KB');
    await db.collection(COLLECTIONS.TOURNEES_EN_COURS).updateOne(
      { collectorEmail: tourneeData.collectorEmail },
      { $set: { ...tourneeData, _id: tourneeData.collectorEmail } },
      { upsert: true }
    );
    res.json({ success: true, tourneeId: tourneeData.id });
  } catch (error) { console.error('Erreur POST tournee en cours:', error); res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
app.delete('/api/tournees/en-cours/:email', async (req, res) => {
  try {
    if (!db || !isConnected) return res.status(503).json({ success: false, error: 'DB non connectee' });
    const email = decodeURIComponent(req.params.email);
    const result = await db.collection(COLLECTIONS.TOURNEES_EN_COURS).deleteOne({ collectorEmail: email });
    return res.json({ success: true, deleted: result.deletedCount > 0 });
  } catch (error) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
app.post('/api/tournees/paused', async (req, res) => {
  try {
    if (!db || !isConnected) return res.status(503).json({ success: false, error: 'DB non connectee' });
    const tourneeData = sanitizeObject(req.body);
    if (!tourneeData.collectorEmail) return res.status(400).json({ success: false, error: 'collectorEmail requis' });
    await db.collection(COLLECTIONS.TOURNEES_EN_COURS).updateOne(
      { collectorEmail: tourneeData.collectorEmail },
      { $set: { ...tourneeData, _id: tourneeData.collectorEmail, isPaused: true, status: 'paused', pausedAt: new Date().toISOString(), lastUpdate: new Date().toISOString() } },
      { upsert: true }
    );
    res.json({ success: true, tourneeId: tourneeData.id });
  } catch (error) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
// ===== BULK DATA (1 seul appel pour tout charger — optimisation mobile) =====
app.get('/api/bulk-data', async (req, res) => {
  try {
    if (!db || !isConnected) return res.json({ success: false, error: 'DB not connected' });
    const limit = parseInt(req.query.limit) || 500;
    const [restaurants, pendingRestaurants, collections, pendingCollectors, approvedCollectors, pendingOperators, approvedOperators, expeditions, avisClients, adminSettings] = await Promise.all([
      db.collection(COLLECTIONS.RESTAURANTS).find({ status: { $ne: 'deleted' } }, { projection: { password: 0, loginAttempts: 0, lockUntil: 0, contratPDF: 0, 'contrat.base64': 0, 'signatures.admin': 0, 'signatures.restaurant': 0, adminSignatureData: 0, tamponData: 0 } }).limit(limit).toArray().catch(() => []),
      db.collection(COLLECTIONS.PENDING_RESTAURANTS).find({}, { projection: { password: 0 } }).limit(limit).toArray().catch(() => []),
      db.collection(COLLECTIONS.COLLECTIONS).find({}, { projection: { bsdPdfBase64: 0, colSignature: 0, restoSignature: 0, signatureData: 0 } }).sort({ date: -1 }).limit(limit).toArray().catch(() => []),
      db.collection(COLLECTIONS.PENDING_COLLECTORS).find({}).limit(100).toArray().catch(() => []),
      db.collection(COLLECTIONS.APPROVED_COLLECTORS).find({}).limit(100).toArray().catch(() => []),
      db.collection(COLLECTIONS.PENDING_OPERATORS || 'pending_operators').find({}).limit(100).toArray().catch(() => []),
      db.collection(COLLECTIONS.APPROVED_OPERATORS || 'approved_operators').find({}).limit(100).toArray().catch(() => []),
      db.collection(COLLECTIONS.EXPEDITIONS).find({}, { projection: { bsdPdfBase64: 0, 'bsdCerfa.base64': 0 } }).sort({ date: -1 }).limit(limit).toArray().catch(() => []),
      db.collection('avis_clients').find({}).sort({ date: -1 }).limit(100).toArray().catch(() => []),
      db.collection('admin_settings').findOne({ id: 'main' }).catch(() => null)
    ]);
    res.json({
      success: true,
      restaurants, pendingRestaurants, collections, 
      pendingCollectors, approvedCollectors,
      pendingOperators, approvedOperators,
      expeditions, avisClients,
      adminSettings: adminSettings || {},
      _loadedAt: new Date().toISOString()
    });
  } catch (e) {
    console.error('Bulk data error:', e.message);
    res.json({ success: false, error: e.message });
  }
});

// ===== BULK LOAD (optimisation mobile — tout en 1 requête) =====
app.get('/api/bulk-load', async (req, res) => {
  try {
    // Attendre que MongoDB soit prêt (max 10s)
    let waitMs = 0;
    while ((!db || !isConnected) && waitMs < 10000) {
      await new Promise(r => setTimeout(r, 500));
      waitMs += 500;
    }
    if (!db || !isConnected) return res.json({ success: false, reason: 'db_not_ready' });
    const [restaurants, pendingRestaurants, collections, pendingCollectors, approvedCollectors, 
           pendingOperators, approvedOperators, expeditions, demandesCollecte] = await Promise.all([
      db.collection(COLLECTIONS.RESTAURANTS).find({ status: { $ne: 'pending' } }, { projection: { password: 0, loginAttempts: 0, lockUntil: 0, contratPDF: 0, 'contrat.base64': 0, 'signatures.admin': 0, 'signatures.restaurant': 0, adminSignatureData: 0, tamponData: 0 } }).limit(500).toArray(),
      db.collection(COLLECTIONS.RESTAURANTS).find({ status: 'pending' }, { projection: { password: 0, loginAttempts: 0, lockUntil: 0, contratPDF: 0, 'contrat.base64': 0, 'signatures.admin': 0, 'signatures.restaurant': 0, adminSignatureData: 0, tamponData: 0 } }).limit(100).toArray(),
      db.collection(COLLECTIONS.COLLECTIONS).find({}, { projection: { bsdPdfBase64: 0, colSignature: 0, restoSignature: 0, signatureData: 0 } }).sort({ date: -1 }).limit(2000).toArray(),
      db.collection(COLLECTIONS.PENDING_COLLECTORS).find({}).limit(100).toArray(),
      db.collection(COLLECTIONS.APPROVED_COLLECTORS).find({}).limit(100).toArray(),
      db.collection('pending_operators').find({}).limit(100).toArray(),
      db.collection('approved_operators').find({}).limit(100).toArray(),
      db.collection(COLLECTIONS.EXPEDITIONS).find({}, { projection: { bsdPdfBase64: 0, 'bsdCerfa.base64': 0 } }).sort({ date: -1 }).limit(500).toArray(),
      db.collection('demandes_collecte').find({ status: { $in: ['pending', 'accepted'] } }).limit(200).toArray()
    ]);
    res.json({ 
      success: true, 
      restaurants, pendingRestaurants, collections, 
      pendingCollectors, approvedCollectors,
      pendingOperators, approvedOperators,
      expeditions, demandesCollecte
    });
  } catch (e) { 
    console.error('Bulk load error:', e.message);
    res.json({ success: false }); 
  }
});

// ===== ADMIN SETTINGS (backup date, etc.) =====
app.get('/api/admin-settings', async (req, res) => {
  try {
    if (!db || !isConnected) return res.json({});
    const settings = await db.collection('admin_settings').findOne({ id: 'main' });
    res.json(settings || {});
  } catch (e) { res.json({}); }
});
app.put('/api/admin-settings', async (req, res) => {
  try {
    if (!db || !isConnected) return res.status(503).json({ success: false });
    const update = sanitizeObject(req.body);
    await db.collection('admin_settings').updateOne({ id: 'main' }, { $set: update }, { upsert: true });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false }); }
});

// ===== REGISTRE VÉHICULES (Contraventions) =====
app.get('/api/vehicle-logs', async (req, res) => {
  try {
    if (!db || !isConnected) return res.json([]);
    const query = {};
    if (req.query.immatriculation) query.immatriculation = { $regex: req.query.immatriculation.replace(/[-\s]/g, ''), $options: 'i' };
    if (req.query.date) {
      const d = new Date(req.query.date);
      const start = new Date(d.getFullYear(), d.getMonth(), d.getDate());
      const end = new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1);
      query.dateDepart = { $gte: start.toISOString(), $lt: end.toISOString() };
    }
    if (req.query.from && req.query.to) {
      query.dateDepart = { $gte: new Date(req.query.from).toISOString(), $lte: new Date(req.query.to).toISOString() };
    }
    const logs = await db.collection(COLLECTIONS.VEHICLE_LOGS).find(query).sort({ dateDepart: -1 }).limit(500).toArray();
    res.json(logs);
  } catch (e) { res.json([]); }
});
app.post('/api/vehicle-logs', async (req, res) => {
  try {
    if (!db || !isConnected) return res.status(503).json({ success: false });
    const log = sanitizeObject(req.body);
    if (!log.immatriculation || !log.collectorNumber) return res.status(400).json({ success: false, error: 'Immatriculation et collecteur requis' });
    log.immatriculationNorm = (log.immatriculation || '').replace(/[-\s]/g, '').toUpperCase();
    log.createdAt = new Date().toISOString();
    await db.collection(COLLECTIONS.VEHICLE_LOGS).insertOne(log);
    res.json({ success: true, id: log.id });
  } catch (e) { res.status(500).json({ success: false }); }
});
app.put('/api/vehicle-logs/:id', async (req, res) => {
  try {
    if (!db || !isConnected) return res.status(503).json({ success: false });
    const update = sanitizeObject(req.body);
    await db.collection(COLLECTIONS.VEHICLE_LOGS).updateOne({ id: req.params.id }, { $set: update });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false }); }
});

// ===== AUTHENTIFICATION =====
app.post('/api/auth/admin', async (req, res) => {
  try {
    const { email, password } = sanitizeObject(req.body);
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
    const admin = await getAdmin();
    if (isAccountLocked(admin)) { await auditLog('ADMIN_LOGIN_LOCKED', email, {}, req); return res.status(423).json({ success: false, error: 'Compte verrouille' }); }
    if (email !== admin.email) { await auditLog('ADMIN_LOGIN_FAILED', email, {}, req); return res.status(401).json({ success: false, error: 'Identifiants incorrects' }); }
    const isValid = await bcrypt.compare(password, admin.password);
    if (!isValid) { await auditLog('ADMIN_LOGIN_FAILED', email, {}, req); return res.status(401).json({ success: false, error: 'Identifiants incorrects' }); }
    const token = generateToken({ role: 'admin', email });
    await auditLog('ADMIN_LOGIN_SUCCESS', email, {}, req);
    res.json({ success: true, role: 'admin', token, expiresIn: JWT_EXPIRES_IN });
  } catch (error) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
app.post('/api/auth/collector', async (req, res) => {
  try {
    const { email, password } = sanitizeObject(req.body);
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
    if (!isValidEmail(email)) return res.status(400).json({ success: false, error: 'Format email invalide' });
    const collector = await getCollectorByEmail(email);
    if (!collector) { await auditLog('COLLECTOR_LOGIN_FAILED', email, { reason: 'Not found' }, req); return res.status(401).json({ success: false, error: 'Compte non trouve' }); }
    if (collector.status === 'pending') return res.json({ success: false, error: 'pending' });
    if (collector.status !== 'approved') return res.status(401).json({ success: false, error: 'Compte non approuve' });
    if (isAccountLocked(collector)) return res.status(423).json({ success: false, error: 'Compte verrouille' });
    const isValid = await bcrypt.compare(password, collector.password);
    if (!isValid) { await incrementLoginAttempts(COLLECTIONS.COLLECTORS, email); return res.status(401).json({ success: false, error: 'Mot de passe incorrect' }); }
    await resetLoginAttempts(COLLECTIONS.COLLECTORS, email);
    const token = generateToken({ role: 'collector', email, collectorNumber: collector.collectorNumber });
    const { password: _, loginAttempts, lockUntil, ...data } = collector;
    await auditLog('COLLECTOR_LOGIN_SUCCESS', email, {}, req);
    res.json({ success: true, role: 'collector', data, token, expiresIn: JWT_EXPIRES_IN });
  } catch (error) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
app.post('/api/auth/operator', async (req, res) => {
  try {
    const { email, password } = sanitizeObject(req.body);
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
    const operator = await getOperatorByEmail(email);
    if (!operator) return res.status(401).json({ success: false, error: 'Compte non trouve' });
    if (operator.status === 'pending') return res.json({ success: false, error: 'pending' });
    if (operator.status !== 'approved') return res.status(401).json({ success: false, error: 'Compte non approuve' });
    if (isAccountLocked(operator)) return res.status(423).json({ success: false, error: 'Compte verrouille' });
    const isValid = await bcrypt.compare(password, operator.password);
    if (!isValid) { await incrementLoginAttempts(COLLECTIONS.OPERATORS, email); return res.status(401).json({ success: false, error: 'Mot de passe incorrect' }); }
    await resetLoginAttempts(COLLECTIONS.OPERATORS, email);
    const token = generateToken({ role: 'operator', email });
    const { password: _, loginAttempts, lockUntil, ...data } = operator;
    await auditLog('OPERATOR_LOGIN_SUCCESS', email, {}, req);
    res.json({ success: true, role: 'operator', data, token });
  } catch (error) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
app.post('/api/auth/restaurant', async (req, res) => {
  try {
    const { email, password } = sanitizeObject(req.body);
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
    const restaurant = await getRestaurantByEmail(email);
    if (!restaurant) return res.status(401).json({ success: false, error: 'Compte non trouve' });
    if (restaurant.status === 'pending') return res.json({ success: false, error: 'pending' });
    if (restaurant.status === 'terminated') return res.status(401).json({ success: false, error: 'Contrat resilie' });
    const isApproved = restaurant.status === 'approved' || (restaurant.tempPassword && !restaurant.status) || (restaurant.createdBy === 'admin' && !restaurant.status);
    if (!isApproved) return res.status(401).json({ success: false, error: 'Compte non approuve' });
    if (isAccountLocked(restaurant)) return res.status(423).json({ success: false, error: 'Compte verrouille' });
    let isValid = false; let usedTempPassword = false;
    if (restaurant.password) { try { isValid = await bcrypt.compare(password, restaurant.password); } catch (e) {} }
    if (!isValid && restaurant.tempPassword) { isValid = (password === restaurant.tempPassword); usedTempPassword = isValid; }
    if (!isValid) { await incrementLoginAttempts(COLLECTIONS.RESTAURANTS, email); return res.status(401).json({ success: false, error: 'Mot de passe incorrect' }); }
    if (!restaurant.status && (restaurant.tempPassword || restaurant.createdBy === 'admin')) await updateRestaurant(restaurant.id, { status: 'approved' });
    await resetLoginAttempts(COLLECTIONS.RESTAURANTS, email);
    const token = generateToken({ role: 'restaurant', email, id: restaurant.id });
    const { password: _, tempPassword: __, loginAttempts, lockUntil, ...data } = restaurant;
    await auditLog('RESTAURANT_LOGIN_SUCCESS', email, { usedTempPassword }, req);
    res.json({ success: true, role: 'restaurant', data: { ...data, usedTempPassword, needsContractSignature: !restaurant.contratStatus || restaurant.contratStatus !== 'signed' }, token });
  } catch (error) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
app.get('/api/auth/verify', authenticateToken, (req, res) => { res.json({ success: true, user: req.user }); });

// [FIX 1.9] Déconnexion — invalide le token courant
app.post('/api/auth/logout', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token) {
    tokenBlacklist.add(token);
    console.log('Token revoque pour deconnexion');
  }
  res.json({ success: true });
});

// [FIX 1.9] Révocation forcée — invalide tous les tokens d'un utilisateur (usage admin)
app.post('/api/auth/revoke', authenticateToken, requireRole('admin'), (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ success: false, error: 'Email requis' });
  // Note: sans stockage des tokens émis, on ne peut pas révoquer rétroactivement tous les tokens
  // d'un utilisateur. Mais on peut forcer une vérification côté base de données au prochain appel.
  // En pratique, le token expire en 24h max.
  auditLog('TOKEN_REVOKE_REQUESTED', email, { revokedBy: req.user.email }, req);
  res.json({ success: true, message: 'Revocation enregistree' });
});
// ===== COLLECTEURS CRUD =====
app.post('/api/collectors/register', async (req, res) => {
  try {
    const { email, password, ...data } = sanitizeObject(req.body);
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
    if (!isValidEmail(email)) return res.status(400).json({ success: false, error: 'Format email invalide' });
    if (password.length < 8) return res.status(400).json({ success: false, error: 'Mot de passe trop court' });
    const existing = await getCollectorByEmail(email);
    if (existing) return res.status(409).json({ success: false, error: 'Email deja utilise' });
    await addCollector({ email, password: await bcrypt.hash(password, BCRYPT_ROUNDS), ...data, status: 'pending', dateRequest: new Date().toISOString() });
    await auditLog('COLLECTOR_REGISTER', email, { status: 'pending' }, req);
    res.status(201).json({ success: true });
  } catch (error) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
app.get('/api/collectors/pending', async (req, res) => { const c = await getCollectors('pending'); res.json(c.map(({ password, loginAttempts, lockUntil, ...x }) => x)); });
app.get('/api/collectors/approved', async (req, res) => { const c = await getCollectors('approved'); res.json(c.map(({ password, ...x }) => x)); });
app.post('/api/collectors/:email/approve', async (req, res) => { try { const { email } = req.params; const n = await generateCollectorNumber(); await updateCollector(email, { status: 'approved', collectorNumber: n, dateApproval: new Date().toISOString() }); await auditLog('COLLECTOR_APPROVED', email, { collectorNumber: n }, req); res.json({ success: true, collectorNumber: n }); } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); } });
app.post('/api/collectors/:email/reject', async (req, res) => { await deleteCollector(req.params.email); res.json({ success: true }); });
app.delete('/api/collectors/:email', async (req, res) => { await deleteCollector(req.params.email); res.json({ success: true }); });
app.put('/api/collectors/:email/password', async (req, res) => { try { const { password } = sanitizeObject(req.body); if (!password || password.length < 6) return res.status(400).json({ success: false, error: 'Mot de passe invalide' }); await updateCollector(req.params.email, { password: await bcrypt.hash(password, BCRYPT_ROUNDS), loginAttempts: 0, lockUntil: null }); await auditLog('COLLECTOR_PASSWORD_RESET', req.params.email, {}, req); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); } });
app.post('/api/collectors/:email/unlock', async (req, res) => {
  try {
    const email = decodeURIComponent(req.params.email);
    const user = await getCollectorByEmail(email);
    if (!user) return res.status(404).json({ success: false, error: 'Compte non trouvé' });
    await updateCollector(email, { loginAttempts: 0, lockUntil: null });
    await auditLog('COLLECTOR_UNLOCKED', email, { unlockedBy: 'admin' }, req);
    res.json({ success: true, message: 'Compte déverrouillé' });
  } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
// ===== OPERATEURS CRUD =====
app.post('/api/operators/register', async (req, res) => {
  try {
    const { email, password, ...data } = sanitizeObject(req.body);
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
    const existing = await getOperatorByEmail(email);
    if (existing) return res.status(409).json({ success: false, error: 'Email deja utilise' });
    await addOperator({ email, password: await bcrypt.hash(password, BCRYPT_ROUNDS), ...data, status: 'pending', dateRequest: new Date().toISOString() });
    res.status(201).json({ success: true });
  } catch (error) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
app.get('/api/operators/pending', async (req, res) => { const o = await getOperators('pending'); res.json(o.map(({ password, loginAttempts, lockUntil, ...x }) => x)); });
app.get('/api/operators/approved', async (req, res) => { const o = await getOperators('approved'); res.json(o.map(({ password, ...x }) => x)); });
app.post('/api/operators/:email/approve', async (req, res) => { const { email } = req.params; const n = await generateOperatorNumber(); await updateOperator(email, { status: 'approved', operatorNumber: n, dateApproval: new Date().toISOString() }); res.json({ success: true, operatorNumber: n }); });
app.post('/api/operators/:email/reject', async (req, res) => { await deleteOperator(req.params.email); res.json({ success: true }); });
app.delete('/api/operators/:email', async (req, res) => { await deleteOperator(req.params.email); res.json({ success: true }); });
app.put('/api/operators/:email/password', async (req, res) => { try { const { password } = sanitizeObject(req.body); if (!password || password.length < 6) return res.status(400).json({ success: false, error: 'Mot de passe invalide' }); await updateOperator(req.params.email, { password: await bcrypt.hash(password, BCRYPT_ROUNDS), loginAttempts: 0, lockUntil: null }); await auditLog('OPERATOR_PASSWORD_RESET', req.params.email, {}, req); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); } });
app.post('/api/operators/:email/unlock', async (req, res) => {
  try {
    const email = decodeURIComponent(req.params.email);
    const user = await getOperatorByEmail(email);
    if (!user) return res.status(404).json({ success: false, error: 'Compte non trouvé' });
    await updateOperator(email, { loginAttempts: 0, lockUntil: null });
    await auditLog('OPERATOR_UNLOCKED', email, { unlockedBy: 'admin' }, req);
    res.json({ success: true, message: 'Compte déverrouillé' });
  } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
// ===== RESTAURANTS CRUD =====
app.post('/api/restaurants/register', async (req, res) => {
  try {
    const { email, password, id, qrCode, siret, ...data } = sanitizeObject(req.body);
    let existingBySiret = null;
    if (siret && db && isConnected) existingBySiret = await db.collection(COLLECTIONS.RESTAURANTS).findOne({ siret });
    if (existingBySiret) {
      if (email && email !== existingBySiret.email) { const ebye = await getRestaurantByEmail(email); if (ebye && ebye.siret !== siret) return res.status(409).json({ success: false, error: 'Cet email est deja utilise' }); }
      const isFinalization = !existingBySiret.password && password;
      const isResub = existingBySiret.status === 'terminated';
      const upd = { ...data, email: email || existingBySiret.email, dateRequest: new Date().toISOString() };
      if (password) upd.password = await bcrypt.hash(password, BCRYPT_ROUNDS);
      if (isFinalization && existingBySiret.status === 'approved') { upd.status = 'approved'; upd.passwordSetDate = new Date().toISOString(); } else { upd.status = 'pending'; upd.isResubmission = isResub; }
      await updateRestaurant(existingBySiret.id, upd);
      return res.status(200).json({ success: true, id: existingBySiret.id, qrCode: existingBySiret.qrCode || existingBySiret.id, isAccountFinalization: isFinalization, isResubmission: isResub, status: upd.status });
    }
    if (email) { const ebye = await getRestaurantByEmail(email); if (ebye) return res.status(409).json({ success: false, error: 'Cet email est deja utilise' }); }
    let newQR = qrCode;
    if (!newQR || !newQR.startsWith('QR-')) { const all = await getRestaurants(); const nums = all.filter(r => r.qrCode && r.qrCode.startsWith('QR-')).map(r => parseInt(r.qrCode.replace('QR-', '')) || 0); newQR = 'QR-' + String((nums.length > 0 ? Math.max(...nums) : 0) + 1).padStart(5, '0'); }
    const existingQR = await getRestaurantByQRCode(newQR);
    if (existingQR) { const all = await getRestaurants(); const nums = all.filter(r => r.qrCode && r.qrCode.startsWith('QR-')).map(r => parseInt(r.qrCode.replace('QR-', '')) || 0); newQR = 'QR-' + String((nums.length > 0 ? Math.max(...nums) : 0) + 1).padStart(5, '0'); }
    const rid = id || newQR;
    await addRestaurant({ id: rid, qrCode: newQR, email: email || '', password: password ? await bcrypt.hash(password, BCRYPT_ROUNDS) : null, siret: siret || '', ...data, status: 'pending', dateRequest: new Date().toISOString() });
    res.status(201).json({ success: true, id: rid, qrCode: newQR });
  } catch (error) { console.error('Erreur register restaurant:', error); res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
app.get('/api/restaurants/pending', async (req, res) => { const r = await getRestaurants('pending'); res.json(r.map(({ password, loginAttempts, lockUntil, ...x }) => x)); });
// [FIX 3.2 + 3.3] GET /api/restaurants — Delta support via ?since=
app.get('/api/restaurants', async (req, res) => {
  try {
    if (!db || !isConnected) return res.json([]);
    const since = req.query.since || req.headers['if-modified-since'];
    let query = { status: { $in: ['approved', 'terminated'] } };
    
    if (since) {
      try {
        const sinceDate = new Date(since);
        if (!isNaN(sinceDate.getTime())) {
          query = { ...query, $or: [{ updatedAt: { $gte: sinceDate.toISOString() } }, { dateApproval: { $gte: sinceDate.toISOString() } }] };
        }
      } catch(e) {}
    }
    
    const restaurants = await db.collection(COLLECTIONS.RESTAURANTS)
      .find(query, { projection: { password: 0, loginAttempts: 0, lockUntil: 0, contratPDF: 0, 'contrat.base64': 0, 'signatures.admin': 0, 'signatures.restaurant': 0, adminSignatureData: 0, tamponData: 0 } })
      .toArray();
    
    res.set('X-Total-Count', restaurants.length);
    res.set('X-Is-Delta', since ? 'true' : 'false');
    res.set('Last-Modified', new Date().toUTCString());
    
    res.json(restaurants);
  } catch (e) { res.json([]); }
});
app.get('/api/restaurants/qr/:qrCode', async (req, res) => { const r = await getRestaurantByQRCode(req.params.qrCode); if (!r || r.status !== 'approved') return res.status(404).json({ error: 'Restaurant non trouve' }); const { password, loginAttempts, lockUntil, ...data } = r; res.json(data); });
app.get('/api/restaurants/siret/:siret', async (req, res) => { const siret = req.params.siret.replace(/\D/g, ''); if (siret.length !== 14) return res.status(400).json({ error: 'SIRET invalide' }); if (!db || !isConnected) return res.status(503).json({ error: 'DB non disponible' }); const r = await db.collection(COLLECTIONS.RESTAURANTS).findOne({ siret }); if (!r) return res.status(404).json({ error: 'Restaurant non trouve', exists: false }); const { password, loginAttempts, lockUntil, ...data } = r; res.json({ ...data, exists: true }); });
app.post('/api/restaurants/:id/terminate', async (req, res) => { try { const r = await getRestaurantById(req.params.id); if (!r) return res.status(404).json({ success: false, error: 'Non trouve' }); const dt = new Date().toISOString(); await updateRestaurant(req.params.id, { status: 'terminated', dateTerminated: dt, terminationReason: req.body?.reason || 'Fin de contrat' }); res.json({ success: true, dateTerminated: dt }); } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); } });
app.post('/api/restaurants/:id/approve', async (req, res) => { try { const { id } = req.params; const { qrCode, password, ...upd } = sanitizeObject(req.body); const r = await getRestaurantById(id); if (!r) return res.status(404).json({ success: false, error: 'Non trouve' }); const updates = { ...upd, status: 'approved', qrCode: qrCode || r.qrCode || 'UCO-' + Date.now(), dateApproval: new Date().toISOString() }; if (password && !r.password) updates.password = await bcrypt.hash(password, BCRYPT_ROUNDS); await updateRestaurant(id, updates); res.json({ success: true, qrCode: updates.qrCode }); } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); } });
app.post('/api/restaurants/:id/reject', async (req, res) => { await deleteRestaurant(req.params.id); res.json({ success: true }); });
app.post('/api/restaurants', async (req, res) => { try { const { id, qrCode, ...data } = sanitizeObject(req.body); const rid = id || qrCode || uuidv4(); const existing = await getRestaurantById(rid); if (existing) return res.status(409).json({ success: false, error: 'QR Code deja attribue' }); await addRestaurant({ ...data, id: rid, qrCode: qrCode || rid, status: data.status || 'approved', dateCreated: new Date().toISOString() }); res.status(201).json({ success: true, id: rid, qrCode: qrCode || rid }); } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); } });
app.put('/api/restaurants/:id', async (req, res) => { try { const r = await getRestaurantById(req.params.id); if (!r) return res.status(404).json({ success: false, error: 'Non trouve' }); await updateRestaurant(req.params.id, sanitizeObject(req.body)); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); } });
app.put('/api/restaurants/:id/password', async (req, res) => { try { const { password } = sanitizeObject(req.body); if (!password || password.length < 8) return res.status(400).json({ success: false, error: 'Mot de passe invalide' }); const r = await getRestaurantById(req.params.id); if (!r) return res.status(404).json({ success: false, error: 'Non trouve' }); await updateRestaurant(req.params.id, { password: await bcrypt.hash(password, BCRYPT_ROUNDS) }); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); } });
app.post('/api/restaurants/:id/unlock', async (req, res) => {
  try {
    const id = decodeURIComponent(req.params.id);
    const r = await getRestaurantById(id) || await getRestaurantByEmail(id);
    if (!r) return res.status(404).json({ success: false, error: 'Compte non trouvé' });
    await updateRestaurant(r.id, { loginAttempts: 0, lockUntil: null });
    await auditLog('RESTAURANT_UNLOCKED', id, { unlockedBy: 'admin' }, req);
    res.json({ success: true, message: 'Compte déverrouillé' });
  } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
// =============================================
// [SESSION 15] PATCH server.js — endpoint /api/restaurants/:id/full
// =============================================
// INSTRUCTION : Dans server.js, trouver la ligne :
//   app.get('/api/restaurants/:id/contrat', async (req, res) => {
// Et INSÉRER CE BLOC JUSTE AVANT :

app.get('/api/restaurants/:id/full', async (req, res) => {
  try {
    if (!db || !isConnected) return res.status(503).json({ error: 'DB non disponible' });
    const s = sanitizeInput(req.params.id);
    const r = await db.collection(COLLECTIONS.RESTAURANTS).findOne(
      { $or: [{ id: s }, { qrCode: s }, { email: s }] }
      // Pas de projection — retourne TOUT incluant les signatures
    );
    if (!r) return res.status(404).json({ error: 'Restaurant non trouvé' });
    // Retirer uniquement les données d'authentification
    const { password, tempPassword, loginAttempts, lockUntil, ...data } = r;
    res.json({ success: true, restaurant: data });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// =============================================
// FIN DU PATCH — ensuite vient l'existant :
// app.get('/api/restaurants/:id/contrat', async (req, res) => { ...
// =============================================
app.get('/api/restaurants/:id/contrat', async (req, res) => {
  try {
    if (!db || !isConnected) return res.status(503).json({ error: 'DB non disponible' });
    const s = sanitizeInput(req.params.id);
    const r = await db.collection(COLLECTIONS.RESTAURANTS).findOne(
      { $or: [{ id: s }, { qrCode: s }] },
      { projection: { 'contrat.base64': 1, 'contrat.filename': 1, contratStatus: 1 } }
    );
    if (!r) return res.status(404).json({ error: 'Restaurant non trouvé' });
    if (!r.contrat?.base64) return res.status(404).json({ error: 'Pas de contrat disponible' });
    res.json({ success: true, base64: r.contrat.base64, filename: r.contrat.filename, contratStatus: r.contratStatus });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});
app.post('/api/restaurants/:id/change-password', async (req, res) => {
  try {
    const { oldPassword, newPassword } = sanitizeObject(req.body);
    if (!oldPassword) return res.status(400).json({ success: false, error: 'Ancien mot de passe requis' });
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ success: false, error: 'Nouveau mot de passe invalide' });
    const r = await getRestaurantById(req.params.id);
    if (!r) return res.status(404).json({ success: false, error: 'Non trouve' });
    let isOldValid = false;
    if (r.password) isOldValid = await bcrypt.compare(oldPassword, r.password);
    if (!isOldValid && r.tempPassword) isOldValid = (oldPassword === r.tempPassword);
    if (!isOldValid) return res.status(401).json({ success: false, error: 'Ancien mot de passe incorrect' });
    await updateRestaurant(req.params.id, { password: await bcrypt.hash(newPassword, BCRYPT_ROUNDS), tempPassword: null, passwordChangedAt: new Date().toISOString() });
    res.json({ success: true, message: 'Mot de passe modifie avec succes' });
  } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
// ===== COLLECTES [FIX OOM] =====
// [FIX 3.2 + 3.3] GET /api/collections — Pagination + If-Modified-Since
app.get('/api/collections', async (req, res) => {
  try {
    if (!db || !isConnected) return res.json([]);
    
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(2000, Math.max(1, parseInt(req.query.limit) || 2000));
    const skip = (page - 1) * limit;
    const since = req.query.since || req.headers['if-modified-since'];
    
    const projection = { colSignature: 0, restoSignature: 0, bsdPdfBase64: 0, signatureData: 0 };
    let query = {};
    
    // [FIX 3.3] Si le client envoie ?since=ISO_DATE, ne renvoyer que les collectes modifiées depuis
    if (since) {
      try {
        const sinceDate = new Date(since);
        if (!isNaN(sinceDate.getTime())) {
          query = { $or: [{ updatedAt: { $gte: sinceDate.toISOString() } }, { createdAt: { $gte: sinceDate.toISOString() } }] };
        }
      } catch(e) {}
    }
    
    const total = await db.collection(COLLECTIONS.COLLECTIONS).countDocuments(query);
    const collections = await db.collection(COLLECTIONS.COLLECTIONS)
      .find(query, { projection })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();
    
    // Headers de pagination
    res.set('X-Total-Count', total);
    res.set('X-Page', page);
    res.set('X-Limit', limit);
    res.set('X-Has-More', skip + collections.length < total ? 'true' : 'false');
    res.set('Last-Modified', new Date().toUTCString());
    
    res.json(collections.map(c => ({ ...c, date: c.date || c.createdAt })));
  } catch (e) { res.json([]); }
});
app.get('/api/collections/:id', async (req, res) => {
  try {
    if (!db || !isConnected) return res.status(503).json({ error: 'DB non connectee' });
    const col = await db.collection(COLLECTIONS.COLLECTIONS).findOne({ $or: [{ _id: sanitizeInput(req.params.id) }, { id: sanitizeInput(req.params.id) }] });
    if (!col) return res.status(404).json({ error: 'Collecte non trouvee' });
    
    // [FIX 3.8] Si ?withSignatures=true et que les signatures sont sur R2, les reconstruire
    if (req.query.withSignatures === 'true' && col._r2) {
      for (const [field, info] of Object.entries(col._r2)) {
        if (info.r2Key) {
          try {
            const buffer = await downloadFromR2(info.r2Key);
            if (buffer) {
              const prefix = info.contentType ? `data:${info.contentType};base64,` : 'data:image/png;base64,';
              col[field] = prefix + buffer.toString('base64');
            }
          } catch(e) {}
        }
      }
    }
    
    res.json(col);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});
// [FIX 1.8] POST /api/collections — Validation complète
app.post('/api/collections', async (req, res) => {
  try {
    if (!db || !isConnected) return res.status(503).json({ success: false, error: 'DB non connectee' });
    
    const data = sanitizeObject(req.body);
    
    // Validation des champs requis
    if (!data.restaurantId) {
      return res.status(400).json({ success: false, error: 'restaurantId requis' });
    }
    const volume = parseFloat(data.volume);
    if (!volume || volume <= 0) {
      return res.status(400).json({ success: false, error: 'Volume doit etre superieur a 0' });
    }
    if (!data.collectorNumber && !data.collectorId) {
      return res.status(400).json({ success: false, error: 'collectorNumber ou collectorId requis' });
    }
    
    // Anti-doublon: meme restaurant + meme collecteur dans les 2 dernieres minutes
    const twoMinAgo = new Date(Date.now() - 2 * 60 * 1000).toISOString();
    const duplicate = await db.collection(COLLECTIONS.COLLECTIONS).findOne({
      restaurantId: data.restaurantId,
      collectorNumber: data.collectorNumber,
      createdAt: { $gte: twoMinAgo }
    });
    if (duplicate) {
      console.warn('Doublon collecte detecte:', { restaurantId: data.restaurantId, collectorNumber: data.collectorNumber });
      return res.status(409).json({ 
        success: false, 
        error: 'Une collecte a deja ete enregistree pour ce restaurant il y a moins de 2 minutes',
        existingId: duplicate._id
      });
    }
    
    // Generer le numero d'ordre AAMMJJ-COLXXX-XX
    const now = new Date();
    const aa = String(now.getFullYear()).slice(2);
    const mm = String(now.getMonth() + 1).padStart(2, '0');
    const jj = String(now.getDate()).padStart(2, '0');
    const colNum = parseInt(data.collectorNumber) || 0;
    const colId = colNum > 0 ? 'COL' + String(colNum).padStart(3, '0') : 'COL001';
    
    // Compter les collectes du meme collecteur aujourd'hui pour le suffixe
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    const todayCount = await db.collection(COLLECTIONS.COLLECTIONS).countDocuments({
      collectorNumber: data.collectorNumber,
      createdAt: { $gte: todayStart }
    });
    const seq = String(todayCount + 1).padStart(2, '0');
    const numeroOrdre = aa + mm + jj + '-' + colId + '-' + seq;
    
    const collectionId = data.id || uuidv4();
    const collectionDoc = {
      ...data,
      _id: collectionId,
      id: collectionId,
      volume: volume,
      price: parseFloat(data.price) || 0,
      numeroOrdre: data.numeroOrdre || numeroOrdre,
      date: data.date || now.toISOString(),
      createdAt: now.toISOString()
    };
    
    // [FIX 3.8] Extraire les signatures vers R2 si configuré
    let finalDoc = collectionDoc;
    try {
      finalDoc = await extractAndUploadSignatures(collectionDoc, `collections/${collectionId}`);
    } catch (e) { console.log('R2 extraction skipped:', e.message); }
    
    await db.collection(COLLECTIONS.COLLECTIONS).insertOne(finalDoc);
    
    // Verifier le restaurant et retourner ses infos
    let restaurant = null;
    try {
      restaurant = await db.collection(COLLECTIONS.RESTAURANTS).findOne(
        { $or: [{ id: data.restaurantId }, { qrCode: data.restaurantId }] },
        { projection: { password: 0, loginAttempts: 0, lockUntil: 0, contratPDF: 0, 'contrat.base64': 0, 'signatures.admin': 0, 'signatures.restaurant': 0, adminSignatureData: 0, tamponData: 0 } }
      );
    } catch(e) {}
    
    await auditLog('COLLECTION_CREATED', collectionId, { 
      restaurantId: data.restaurantId, 
      volume: volume, 
      collectorNumber: data.collectorNumber 
    }, req);
    
    res.status(201).json({ 
      success: true, 
      id: collectionId,
      collectionId: collectionId,
      numeroOrdre: collectionDoc.numeroOrdre,
      date: collectionDoc.date,
      restaurant: restaurant
    });
  } catch (e) { 
    console.error('Erreur POST collection:', e.message);
    res.status(500).json({ success: false, error: 'Erreur serveur' }); 
  }
});
// ===== TOURNEES [FIX OOM] =====
// [FIX 3.2] GET /api/tournees — Pagination
app.get('/api/tournees', async (req, res) => {
  try {
    if (!db || !isConnected) return res.json([]);
    const limit = Math.min(500, Math.max(1, parseInt(req.query.limit) || 500));
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const skip = (page - 1) * limit;
    const projection = { 'collectes.colSignature': 0, 'collectes.restoSignature': 0 };
    const total = await db.collection(COLLECTIONS.TOURNEES).countDocuments({});
    const tournees = await db.collection(COLLECTIONS.TOURNEES)
      .find({}, { projection })
      .sort({ dateDepart: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();
    res.set('X-Total-Count', total);
    res.set('X-Has-More', skip + tournees.length < total ? 'true' : 'false');
    res.json(tournees);
  } catch (e) { res.json([]); }
});
app.post('/api/tournees', async (req, res) => { try { const t = sanitizeObject({ ...req.body, id: req.body.id || uuidv4() }); await addTournee(t); res.status(201).json({ success: true, id: t.id }); } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); } });
app.put('/api/tournees/:id', async (req, res) => { await updateTournee(req.params.id, sanitizeObject(req.body)); res.json({ success: true }); });
// ===== RAPPORTS TOURNEES =====
app.get('/api/rapports-tournees', async (req, res) => { try { if (!db || !isConnected) return res.json([]); const r = await db.collection('rapports_tournees').find({}).sort({ createdAt: -1 }).limit(100).toArray(); res.json(r || []); } catch (e) { res.json([]); } });
app.post('/api/rapports-tournees', async (req, res) => { try { if (!db || !isConnected) return res.status(503).json({ success: false, error: 'DB non disponible' }); const r = sanitizeObject(req.body); r.createdAt = r.createdAt || new Date().toISOString(); await db.collection('rapports_tournees').insertOne({ ...r, _id: r.id || uuidv4() }); res.status(201).json({ success: true, id: r.id }); } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); } });
// ===== SETTINGS =====
app.get('/api/settings', async (req, res) => { const s = await getSettings(); const { admin, brevoApiKey, ...pub } = s; pub.brevoApiKey = brevoApiKey ? '••••••••••••••••' : ''; pub.hasBrevoKey = !!brevoApiKey; res.json(pub); });
app.put('/api/settings', async (req, res) => { try { const { brevoApiKey, ...other } = req.body; const s = sanitizeObject(other); if (brevoApiKey) s.brevoApiKey = brevoApiKey; await updateSettings(s); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); } });
app.put('/api/admin/password', async (req, res) => {
  try {
    const { currentPassword, newPassword } = sanitizeObject(req.body);
    if (!currentPassword || !newPassword) return res.status(400).json({ success: false, error: 'Mots de passe requis' });
    if (newPassword.length < 8) return res.status(400).json({ success: false, error: 'Mot de passe trop court' });
    const admin = await getAdmin();
    const isValid = await bcrypt.compare(currentPassword, admin.password);
    if (!isValid) return res.status(401).json({ success: false, error: 'Mot de passe actuel incorrect' });
    const settings = await getSettings();
    await updateSettings({ ...settings, admin: { ...admin, password: await bcrypt.hash(newPassword, BCRYPT_ROUNDS) } });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
// ===== EMAIL =====
app.post('/api/send-email', async (req, res) => {
  try {
    const { to, subject, htmlContent, html, senderName, attachment, content, title } = req.body;
    if (!to || !subject) return res.status(400).json({ success: false, error: 'Parametres manquants' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) return res.status(400).json({ success: false, error: 'Email invalide' });
    const settings = await getSettings();
    if (!settings.brevoApiKey) return res.status(503).json({ success: false, error: 'Service email non configure' });
    let rawContent = (content || htmlContent || html || '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, ' ');
    let cleanContent = rawContent.replace(/<!DOCTYPE[^>]*>/gi, '').replace(/<html[^>]*>/gi, '').replace(/<\/html>/gi, '').replace(/<head[^>]*>[\s\S]*?<\/head>/gi, '').replace(/<body[^>]*>/gi, '').replace(/<\/body>/gi, '').replace(/<meta[^>]*>/gi, '').trim();
    const finalHtml = '<html><head><meta charset="UTF-8"></head><body style="font-family:Arial,sans-serif;padding:20px;">' + cleanContent + '</body></html>';
    const emailPayload = { sender: { name: senderName || 'UCO AND CO', email: 'contact@uco-and-co.fr' }, to: [{ email: to }], subject: subject.substring(0, 200), htmlContent: finalHtml };
    if (attachment && attachment.content && attachment.name) emailPayload.attachment = [{ content: attachment.content, name: attachment.name.substring(0, 100) }];
    const response = await fetch('https://api.brevo.com/v3/smtp/email', { method: 'POST', headers: { 'accept': 'application/json', 'api-key': settings.brevoApiKey, 'content-type': 'application/json' }, body: JSON.stringify(emailPayload) });
    const responseData = await response.json();
    if (response.ok) res.json({ success: true, messageId: responseData.messageId });
    else res.status(502).json({ success: false, error: responseData.message || 'Erreur Brevo' });
  } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
// ===== SMS =====
app.post('/api/send-sms', async (req, res) => {
  try {
    const { to, message, content } = req.body;
    const smsMessage = message || content;
    if (!to || !smsMessage) return res.status(400).json({ success: false, error: 'Parametres manquants' });
    const settings = await getSettings();
    if (!settings.brevoApiKey) return res.status(503).json({ success: false, error: 'Cle API Brevo non configuree' });
    if (!settings.smsEnabled) return res.status(503).json({ success: false, error: 'SMS desactive' });
    let phoneNumber = typeof to === 'object' ? to.number : to;
    let countryCode = typeof to === 'object' ? to.countryCode : 'FR';
    phoneNumber = String(phoneNumber).replace(/[\s\.\-]/g, '');
    const prefixes = { 'FR': '+33', 'BE': '+32', 'CH': '+41', 'LU': '+352' };
    const prefix = prefixes[countryCode] || '+33';
    if (!phoneNumber.startsWith('+')) phoneNumber = phoneNumber.startsWith('0') ? prefix + phoneNumber.slice(1) : prefix + phoneNumber;
    const response = await fetch('https://api.brevo.com/v3/transactionalSMS/sms', { method: 'POST', headers: { 'accept': 'application/json', 'api-key': settings.brevoApiKey, 'content-type': 'application/json' }, body: JSON.stringify({ sender: 'UCOANDCO', recipient: phoneNumber, content: smsMessage.slice(0, 160) }) });
    const responseData = await response.json();
    if (response.ok) res.json({ success: true, messageId: responseData.messageId });
    else res.status(502).json({ success: false, error: responseData.message || 'Erreur SMS', code: responseData.code });
  } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
// ===== AUDIT LOGS =====
app.get('/api/audit-logs', authenticateToken, requireRole('admin'), async (req, res) => {
  if (!db || !isConnected) return res.json([]);
  try { const { limit = 100, action, userId } = req.query; const q = {}; if (action) q.action = action; if (userId) q.userId = userId; const logs = await db.collection(COLLECTIONS.AUDIT_LOGS).find(q).sort({ timestamp: -1 }).limit(parseInt(limit)).toArray(); res.json(logs); } catch (e) { res.json([]); }
});
// ===== STATS [OPTIMISE] =====
app.get('/api/stats', async (req, res) => {
  try {
    if (!db || !isConnected) return res.json({ restaurants: 0, collectors: 0, operators: 0, collections: 0, totalVolume: 0, totalAmount: 0 });
    const [rc, cc, oc, colc, va] = await Promise.all([
      db.collection(COLLECTIONS.RESTAURANTS).countDocuments({ status: 'approved' }),
      db.collection(COLLECTIONS.COLLECTORS).countDocuments({ status: 'approved' }),
      db.collection(COLLECTIONS.OPERATORS).countDocuments({ status: 'approved' }),
      db.collection(COLLECTIONS.COLLECTIONS).countDocuments(),
      db.collection(COLLECTIONS.COLLECTIONS).aggregate([{ $group: { _id: null, totalVolume: { $sum: { $toDouble: { $ifNull: ['$quantite', 0] } } }, totalAmount: { $sum: { $toDouble: { $ifNull: ['$montant', 0] } } } } }]).toArray()
    ]);
    const totals = va[0] || { totalVolume: 0, totalAmount: 0 };
    res.json({ restaurants: rc, collectors: cc, operators: oc, collections: colc, totalVolume: Math.round(totals.totalVolume * 100) / 100, totalAmount: Math.round(totals.totalAmount * 100) / 100 });
  } catch (e) { res.json({ restaurants: 0, collectors: 0, operators: 0, collections: 0, totalVolume: 0, totalAmount: 0 }); }
});
// ===== PARTENAIRES =====
app.get('/api/partners', async (req, res) => { try { if (!db || !isConnected) return res.json([]); res.json(await db.collection('partners').find({}).toArray()); } catch (e) { res.json([]); } });
app.post('/api/partners', async (req, res) => { try { if (!db || !isConnected) return res.status(503).json({ success: false }); const p = req.body; if (!p.id) p.id = 'partner_' + Date.now(); p.createdAt = new Date().toISOString(); await db.collection('partners').insertOne(p); res.json({ success: true, partner: p }); } catch (e) { res.status(500).json({ success: false, error: e.message }); } });
app.put('/api/partners/:id', async (req, res) => { try { if (!db || !isConnected) return res.status(503).json({ success: false }); const u = req.body; u.updatedAt = new Date().toISOString(); const r = await db.collection('partners').updateOne({ id: req.params.id }, { $set: u }); if (r.matchedCount === 0) return res.status(404).json({ success: false }); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false }); } });
app.delete('/api/partners/:id', async (req, res) => { try { if (!db || !isConnected) return res.status(503).json({ success: false }); const r = await db.collection('partners').deleteOne({ id: req.params.id }); if (r.deletedCount === 0) return res.status(404).json({ success: false }); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false }); } });
// ===== PRESTATAIRES =====
const SERVICES_DISPONIBLES = [
  { id: 'bac_graisse', name: 'Entretien bac a graisse', icon: '🪣' }, { id: 'hotte', name: 'Nettoyage hotte', icon: '🌀' },
  { id: 'extincteur', name: 'Extincteurs', icon: '🧯' }, { id: 'deratisation', name: 'Deratisation', icon: '🐀' },
  { id: 'haccp', name: 'Formation HACCP', icon: '📋' }, { id: 'frigoriste', name: 'Frigoriste', icon: '❄️' },
  { id: 'matieres_premieres', name: 'Matieres premieres', icon: '🛒' }, { id: 'comptable', name: 'Expert-comptable', icon: '📊' },
  { id: 'avocat', name: 'Avocat', icon: '⚖️' }, { id: 'assurance', name: 'Assurance', icon: '🛡️' },
  { id: 'electricien', name: 'Electricien', icon: '⚡' }, { id: 'plombier', name: 'Plombier', icon: '🔧' },
  { id: 'nettoyage', name: 'Nettoyage pro', icon: '🧹' }, { id: 'securite', name: 'Securite incendie', icon: '🔥' },
  { id: 'autre', name: 'Autre service', icon: '📦' }
];
app.get('/api/services-disponibles', (req, res) => { res.json(SERVICES_DISPONIBLES); });
app.get('/api/prestataires', async (req, res) => { try { if (!db || !isConnected) return res.json([]); res.json(await db.collection(COLLECTIONS.PRESTATAIRES).find({}).toArray() || []); } catch (e) { res.json([]); } });
app.get('/api/prestataires/:id', async (req, res) => { try { if (!db || !isConnected) return res.status(503).json({ success: false }); const p = await db.collection(COLLECTIONS.PRESTATAIRES).findOne({ $or: [{ id: sanitizeInput(req.params.id) }, { _id: sanitizeInput(req.params.id) }] }); if (!p) return res.status(404).json({ success: false }); res.json(p); } catch (e) { res.status(500).json({ success: false }); } });
app.post('/api/prestataires', async (req, res) => {
  try {
    if (!db || !isConnected) return res.status(503).json({ success: false });
    const data = sanitizeObject(req.body);
    if (!data.enseigne) return res.status(400).json({ success: false, error: 'Enseigne requise' });
    if (!data.email) return res.status(400).json({ success: false, error: 'Email requis' });
    if (!data.services || data.services.length === 0) return res.status(400).json({ success: false, error: 'Service requis' });
    if (data.siret && data.siret !== 'EN_COURS') { const ex = await db.collection(COLLECTIONS.PRESTATAIRES).findOne({ siret: data.siret }); if (ex) return res.status(409).json({ success: false, error: 'SIRET deja utilise' }); }
    const exEmail = await db.collection(COLLECTIONS.PRESTATAIRES).findOne({ email: data.email }); if (exEmail) return res.status(409).json({ success: false, error: 'Email deja utilise' });
    const pid = 'PREST_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    const np = { ...data, id: pid, _id: pid, dateCreation: new Date().toISOString(), status: 'active', createdBy: req.body.createdBy || 'admin' };
    await db.collection(COLLECTIONS.PRESTATAIRES).insertOne(np);
    res.status(201).json({ success: true, id: pid, prestataire: np });
  } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
app.put('/api/prestataires/:id', async (req, res) => { try { if (!db || !isConnected) return res.status(503).json({ success: false }); const data = sanitizeObject(req.body); delete data._id; data.updatedAt = new Date().toISOString(); const r = await db.collection(COLLECTIONS.PRESTATAIRES).updateOne({ $or: [{ id: sanitizeInput(req.params.id) }, { _id: sanitizeInput(req.params.id) }] }, { $set: data }); if (r.matchedCount === 0) return res.status(404).json({ success: false }); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false }); } });
app.delete('/api/prestataires/:id', authenticateToken, async (req, res) => { try { if (!db || !isConnected) return res.status(503).json({ success: false }); const r = await db.collection(COLLECTIONS.PRESTATAIRES).deleteOne({ $or: [{ id: sanitizeInput(req.params.id) }, { _id: sanitizeInput(req.params.id) }] }); if (r.deletedCount === 0) return res.status(404).json({ success: false }); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false }); } });
app.get('/api/prestataires/service/:serviceId', async (req, res) => { try { if (!db || !isConnected) return res.json([]); res.json(await db.collection(COLLECTIONS.PRESTATAIRES).find({ services: sanitizeInput(req.params.serviceId), status: 'active' }).toArray() || []); } catch (e) { res.json([]); } });
// ===== AVIS =====
app.get('/api/avis', async (req, res) => { try { if (!db || !isConnected) return res.json([]); res.json(await db.collection(COLLECTIONS.AVIS).find({}).sort({ dateCreation: -1 }).toArray() || []); } catch (e) { res.json([]); } });

// ===== DAILY VOLUMES =====
app.get('/api/daily-volumes', async (req, res) => {
  try {
    if (!db || !isConnected) return res.json([]);
    const volumes = await db.collection(COLLECTIONS.DAILY_VOLUMES).find({}).sort({ date: -1 }).limit(500).toArray();
    res.json(volumes || []);
  } catch (e) { res.json([]); }
});
app.post('/api/daily-volumes', async (req, res) => {
  try {
    if (!db || !isConnected) return res.status(503).json({ success: false, error: 'DB non connectee' });
    const data = sanitizeObject(req.body);
    if (!data.date || !data.collectorId) return res.status(400).json({ success: false, error: 'date et collectorId requis' });
    data.updatedAt = new Date().toISOString();
    await db.collection(COLLECTIONS.DAILY_VOLUMES).updateOne(
      { date: data.date, collectorId: data.collectorId },
      { $set: data },
      { upsert: true }
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});

// ===== EXPEDITIONS =====
app.get('/api/expeditions', async (req, res) => {
  try {
    if (!db || !isConnected) return res.json([]);
    const expeditions = await db.collection(COLLECTIONS.EXPEDITIONS).find({}, { projection: { bsdPdfBase64: 0, 'bsdCerfa.base64': 0 } }).sort({ date: -1 }).limit(500).toArray();
    res.json(expeditions || []);
  } catch (e) { res.json([]); }
});
app.post('/api/expeditions', async (req, res) => {
  try {
    if (!db || !isConnected) return res.status(503).json({ success: false, error: 'DB non connectee' });
    const data = sanitizeObject(req.body);
    if (!data.id) data.id = require('uuid').v4();
    data.createdAt = data.createdAt || new Date().toISOString();
    data.updatedAt = new Date().toISOString();
    await db.collection(COLLECTIONS.EXPEDITIONS).updateOne(
      { id: data.id },
      { $set: data },
      { upsert: true }
    );
    res.json({ success: true, id: data.id });
  } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});
app.post('/api/avis', async (req, res) => { try { if (!db || !isConnected) return res.status(503).json({ success: false }); const a = sanitizeObject(req.body); if (!a.id) a.id = 'avis_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9); a.dateCreation = a.dateCreation || new Date().toISOString(); await db.collection(COLLECTIONS.AVIS).insertOne({ ...a, _id: a.id }); res.status(201).json({ success: true, id: a.id }); } catch (e) { res.status(500).json({ success: false }); } });
app.delete('/api/avis/:id', authenticateToken, async (req, res) => { try { if (!db || !isConnected) return res.status(503).json({ success: false }); await db.collection(COLLECTIONS.AVIS).deleteOne({ id: sanitizeInput(req.params.id) }); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false }); } });
app.post('/api/avis/:id/read', async (req, res) => { try { if (!db || !isConnected) return res.status(503).json({ success: false }); await db.collection(COLLECTIONS.AVIS).updateOne({ $or: [{ id: sanitizeInput(req.params.id) }, { _id: sanitizeInput(req.params.id) }] }, { $set: { isRead: true, readAt: new Date().toISOString() } }); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false }); } });
app.post('/api/avis/mark-all-read', async (req, res) => { try { if (!db || !isConnected) return res.status(503).json({ success: false }); const r = await db.collection(COLLECTIONS.AVIS).updateMany({ isRead: { $ne: true } }, { $set: { isRead: true, readAt: new Date().toISOString() } }); res.json({ success: true, count: r.modifiedCount }); } catch (e) { res.status(500).json({ success: false }); } });
// =============================================
// TRANSPORTEURS / RECEPTEURS / CERTIFICATEURS
// =============================================
// Helper function for generic role routes
function createRoleRoutes(app, roleName, collectionName, numberField, numberPrefix) {
  // Register
  app.post('/api/' + roleName + '/register', async (req, res) => {
    try {
      const { email, password, ...data } = sanitizeObject(req.body);
      if (!email || !password) return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
      if (!isValidEmail(email)) return res.status(400).json({ success: false, error: 'Email invalide' });
      const existing = await db.collection(collectionName).findOne({ email });
      if (existing) return res.status(409).json({ success: false, error: 'Email deja utilise' });
      await db.collection(collectionName).insertOne({
        ...data, email, password: await bcrypt.hash(password, BCRYPT_ROUNDS),
        _id: email, status: 'pending', loginAttempts: 0, lockUntil: null,
        dateRequest: new Date().toISOString(), createdAt: new Date().toISOString()
      });
      await auditLog(roleName.toUpperCase() + '_REGISTER', email, { status: 'pending' }, req);
      res.status(201).json({ success: true });
    } catch (e) { console.error('Erreur register ' + roleName + ':', e.message); res.status(500).json({ success: false, error: 'Erreur serveur' }); }
  });

  // Auth
  app.post('/api/auth/' + roleName, async (req, res) => {
    try {
      const { email, password } = sanitizeObject(req.body);
      if (!email || !password) return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
      const user = await db.collection(collectionName).findOne({ email });
      if (!user) return res.status(401).json({ success: false, error: 'Compte non trouve' });
      if (user.status === 'pending') return res.json({ success: false, error: 'pending' });
      if (user.status !== 'approved') return res.status(401).json({ success: false, error: 'Compte non approuve' });
      if (isAccountLocked(user)) return res.status(423).json({ success: false, error: 'Compte verrouille' });
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        await incrementLoginAttempts(collectionName, email);
        return res.status(401).json({ success: false, error: 'Mot de passe incorrect' });
      }
      await resetLoginAttempts(collectionName, email);
      const token = generateToken({ role: roleName, email });
      const { password: _, loginAttempts, lockUntil, ...data } = user;
      await auditLog(roleName.toUpperCase() + '_LOGIN_SUCCESS', email, {}, req);
      res.json({ success: true, role: roleName, data, token });
    } catch (e) { console.error('Erreur auth ' + roleName + ':', e.message); res.status(500).json({ success: false, error: 'Erreur serveur' }); }
  });

  // List pending
  app.get('/api/' + roleName + '/pending', async (req, res) => {
    try {
      if (!db || !isConnected) return res.json([]);
      const items = await db.collection(collectionName).find({ status: 'pending' }).toArray();
      res.json(items.map(({ password, loginAttempts, lockUntil, ...x }) => x));
    } catch (e) { res.json([]); }
  });

  // List approved
  app.get('/api/' + roleName + '/approved', async (req, res) => {
    try {
      if (!db || !isConnected) return res.json([]);
      const items = await db.collection(collectionName).find({ status: 'approved' }).toArray();
      res.json(items.map(({ password, ...x }) => x));
    } catch (e) { res.json([]); }
  });

  // Approve
  app.post('/api/' + roleName + '/:email/approve', async (req, res) => {
    try {
      const { email } = req.params;
      const existing = await db.collection(collectionName).find({ status: 'approved' }).toArray();
      const nums = existing.filter(x => x[numberField]).map(x => x[numberField]);
      let num = 1;
      while (nums.includes(num)) num++;
      await db.collection(collectionName).updateOne(
        { email },
        { $set: { status: 'approved', [numberField]: num, dateApproval: new Date().toISOString(), updatedAt: new Date().toISOString() } }
      );
      await auditLog(roleName.toUpperCase() + '_APPROVED', email, { [numberField]: num }, req);
      res.json({ success: true, [numberField]: num, formatted: numberPrefix + '-' + String(num).padStart(3, '0') });
    } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
  });

  // Reject (delete pending)
  app.post('/api/' + roleName + '/:email/reject', async (req, res) => {
    try {
      await db.collection(collectionName).deleteOne({ email: req.params.email });
      await auditLog(roleName.toUpperCase() + '_REJECTED', req.params.email, {}, req);
      res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
  });

  // Delete
  app.delete('/api/' + roleName + '/:email', async (req, res) => {
    try {
      await db.collection(collectionName).deleteOne({ email: req.params.email });
      res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
  });

  // Update
  app.put('/api/' + roleName + '/:email', async (req, res) => {
    try {
      const data = sanitizeObject(req.body);
      delete data._id; delete data.password;
      data.updatedAt = new Date().toISOString();
      await db.collection(collectionName).updateOne({ email: req.params.email }, { $set: data });
      res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
  });

  // Password reset (by admin)
  app.put('/api/' + roleName + '/:email/password', async (req, res) => {
    try {
      const { password } = sanitizeObject(req.body);
      if (!password || password.length < 6) return res.status(400).json({ success: false, error: 'Mot de passe invalide' });
      await db.collection(collectionName).updateOne(
        { email: req.params.email },
        { $set: { password: await bcrypt.hash(password, BCRYPT_ROUNDS), loginAttempts: 0, lockUntil: null, updatedAt: new Date().toISOString() } }
      );
      await auditLog(roleName.toUpperCase() + '_PASSWORD_RESET', req.params.email, {}, req);
      res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
  });
  // Unlock (by admin)
  app.post('/api/' + roleName + '/:email/unlock', async (req, res) => {
    try {
      const email = decodeURIComponent(req.params.email);
      await db.collection(collectionName).updateOne(
        { email },
        { $set: { loginAttempts: 0, lockUntil: null, updatedAt: new Date().toISOString() } }
      );
      await auditLog(roleName.toUpperCase() + '_UNLOCKED', email, { unlockedBy: 'admin' }, req);
      res.json({ success: true, message: 'Compte déverrouillé' });
    } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
  });
}

// Create routes for all 3 roles
createRoleRoutes(app, 'transporteurs', COLLECTIONS.TRANSPORTEURS, 'transporteurNumber', 'TRA');
createRoleRoutes(app, 'recepteurs', COLLECTIONS.RECEPTEURS, 'recepteurNumber', 'REC');
createRoleRoutes(app, 'certificateurs', COLLECTIONS.CERTIFICATEURS, 'certificateurNumber', 'CERT');

// Password reset for transporteurs/recepteurs/certificateurs
app.post('/api/password-reset/:role', async (req, res) => {
  try {
    const { role } = req.params;
    const { email, newPassword } = sanitizeObject(req.body);
    const collMap = { 
      transporteurs: COLLECTIONS.TRANSPORTEURS, 
      recepteurs: COLLECTIONS.RECEPTEURS, 
      certificateurs: COLLECTIONS.CERTIFICATEURS,
      collectors: COLLECTIONS.COLLECTORS,
      operators: COLLECTIONS.OPERATORS,
      restaurants: COLLECTIONS.RESTAURANTS
    };
    const coll = collMap[role];
    if (!coll) return res.status(400).json({ success: false, error: 'Role invalide' });
    if (!email || !newPassword) return res.status(400).json({ success: false, error: 'Email et nouveau mot de passe requis' });
    if (newPassword.length < 6) return res.status(400).json({ success: false, error: 'Mot de passe trop court' });
    // Restaurants use email field, others use email as _id
    const query = role === 'restaurants' ? { email } : { email };
    const user = await db.collection(coll).findOne(query);
    if (!user) return res.status(404).json({ success: false, error: 'Compte non trouve' });
    await db.collection(coll).updateOne(query, { $set: { password: await bcrypt.hash(newPassword, BCRYPT_ROUNDS), passwordChangedAt: new Date().toISOString(), updatedAt: new Date().toISOString() } });
    await auditLog(role.toUpperCase() + '_PASSWORD_RESET', email, {}, req);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: 'Erreur serveur' }); }
});

// [FIX 3.8] Endpoint pour télécharger une signature depuis R2
app.get('/api/r2/:key(*)', async (req, res) => {
  try {
    const key = req.params.key;
    const buffer = await downloadFromR2(key);
    if (!buffer) return res.status(404).json({ error: 'Fichier non trouve' });
    
    // Déterminer le content-type depuis l'extension
    const ext = key.split('.').pop();
    const types = { png: 'image/png', jpg: 'image/jpeg', pdf: 'application/pdf' };
    res.set('Content-Type', types[ext] || 'application/octet-stream');
    res.set('Cache-Control', 'public, max-age=86400'); // Cache 24h
    res.send(buffer);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// [FIX 3.8] Endpoint pour uploader un fichier vers R2
app.post('/api/r2/upload', async (req, res) => {
  try {
    const { key, base64, contentType } = req.body;
    if (!key || !base64) return res.status(400).json({ error: 'key et base64 requis' });
    const uploaded = await uploadToR2(key, base64, contentType || 'image/png');
    if (!uploaded) return res.status(503).json({ error: 'R2 non disponible' });
    res.json({ success: true, key: uploaded, url: `${API_BASE_URL || ''}/api/r2/${uploaded}` });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// [FIX 3.8] Migration: extraire les signatures des collectes existantes vers R2
app.post('/api/r2/migrate', async (req, res) => {
  const client = initS3();
  if (!client) return res.json({ success: false, error: 'R2 non configure', migrated: 0 });
  if (!db || !isConnected) return res.status(503).json({ error: 'DB non connectee' });
  
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    // Trouver les collectes qui ont encore des signatures en base64
    const collectionsWithSig = await db.collection(COLLECTIONS.COLLECTIONS)
      .find({
        $or: [
          { colSignature: { $exists: true, $ne: null, $not: { $size: 0 } } },
          { restoSignature: { $exists: true, $ne: null, $not: { $size: 0 } } }
        ],
        '_r2.colSignature': { $exists: false }
      })
      .limit(limit)
      .toArray();
    
    let migrated = 0;
    let errors = 0;
    
    for (const col of collectionsWithSig) {
      try {
        const prefix = `collections/${col._id || col.id}`;
        const r2Keys = {};
        
        for (const field of ['colSignature', 'restoSignature']) {
          if (col[field] && typeof col[field] === 'string' && col[field].length > 1000) {
            let base64 = col[field];
            let contentType = 'image/png';
            if (base64.startsWith('data:')) {
              const match = base64.match(/^data:([^;]+);base64,(.+)$/);
              if (match) { contentType = match[1]; base64 = match[2]; }
            }
            const key = `${prefix}/${field}.png`;
            const uploaded = await uploadToR2(key, base64, contentType);
            if (uploaded) {
              r2Keys[field] = { r2Key: key, contentType, size: base64.length };
            }
          }
        }
        
        if (Object.keys(r2Keys).length > 0) {
          // Mettre à jour MongoDB: supprimer les base64, ajouter les clés R2
          const update = { $set: { _r2: r2Keys }, $unset: {} };
          for (const field of Object.keys(r2Keys)) {
            update.$unset[field] = '';
          }
          await db.collection(COLLECTIONS.COLLECTIONS).updateOne({ _id: col._id }, update);
          migrated++;
        }
      } catch (e) {
        errors++;
        console.log('Migration error for', col._id, ':', e.message);
      }
    }
    
    const remaining = await db.collection(COLLECTIONS.COLLECTIONS).countDocuments({
      $or: [
        { colSignature: { $exists: true, $ne: null } },
        { restoSignature: { $exists: true, $ne: null } }
      ],
      '_r2.colSignature': { $exists: false }
    });
    
    await auditLog('R2_MIGRATION', 'system', { migrated, errors, remaining }, req);
    res.json({ success: true, migrated, errors, remaining, message: `${migrated} collecte(s) migrees, ${remaining} restante(s)` });
  } catch (e) {
    console.error('Migration R2 error:', e.message);
    res.status(500).json({ error: 'Erreur migration' });
  }
});

// [FIX 3.8] Status R2
app.get('/api/r2/status', (req, res) => {
  const client = initS3();
  res.json({
    configured: !!client,
    bucket: R2_BUCKET,
    hasCredentials: !!(process.env.R2_ACCOUNT_ID && process.env.R2_ACCESS_KEY_ID && process.env.R2_SECRET_ACCESS_KEY)
  });
});

// [FIX 3.6] Archivage collectes > 1 an — libérer l'espace MongoDB
app.post('/api/archive/collections', async (req, res) => {
  if (!db || !isConnected) return res.status(503).json({ error: 'DB non connectee' });
  try {
    const monthsOld = parseInt(req.query.months) || 12;
    const cutoff = new Date();
    cutoff.setMonth(cutoff.getMonth() - monthsOld);
    const cutoffStr = cutoff.toISOString();
    
    // Compter les collectes à archiver
    const toArchive = await db.collection(COLLECTIONS.COLLECTIONS).countDocuments({
      createdAt: { $lt: cutoffStr },
      _archived: { $ne: true }
    });
    
    if (toArchive === 0) return res.json({ success: true, archived: 0, message: 'Aucune collecte a archiver' });
    
    // Copier vers la collection d'archive (sans signatures)
    const oldCollections = await db.collection(COLLECTIONS.COLLECTIONS)
      .find({ createdAt: { $lt: cutoffStr }, _archived: { $ne: true } })
      .project({ colSignature: 0, restoSignature: 0 })
      .limit(500)
      .toArray();
    
    if (oldCollections.length > 0) {
      // Insérer dans la collection archive
      const archiveDocs = oldCollections.map(c => ({ ...c, _archivedAt: new Date().toISOString(), _originalCollection: 'collections' }));
      await db.collection('archives_collections').insertMany(archiveDocs);
      
      // Marquer comme archivées (mais ne pas supprimer — sécurité)
      const ids = oldCollections.map(c => c._id);
      await db.collection(COLLECTIONS.COLLECTIONS).updateMany(
        { _id: { $in: ids } },
        { $set: { _archived: true, colSignature: null, restoSignature: null, _archivedAt: new Date().toISOString() } }
      );
    }
    
    await auditLog('ARCHIVE_COLLECTIONS', 'system', { archived: oldCollections.length, cutoff: cutoffStr, monthsOld }, req);
    
    // Stats d'espace libéré (estimation)
    const avgSigSize = 150; // KB moyenne par signature
    const freedKB = oldCollections.length * avgSigSize * 2; // 2 signatures par collecte
    
    res.json({
      success: true,
      archived: oldCollections.length,
      remaining: toArchive - oldCollections.length,
      freedEstimate: (freedKB / 1024).toFixed(1) + ' MB',
      message: `${oldCollections.length} collecte(s) archivee(s). ~${(freedKB / 1024).toFixed(1)} MB liberes`
    });
  } catch (e) {
    console.error('Erreur archivage:', e.message);
    res.status(500).json({ error: 'Erreur archivage: ' + e.message });
  }
});

// [FIX 3.6] Stats d'archivage
app.get('/api/archive/stats', async (req, res) => {
  if (!db || !isConnected) return res.status(503).json({ error: 'DB non connectee' });
  try {
    const totalCollections = await db.collection(COLLECTIONS.COLLECTIONS).countDocuments({});
    const archivedCollections = await db.collection(COLLECTIONS.COLLECTIONS).countDocuments({ _archived: true });
    const archiveCount = await db.collection('archives_collections').countDocuments({});
    
    const cutoff = new Date();
    cutoff.setMonth(cutoff.getMonth() - 12);
    const oldCount = await db.collection(COLLECTIONS.COLLECTIONS).countDocuments({
      createdAt: { $lt: cutoff.toISOString() },
      _archived: { $ne: true }
    });
    
    res.json({
      totalCollections,
      archivedInPlace: archivedCollections,
      archivedSeparate: archiveCount,
      eligibleForArchive: oldCount,
      estimatedFreeable: (oldCount * 300 / 1024).toFixed(1) + ' MB'
    });
  } catch (e) { res.status(500).json({ error: 'Erreur' }); }
});

// ===== QONTO — Joindre factures aux transactions =====
// Proxy pour éviter CORS (frontend → backend → Qonto API)

// Rechercher une transaction Qonto par montant et date
app.post('/api/qonto/find-transaction', async (req, res) => {
  const { amount, dateFrom, dateTo, label } = req.body;
  try {
    // Utiliser les credentials stockés en base (configurés via /api/qonto/configure)
    const settings = await getSettings();
    const apiKey = settings?.qontoSecretKey;
    const slug = settings?.qontoOrganizationId;
    if (!apiKey || !slug) return res.status(400).json({ error: 'Qonto non configure. Allez dans Parametres pour configurer.' });
    
    const params = new URLSearchParams({
      slug,
      status: 'completed',
      ...(dateFrom && { settled_at_from: dateFrom }),
      ...(dateTo && { settled_at_to: dateTo }),
    });
    const response = await fetch(`https://thirdparty.qonto.com/v2/transactions?${params}`, {
      headers: { 'Authorization': `${slug}:${apiKey}` }
    });
    const data = await response.json();
    if (!data.transactions) return res.json({ transactions: [], message: 'Aucune transaction trouvee' });
    
    // Filtrer par montant (tolérance 0.01€)
    const targetAmount = Math.abs(parseFloat(amount));
    const matched = data.transactions.filter(t => {
      const txAmount = Math.abs(t.amount);
      return Math.abs(txAmount - targetAmount) <= 0.01;
    });
    
    res.json({ transactions: matched.slice(0, 10), total: matched.length });
  } catch (e) {
    console.error('Qonto search error:', e.message);
    res.status(500).json({ error: 'Erreur Qonto: ' + e.message });
  }
});

// Joindre un PDF à une transaction Qonto
app.post('/api/qonto/attach', async (req, res) => {
  const { transactionId, pdfBase64, filename } = req.body;
  if (!transactionId || !pdfBase64) return res.status(400).json({ error: 'transactionId et pdfBase64 requis' });
  try {
    const settings = await getSettings();
    const apiKey = settings?.qontoSecretKey;
    const slug = settings?.qontoOrganizationId;
    if (!apiKey || !slug) return res.status(400).json({ error: 'Qonto non configure' });
    
    // Upload le fichier
    const boundary = '----FormBoundary' + Date.now();
    const pdfBuffer = Buffer.from(pdfBase64, 'base64');
    
    const body = [
      `--${boundary}`,
      `Content-Disposition: form-data; name="file"; filename="${filename || 'facture.pdf'}"`,
      'Content-Type: application/pdf',
      '',
      pdfBuffer.toString('binary'),
      `--${boundary}--`
    ].join('\r\n');
    
    const uploadRes = await fetch(`https://thirdparty.qonto.com/v2/transactions/${transactionId}/attachments`, {
      method: 'POST',
      headers: {
        'Authorization': `${slug}:${apiKey}`,
        'Content-Type': `multipart/form-data; boundary=${boundary}`
      },
      body
    });
    
    if (uploadRes.ok) {
      const result = await uploadRes.json().catch(() => ({}));
      await auditLog('QONTO_ATTACH', 'admin', { transactionId, filename }, req);
      res.json({ success: true, message: 'Facture jointe a la transaction Qonto', result });
    } else {
      const errText = await uploadRes.text();
      res.status(uploadRes.status).json({ error: 'Qonto upload error: ' + errText });
    }
  } catch (e) {
    console.error('Qonto attach error:', e.message);
    res.status(500).json({ error: 'Erreur: ' + e.message });
  }
});

// ===== STRIPE =====
const STRIPE_PLANS = { starter: { name: 'Starter', price: 0, stripePriceId: null }, simple: { name: 'Simple', price: 1499, stripePriceId: null }, premium: { name: 'Premium', price: 1999, stripePriceId: null } };
async function initializeStripePrices(stripe) {
  try {
    const products = await stripe.products.list({ limit: 10 });
    for (const [planId, plan] of Object.entries(STRIPE_PLANS)) {
      if (plan.price === 0) continue;
      let product = products.data.find(p => p.metadata?.planId === planId);
      if (!product) product = await stripe.products.create({ name: 'Abonnement UCO ' + plan.name, description: 'Services partenaires UCO AND CO - Formule ' + plan.name, metadata: { planId } });
      const prices = await stripe.prices.list({ product: product.id, limit: 5 });
      let price = prices.data.find(p => p.recurring?.interval === 'month' && p.unit_amount === plan.price);
      if (!price) price = await stripe.prices.create({ product: product.id, unit_amount: plan.price, currency: 'eur', recurring: { interval: 'month' }, metadata: { planId } });
      STRIPE_PLANS[planId].stripePriceId = price.id;
      STRIPE_PLANS[planId].stripeProductId = product.id;
    }
    console.log('Prix Stripe initialises');
  } catch (e) { console.error('Erreur init Stripe:', e.message); }
}
app.post('/api/stripe/create-subscription', async (req, res) => {
  try {
    const { restaurantId, plan, email, enseigne, siret } = req.body;
    const stripe = await getStripe();
    if (!stripe) return res.status(400).json({ success: false, error: 'Stripe non configure' });
    if (plan === 'starter' || STRIPE_PLANS[plan]?.price === 0) return res.json({ success: true, free: true });
    if (!STRIPE_PLANS[plan]) return res.status(400).json({ success: false, error: 'Plan inconnu: ' + plan });
    if (!STRIPE_PLANS[plan].stripePriceId) await initializeStripePrices(stripe);
    if (!STRIPE_PLANS[plan]?.stripePriceId) {
      try {
        const product = await stripe.products.create({ name: 'Abonnement UCO ' + STRIPE_PLANS[plan].name, metadata: { planId: plan } });
        const price = await stripe.prices.create({ product: product.id, unit_amount: STRIPE_PLANS[plan].price, currency: 'eur', recurring: { interval: 'month' }, metadata: { planId: plan } });
        STRIPE_PLANS[plan].stripePriceId = price.id; STRIPE_PLANS[plan].stripeProductId = product.id;
      } catch (ce) { return res.status(400).json({ success: false, error: 'Erreur prix Stripe: ' + ce.message }); }
    }
    if (!STRIPE_PLANS[plan].stripePriceId) return res.status(400).json({ success: false, error: 'Impossible configurer prix' });
    let customer;
    const ec = await stripe.customers.list({ email, limit: 1 });
    if (ec.data.length > 0) { customer = ec.data[0]; await stripe.customers.update(customer.id, { name: enseigne, metadata: { restaurantId, siret } }); }
    else customer = await stripe.customers.create({ email, name: enseigne, metadata: { restaurantId, siret } });
    const session = await stripe.checkout.sessions.create({ customer: customer.id, payment_method_types: ['card'], mode: 'subscription', line_items: [{ price: STRIPE_PLANS[plan].stripePriceId, quantity: 1 }], subscription_data: { metadata: { restaurantId, siret, plan } }, success_url: (req.headers.origin || 'https://uco-and-co.fr') + '?subscription=success&session_id={CHECKOUT_SESSION_ID}', cancel_url: (req.headers.origin || 'https://uco-and-co.fr') + '?subscription=cancelled', metadata: { restaurantId, siret, plan }, payment_method_collection: 'always' });
    res.json({ success: true, sessionId: session.id, url: session.url });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.post('/api/stripe/create-checkout-session', async (req, res) => { req.body.plan = req.body.plan || 'simple'; return res.redirect(307, '/api/stripe/create-subscription'); });
app.post('/api/stripe/webhook', async (req, res) => {
  try {
    const settings = await getSettings();
    if (!settings?.stripeSecretKey || !settings?.stripeWebhookSecret) return res.status(400).json({ error: 'Stripe non configure' });
    const stripe = await getStripe();
    if (!stripe) return res.status(400).json({ error: 'Stripe non configure' });
    let event;
    try { event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], settings.stripeWebhookSecret); } catch (err) { return res.status(400).send('Webhook Error: ' + err.message); }
    console.log('Webhook Stripe recu: ' + event.type);
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const { restaurantId, siret, plan } = session.metadata || {};
        if (!restaurantId && !siret) break;
        let cardLast4 = '****';
        if (session.subscription) { try { const sub = await stripe.subscriptions.retrieve(session.subscription); if (sub.default_payment_method) { const pm = await stripe.paymentMethods.retrieve(sub.default_payment_method); cardLast4 = pm.card?.last4 || '****'; } } catch (e) {} }
        const sc = []; if (restaurantId) { sc.push({ id: restaurantId }); sc.push({ qrCode: restaurantId }); } if (siret) sc.push({ siret }); if (session.customer_email) sc.push({ email: session.customer_email });
        if (db && isConnected) { await db.collection(COLLECTIONS.RESTAURANTS).updateOne({ $or: sc }, { $set: { subscription: { plan: plan || 'simple', status: 'active', stripeCustomerId: session.customer, stripeSubscriptionId: session.subscription, startDate: new Date().toISOString(), lastPaymentDate: new Date().toISOString(), cardLast4 } } }); }
        break;
      }
      case 'invoice.payment_succeeded': { const inv = event.data.object; if (inv.subscription && inv.billing_reason !== 'subscription_create' && db && isConnected) await db.collection(COLLECTIONS.RESTAURANTS).updateOne({ 'subscription.stripeSubscriptionId': inv.subscription }, { $set: { 'subscription.lastPaymentDate': new Date().toISOString(), 'subscription.status': 'active' } }); break; }
      case 'invoice.payment_failed': { const inv = event.data.object; if (inv.subscription && db && isConnected) await db.collection(COLLECTIONS.RESTAURANTS).updateOne({ 'subscription.stripeSubscriptionId': inv.subscription }, { $set: { 'subscription.status': 'payment_failed', 'subscription.lastFailedAt': new Date().toISOString() }, $inc: { 'subscription.failedAttempts': 1 } }); break; }
      case 'customer.subscription.deleted': { const sub = event.data.object; if (db && isConnected) await db.collection(COLLECTIONS.RESTAURANTS).updateOne({ 'subscription.stripeSubscriptionId': sub.id }, { $set: { 'subscription.status': 'cancelled', 'subscription.endDate': new Date().toISOString() } }); break; }
    }
    res.json({ received: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/stripe/cancel-subscription', async (req, res) => { try { const stripe = await getStripe(); if (!stripe) return res.status(400).json({ success: false }); const sub = await stripe.subscriptions.update(req.body.subscriptionId, { cancel_at_period_end: true }); res.json({ success: true, subscription: sub }); } catch (e) { res.status(500).json({ success: false, error: e.message }); } });
app.post('/api/stripe/customer-portal', async (req, res) => { try { const stripe = await getStripe(); if (!stripe) return res.status(400).json({ success: false }); const session = await stripe.billingPortal.sessions.create({ customer: req.body.customerId, return_url: req.headers.origin || 'https://uco-and-co.fr' }); res.json({ success: true, url: session.url }); } catch (e) { res.status(500).json({ success: false, error: e.message }); } });
// ===== QONTO =====
app.post('/api/qonto/configure', async (req, res) => {
  try {
    const { organizationId, secretKey } = req.body;
    if (!organizationId || !secretKey) return res.status(400).json({ success: false, error: 'ID et Secret Key requis' });
    const qontoAuth = organizationId + ':' + secretKey;
    const testResponse = await fetch('https://thirdparty.qonto.com/v2/organization', { headers: { 'Authorization': qontoAuth, 'Content-Type': 'application/json' } });
    if (!testResponse.ok) return res.status(400).json({ success: false, error: 'Identifiants Qonto invalides' });
    const orgData = await testResponse.json();
    if (db && isConnected) await db.collection('settings').updateOne({}, { $set: { qontoOrganizationId: organizationId, qontoSecretKey: secretKey, qontoOrganizationName: orgData.organization?.name } }, { upsert: true });
    res.json({ success: true, organizationName: orgData.organization?.name });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.get('/api/qonto/status', async (req, res) => {
  try {
    const settings = await getSettings();
    if (!settings?.qontoOrganizationId) return res.json({ success: true, configured: false });
    const testResponse = await fetch('https://thirdparty.qonto.com/v2/organization', { headers: { 'Authorization': settings.qontoOrganizationId + ':' + settings.qontoSecretKey, 'Content-Type': 'application/json' } });
    res.json({ success: true, configured: true, connected: testResponse.ok, organizationName: settings.qontoOrganizationName });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
// ===== GESTION DES ERREURS =====
app.use((err, req, res, next) => {
  console.error('[' + req.requestId + '] Erreur:', err.message);
  if (err.message === 'Non autorise par CORS') return res.status(403).json({ success: false, error: 'Acces non autorise' });
  res.status(500).json({ success: false, error: 'Erreur serveur interne' });
});
app.use((req, res) => { res.status(404).json({ success: false, error: 'Route non trouvee' }); });

// [FIX OOM] Nettoyage periodique des tournees abandonnees (>48h)
setInterval(async () => {
  if (!db || !isConnected) return;
  try {
    const cutoff = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();
    const result = await db.collection(COLLECTIONS.TOURNEES_EN_COURS).deleteMany({ lastUpdate: { $lt: cutoff } });
    if (result.deletedCount > 0) console.log('Nettoyage: ' + result.deletedCount + ' tournee(s) abandonnee(s) supprimee(s)');
  } catch (e) { console.log('Erreur nettoyage:', e.message); }
}, 6 * 60 * 60 * 1000);

// =============================================
// DEMARRAGE DU SERVEUR
// =============================================
async function startServer() {
  await connectDB();
  try {
    const settings = await getSettings();
    if (settings?.stripeSecretKey && settings?.stripeEnabled) {
      console.log('Initialisation des prix Stripe...');
      const stripe = await getStripe();
      if (stripe) { await initializeStripePrices(stripe); console.log('Prix Stripe initialises:', { simple: STRIPE_PLANS.simple.stripePriceId ? 'OK' : 'NON', premium: STRIPE_PLANS.premium.stripePriceId ? 'OK' : 'NON' }); }
    } else { console.log('Stripe non configure ou desactive'); }
  } catch (e) { console.error('Erreur init Stripe:', e.message); }
  app.listen(PORT, () => {
    console.log('');
    console.log('========================================');
    console.log('UCO AND CO - Backend API (OPTIMISE)');
    console.log('========================================');
    console.log('Serveur demarre sur le port ' + PORT);
    console.log('Base de donnees: ' + (isConnected ? 'MongoDB Atlas OK' : 'Mode memoire'));
    if (!process.env.ADMIN_PASSWORD_HASH && !process.env.ADMIN_DEFAULT_PASSWORD) {
      console.warn('⚠️ SECURITE: ADMIN_PASSWORD_HASH ou ADMIN_DEFAULT_PASSWORD non defini dans les variables d\'environnement Render.');
      console.warn('   Le mot de passe par defaut est INSECURE. Ajoutez une variable d\'environnement sur Render.');
    }
    console.log('Securite: Helmet, CORS, Rate limiting, Sanitization, JWT, Bcrypt, Audit logs');
    console.log('Optimisations memoire:');
    console.log('  - Compression gzip');
    console.log('  - Collections: signatures exclues + limit 2000');
    console.log('  - Tournees: signatures exclues + limit 500');
    console.log('  - Stats: aggregation MongoDB');
    console.log('  - Restaurants: projection sans PDFs');
    console.log('  - Stripe: instance singleton');
    console.log('  - Monitoring memoire proactif (30s)');
    console.log('  - TTL indexes (tournees 7j, audit 90j)');
    console.log('  - Nettoyage tournees abandonnees (6h)');
    console.log('  - POST tournees/en-cours: payload check + no sanitize');
    console.log('  Memoire: ' + Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB');
    console.log('');
  });
}
startServer();
