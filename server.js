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

const app = express();
const PORT = process.env.PORT || 3001;

// =============================================
// GESTION DES ERREURS GLOBALES - ANTI-CRASH
// =============================================
process.on('uncaughtException', (err) => {
  console.error('❌ [UNCAUGHT EXCEPTION]', err.message);
  console.error(err.stack);
  // NE PAS faire process.exit() - laisser le serveur tourner
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ [UNHANDLED REJECTION]', reason);
  // NE PAS faire process.exit() - laisser le serveur tourner
});

// =============================================
// CONFIGURATION SÉCURITÉ
// =============================================
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = '24h';
const BCRYPT_ROUNDS = 12;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000;

// =============================================
// MIDDLEWARES DE SÉCURITÉ
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

const allowedOrigins = [
  'https://uco-and-co.netlify.app',
  'https://uco-and-co.fr',
  'https://www.uco-and-co.fr',
  process.env.FRONTEND_URL,
  'http://localhost:3000',
  'http://localhost:5173'
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
      console.warn('🚫 CORS bloqué:', origin);
      callback(new Error('Non autorisé par CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID']
}));

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: { success: false, error: 'Trop de requêtes, réessayez dans 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/api/health' || (req.path === '/api/settings' && req.method === 'GET')
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, error: 'Trop de tentatives de connexion, réessayez dans 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
});

const strictLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { success: false, error: 'Limite atteinte, réessayez plus tard' },
});

app.use('/api/', generalLimiter);
app.use('/api/auth/', authLimiter);
app.use('/api/password-reset', strictLimiter);

app.set('trust proxy', 1);

app.use((req, res, next) => {
  if (req.originalUrl === '/api/stripe/webhook') {
    // Pour Stripe: body brut en Buffer
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
    console.warn(`🚫 Tentative d'injection NoSQL détectée: ${key}`);
  }
}));

app.use(xss());
app.use(hpp());

app.use((req, res, next) => {
  const requestId = uuidv4().slice(0, 8);
  req.requestId = requestId;
  if (req.path.includes('/auth') || req.path.includes('/password')) {
    console.log(`[${new Date().toISOString()}] ${requestId} ${req.method} ${req.path} - IP: ${req.ip}`);
  }
  res.setHeader('X-Request-ID', requestId);
  next();
});

// =============================================
// CONFIGURATION MONGODB ATLAS - ROBUSTE
// =============================================
const MONGODB_URI = process.env.MONGODB_URI || '';
const DB_NAME = 'ucoandco';

let db = null;
let mongoClient = null;
let isConnected = false;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 10;

// Options de connexion robustes
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
    email: 'contact@uco-and-co.com',
    password: bcrypt.hashSync('30Septembre2006A$', BCRYPT_ROUNDS),
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
  AVIS: 'avis'
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
    console.warn('⚠️ MONGODB_URI non configurée - Mode mémoire uniquement');
    return false;
  }

  try {
    console.log('🔄 Connexion sécurisée à MongoDB Atlas...');
    mongoClient = new MongoClient(MONGODB_URI, mongoOptions);
    
    mongoClient.on('close', () => {
      console.warn('⚠️ Connexion MongoDB fermée');
      isConnected = false;
      scheduleReconnect();
    });
    
    mongoClient.on('error', (err) => {
      console.error('❌ Erreur MongoDB:', err.message);
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
      //Index pour tournées en cours (synchronisation multi-appareils)
      await db.collection(COLLECTIONS.TOURNEES_EN_COURS).createIndex({ collectorEmail: 1 }, { unique: true });
    } catch (indexError) {
      console.warn('⚠️ Erreur création index:', indexError.message);
    }
    
    try {
      const existingSettings = await db.collection(COLLECTIONS.SETTINGS).findOne({ _id: 'main' });
      if (!existingSettings) {
        await db.collection(COLLECTIONS.SETTINGS).insertOne({ 
          _id: 'main', 
          ...initialData.settings, 
          admin: initialData.admin 
        });
      }
    } catch (settingsError) {
      console.warn('⚠️ Erreur initialisation settings:', settingsError.message);
    }
    
    console.log('✅ Connecté à MongoDB Atlas avec succès (mode sécurisé)');
    return true;
  } catch (error) {
    console.error('❌ Erreur connexion MongoDB:', error.message);
    isConnected = false;
    scheduleReconnect();
    return false;
  }
}

function scheduleReconnect() {
  if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
    console.error('❌ Max tentatives de reconnexion atteint. Le serveur continue sans DB.');
    return;
  }
  
  reconnectAttempts++;
  const delay = Math.min(5000 * reconnectAttempts, 30000);
  
  console.log(`🔄 Tentative de reconnexion ${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS} dans ${delay/1000}s...`);
  
  setTimeout(async () => {
    if (!isConnected) {
      try {
        if (mongoClient) {
          await mongoClient.close().catch(() => {});
        }
        await connectDB();
      } catch (e) {
        console.error('❌ Échec reconnexion:', e.message);
        scheduleReconnect();
      }
    }
  }, delay);
}

function checkDBConnection(req, res, next) {
  if (req.path === '/api/health') {
    return next();
  }
  
  if (!isConnected || !db) {
    console.warn('⚠️ Requête reçue mais DB non connectée:', req.path);
    return res.status(503).json({
      success: false,
      error: 'Service temporairement indisponible - Base de données en cours de reconnexion',
      retryAfter: 5
    });
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
// Routes Stripe Webhook
const stripeWebhook = require('./routes/stripe-webhook');
app.use('/api/stripe', stripeWebhook);
// Routes demandes de collecte (urgences)
const demandesCollecteRoutes = require('./routes/demandes-collecte');
app.use('/api/demandes-collecte', demandesCollecteRoutes);

process.on('SIGINT', async () => {
  console.log('\n🛑 Arrêt du serveur (SIGINT)...');
  if (mongoClient) {
    try { await mongoClient.close(); console.log('✅ Connexion MongoDB fermée'); } catch (e) {}
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n🛑 Arrêt du serveur (SIGTERM)...');
  if (mongoClient) {
    try { await mongoClient.close(); } catch (e) {}
  }
  process.exit(0);
});

// =============================================
// FONCTIONS UTILITAIRES DE SÉCURITÉ
// =============================================

function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function isStrongPassword(password) {
  const strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return strongRegex.test(password);
}

function sanitizeInput(input, key = '') {
  if (typeof input !== 'string') return input;
  const unlimitedFields = ['restaurant', 'admin', 'collecteur', 'base64', 'content', 'data', 'signature', 'contrat', 'bordereau'];
  const isUnlimited = unlimitedFields.some(f => key.toLowerCase().includes(f));
  const sanitized = input.replace(/[<>]/g, '').trim();
  return isUnlimited ? sanitized : sanitized.slice(0, 5000);
}

function sanitizeObject(obj, parentKey = '') {
  if (typeof obj !== 'object' || obj === null) {
    return sanitizeInput(obj, parentKey);
  }
  const sanitized = Array.isArray(obj) ? [] : {};
  for (const key of Object.keys(obj)) {
    if (key.startsWith('$')) continue;
    sanitized[key] = sanitizeObject(obj[key], key);
  }
  return sanitized;
}

function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ success: false, error: 'Token manquant' });
  }
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(403).json({ success: false, error: 'Token invalide ou expiré' });
  }
  req.user = decoded;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Accès non autorisé' });
    }
    next();
  };
}

async function auditLog(action, userId, details, req) {
  if (!db || !isConnected) return;
  try {
    await db.collection(COLLECTIONS.AUDIT_LOGS).insertOne({
      _id: uuidv4(),
      action,
      userId,
      details: sanitizeObject(details),
      ip: req?.ip || 'unknown',
      userAgent: req?.headers['user-agent'] || 'unknown',
      requestId: req?.requestId,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Erreur audit log:', error.message);
  }
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
  } catch (e) {
    console.error('Erreur incrementLoginAttempts:', e.message);
  }
}

async function resetLoginAttempts(collection, identifier) {
  if (!db || !isConnected) return;
  try {
    await db.collection(collection).updateOne(
      { email: identifier },
      { $set: { loginAttempts: 0, lockUntil: null } }
    );
  } catch (e) {
    console.error('Erreur resetLoginAttempts:', e.message);
  }
}

// =============================================
// FONCTIONS D'ACCÈS AUX DONNÉES
// =============================================

async function getSettings() {
  try {
    if (!db || !isConnected) return initialData.settings;
    
    if (cache.settings && (Date.now() - cache.lastSettingsUpdate) < cache.TTL) {
      return cache.settings;
    }
    
    const allSettings = await db.collection('settings').find({}).toArray();
    
    if (allSettings.length === 0) {
      return initialData.settings;
    }
    
    let mergedSettings = {};
    for (const doc of allSettings) {
      mergedSettings = { ...mergedSettings, ...doc };
    }
    
    cache.settings = mergedSettings;
    cache.lastSettingsUpdate = Date.now();
    
    console.log('✅ Settings chargés:', {
      hasStripeSecretKey: !!mergedSettings.stripeSecretKey,
      hasStripePublicKey: !!mergedSettings.stripePublicKey,
      stripeEnabled: mergedSettings.stripeEnabled,
      qontoEnabled: mergedSettings.qontoEnabled
    });
    
    return mergedSettings;
  } catch (error) {
    console.error('❌ Erreur récupération settings:', error.message);
    return initialData.settings;
  }
}

async function updateSettings(newSettings) {
  if (!db || !isConnected) return false;
  
  try {
    const existingSettings = await getSettings() || {};
    
    const mergedSettings = {
      ...existingSettings,
      ...newSettings,
      admin: existingSettings.admin,
      reviewLinks: {
        ...(existingSettings.reviewLinks || {}),
        ...(newSettings.reviewLinks || {})
      }
    };
    
    if (!newSettings.brevoApiKey && existingSettings.brevoApiKey) {
      mergedSettings.brevoApiKey = existingSettings.brevoApiKey;
    }
    if (!newSettings.stripeSecretKey && existingSettings.stripeSecretKey) {
      mergedSettings.stripeSecretKey = existingSettings.stripeSecretKey;
    }
    if ((!newSettings.stripePublicKey || newSettings.stripePublicKey.startsWith('••••')) && existingSettings.stripePublicKey) {
      mergedSettings.stripePublicKey = existingSettings.stripePublicKey;
    }
    if (!newSettings.stripeWebhookSecret && existingSettings.stripeWebhookSecret) {
      mergedSettings.stripeWebhookSecret = existingSettings.stripeWebhookSecret;
    }
    if (!newSettings.qontoSecretKey && existingSettings.qontoSecretKey) {
      mergedSettings.qontoSecretKey = existingSettings.qontoSecretKey;
    }
    if (!newSettings.qontoOrganizationId && existingSettings.qontoOrganizationId) {
      mergedSettings.qontoOrganizationId = existingSettings.qontoOrganizationId;
    }
    if (!newSettings.qontoOrganizationName && existingSettings.qontoOrganizationName) {
      mergedSettings.qontoOrganizationName = existingSettings.qontoOrganizationName;
    }
    
    delete mergedSettings._id;
    
    const existingDoc = await db.collection(COLLECTIONS.SETTINGS).findOne({});
    const docId = existingDoc?._id || 'main';
    
    await db.collection(COLLECTIONS.SETTINGS).updateOne(
      { _id: docId },
      { $set: mergedSettings },
      { upsert: true }
    );
    
    cache.settings = null;
    cache.lastSettingsUpdate = 0;
    
    console.log('✅ Settings mis à jour avec succès');
    return true;
  } catch (error) {
    console.error('❌ Erreur updateSettings:', error.message);
    return false;
  }
}

async function getAdmin() {
  const settings = await getSettings();
  return settings.admin || initialData.admin;
}

// Collecteurs
async function getCollectors(status = null) {
  if (!db || !isConnected) return [];
  try {
    const query = status ? { status } : {};
    return await db.collection(COLLECTIONS.COLLECTORS).find(query).toArray();
  } catch (e) {
    console.error('Erreur getCollectors:', e.message);
    return [];
  }
}

async function getCollectorByEmail(email) {
  if (!db || !isConnected) return null;
  try {
    return await db.collection(COLLECTIONS.COLLECTORS).findOne({ email: sanitizeInput(email) });
  } catch (e) {
    console.error('Erreur getCollectorByEmail:', e.message);
    return null;
  }
}

async function addCollector(collector) {
  if (!db || !isConnected) return null;
  try {
    const sanitized = sanitizeObject(collector);
    const result = await db.collection(COLLECTIONS.COLLECTORS).insertOne({
      ...sanitized,
      _id: sanitized.email,
      loginAttempts: 0,
      lockUntil: null,
      createdAt: new Date().toISOString()
    });
    return result.insertedId;
  } catch (e) {
    console.error('Erreur addCollector:', e.message);
    return null;
  }
}

async function updateCollector(email, data) {
  if (!db || !isConnected) return false;
  try {
    await db.collection(COLLECTIONS.COLLECTORS).updateOne(
      { email: sanitizeInput(email) },
      { $set: { ...sanitizeObject(data), updatedAt: new Date().toISOString() } }
    );
    return true;
  } catch (e) {
    console.error('Erreur updateCollector:', e.message);
    return false;
  }
}

async function deleteCollector(email) {
  if (!db || !isConnected) return false;
  try {
    await db.collection(COLLECTIONS.COLLECTORS).deleteOne({ email: sanitizeInput(email) });
    return true;
  } catch (e) {
    console.error('Erreur deleteCollector:', e.message);
    return false;
  }
}

// Opérateurs
async function getOperators(status = null) {
  if (!db || !isConnected) return [];
  try {
    const query = status ? { status } : {};
    return await db.collection(COLLECTIONS.OPERATORS).find(query).toArray();
  } catch (e) {
    console.error('Erreur getOperators:', e.message);
    return [];
  }
}

async function getOperatorByEmail(email) {
  if (!db || !isConnected) return null;
  try {
    return await db.collection(COLLECTIONS.OPERATORS).findOne({ email: sanitizeInput(email) });
  } catch (e) {
    console.error('Erreur getOperatorByEmail:', e.message);
    return null;
  }
}

async function addOperator(operator) {
  if (!db || !isConnected) return null;
  try {
    const sanitized = sanitizeObject(operator);
    const result = await db.collection(COLLECTIONS.OPERATORS).insertOne({
      ...sanitized,
      _id: sanitized.email,
      loginAttempts: 0,
      lockUntil: null,
      createdAt: new Date().toISOString()
    });
    return result.insertedId;
  } catch (e) {
    console.error('Erreur addOperator:', e.message);
    return null;
  }
}

async function updateOperator(email, data) {
  if (!db || !isConnected) return false;
  try {
    await db.collection(COLLECTIONS.OPERATORS).updateOne(
      { email: sanitizeInput(email) },
      { $set: { ...sanitizeObject(data), updatedAt: new Date().toISOString() } }
    );
    return true;
  } catch (e) {
    console.error('Erreur updateOperator:', e.message);
    return false;
  }
}

async function deleteOperator(email) {
  if (!db || !isConnected) return false;
  try {
    await db.collection(COLLECTIONS.OPERATORS).deleteOne({ email: sanitizeInput(email) });
    return true;
  } catch (e) {
    console.error('Erreur deleteOperator:', e.message);
    return false;
  }
}

// Restaurants
async function getRestaurants(status = null) {
  if (!db || !isConnected) return [];
  try {
    const query = status ? { status } : {};
    return await db.collection(COLLECTIONS.RESTAURANTS).find(query).toArray();
  } catch (e) {
    console.error('Erreur getRestaurants:', e.message);
    return [];
  }
}

async function getRestaurantById(id) {
  if (!db || !isConnected) return null;
  try {
    const sanitizedId = sanitizeInput(id);
    return await db.collection(COLLECTIONS.RESTAURANTS).findOne({ 
      $or: [
        { id: sanitizedId },
        { siret: sanitizedId },
        { qrCode: sanitizedId }
      ]
    });
  } catch (e) {
    console.error('Erreur getRestaurantById:', e.message);
    return null;
  }
}

async function getRestaurantByQRCode(qrCode) {
  if (!db || !isConnected) return null;
  try {
    return await db.collection(COLLECTIONS.RESTAURANTS).findOne({ qrCode: sanitizeInput(qrCode) });
  } catch (e) {
    console.error('Erreur getRestaurantByQRCode:', e.message);
    return null;
  }
}

async function getRestaurantByEmail(email) {
  if (!db || !isConnected) return null;
  try {
    return await db.collection(COLLECTIONS.RESTAURANTS).findOne({ email: sanitizeInput(email) });
  } catch (e) {
    console.error('Erreur getRestaurantByEmail:', e.message);
    return null;
  }
}

async function addRestaurant(restaurant) {
  if (!db || !isConnected) return null;
  try {
    const sanitized = sanitizeObject(restaurant);
    const result = await db.collection(COLLECTIONS.RESTAURANTS).insertOne({
      ...sanitized,
      _id: sanitized.id,
      loginAttempts: 0,
      lockUntil: null,
      createdAt: new Date().toISOString()
    });
    return result.insertedId;
  } catch (e) {
    console.error('Erreur addRestaurant:', e.message);
    return null;
  }
}

async function updateRestaurant(id, data) {
  if (!db || !isConnected) return false;
  try {
    const sanitizedId = sanitizeInput(id);
    await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
      { $or: [{ id: sanitizedId }, { siret: sanitizedId }, { qrCode: sanitizedId }] },
      { $set: { ...sanitizeObject(data), updatedAt: new Date().toISOString() } }
    );
    return true;
  } catch (e) {
    console.error('Erreur updateRestaurant:', e.message);
    return false;
  }
}

async function deleteRestaurant(id) {
  if (!db || !isConnected) return false;
  try {
    await db.collection(COLLECTIONS.RESTAURANTS).deleteOne({ id: sanitizeInput(id) });
    return true;
  } catch (e) {
    console.error('Erreur deleteRestaurant:', e.message);
    return false;
  }
}

// Collections
async function getCollections() {
  if (!db || !isConnected) return [];
  try {
    return await db.collection(COLLECTIONS.COLLECTIONS).find({}).sort({ date: -1 }).toArray();
  } catch (e) {
    console.error('Erreur getCollections:', e.message);
    return [];
  }
}

async function addCollection(collection) {
  if (!db || !isConnected) return null;
  try {
    const sanitized = sanitizeObject(collection);
    const result = await db.collection(COLLECTIONS.COLLECTIONS).insertOne({
      ...sanitized,
      _id: sanitized.id || uuidv4(),
      createdAt: new Date().toISOString()
    });
    return result.insertedId;
  } catch (e) {
    console.error('Erreur addCollection:', e.message);
    return null;
  }
}

// Tournées
async function getTournees() {
  if (!db || !isConnected) return [];
  try {
    return await db.collection(COLLECTIONS.TOURNEES).find({}).sort({ dateDepart: -1 }).toArray();
  } catch (e) {
    console.error('Erreur getTournees:', e.message);
    return [];
  }
}

async function addTournee(tournee) {
  if (!db || !isConnected) return null;
  try {
    const sanitized = sanitizeObject(tournee);
    const result = await db.collection(COLLECTIONS.TOURNEES).insertOne({
      ...sanitized,
      _id: sanitized.id || uuidv4(),
      createdAt: new Date().toISOString()
    });
    return result.insertedId;
  } catch (e) {
    console.error('Erreur addTournee:', e.message);
    return null;
  }
}

async function updateTournee(id, data) {
  if (!db || !isConnected) return false;
  try {
    await db.collection(COLLECTIONS.TOURNEES).updateOne(
      { _id: sanitizeInput(id) },
      { $set: sanitizeObject(data) }
    );
    return true;
  } catch (e) {
    console.error('Erreur updateTournee:', e.message);
    return false;
  }
}

// Numéros uniques
async function generateCollectorNumber() {
  const collectors = await getCollectors('approved');
  const existingNumbers = collectors.filter(c => c.collectorNumber).map(c => c.collectorNumber);
  let num = 1;
  while (existingNumbers.includes(num)) num++;
  return num;
}

async function generateOperatorNumber() {
  const operators = await getOperators('approved');
  const existingNumbers = operators.filter(o => o.operatorNumber).map(o => o.operatorNumber);
  let num = 1;
  while (existingNumbers.includes(num)) num++;
  return num;
}

// =============================================
// ROUTES API
// =============================================

// ===== PROXY APIs GOUVERNEMENTALES =====
app.get('/api/proxy/siret/:siret', async (req, res) => {
  try {
    const siret = req.params.siret.replace(/\D/g, '');
    if (siret.length !== 14) {
      return res.status(400).json({ error: 'SIRET invalide (14 chiffres requis)' });
    }
    const response = await fetch(`https://recherche-entreprises.api.gouv.fr/search?q=${siret}&page=1&per_page=1`);
    if (!response.ok) {
      return res.status(response.status).json({ error: 'API non disponible' });
    }
    const data = await response.json();
    res.json(data);
  } catch (e) {
    console.error('Erreur proxy SIRET:', e.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/proxy/villes/:cp', async (req, res) => {
  try {
    const cp = req.params.cp.replace(/\D/g, '');
    if (cp.length !== 5) {
      return res.status(400).json({ error: 'Code postal invalide (5 chiffres requis)' });
    }
    const response = await fetch(`https://geo.api.gouv.fr/communes?codePostal=${cp}&fields=nom&format=json`);
    if (!response.ok) {
      return res.status(response.status).json({ error: 'API non disponible' });
    }
    const data = await response.json();
    res.json(data);
  } catch (e) {
    console.error('Erreur proxy villes:', e.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Health check - TOUJOURS retourne 200
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    database: isConnected ? 'MongoDB Atlas' : 'MongoDB disconnected',
    persistent: isConnected,
    secure: true,
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    reconnectAttempts: reconnectAttempts
  });
});

// Test email
app.post('/api/test-email', async (req, res) => {
  try {
    const { to } = req.body;
    if (!to) {
      return res.status(400).json({ success: false, error: 'Email destinataire requis' });
    }
    const settings = await getSettings();
    const apiKey = settings.brevoApiKey;
    if (!apiKey) {
      return res.status(503).json({ success: false, error: 'Clé API Brevo non configurée' });
    }
    const simpleHtml = '<html><head><meta charset="UTF-8"></head><body><h1 style="color:green;">Test UCO AND CO</h1><p>Si ce texte est <strong>vert</strong>, le HTML fonctionne correctement!</p><p>Date: ' + new Date().toLocaleString('fr-FR') + '</p></body></html>';
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'api-key': apiKey,
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        sender: { name: 'UCO AND CO', email: 'contact@uco-and-co.fr' },
        to: [{ email: to }],
        subject: 'Test HTML UCO AND CO',
        htmlContent: simpleHtml
      })
    });
    const responseData = await response.json();
    if (response.ok) {
      res.json({ success: true, messageId: responseData.messageId });
    } else {
      res.status(502).json({ success: false, error: responseData.message || 'Erreur Brevo', details: responseData });
    }
  } catch (error) {
    console.error('Erreur test email:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});
// =============================================
// TOURNÉES EN COURS - SYNCHRONISATION MULTI-APPAREILS
// =============================================

/**
 * GET /api/tournees/en-cours/:email
 * Récupère la tournée en cours d'un collecteur
 */
app.get('/api/tournees/en-cours/:email', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    
    const email = decodeURIComponent(req.params.email);
    console.log(`📱 [SYNC] Recherche tournée en cours pour: ${email}`);
    
    const tournee = await db.collection(COLLECTIONS.TOURNEES_EN_COURS).findOne({ 
      collectorEmail: email,
      active: true,
      dateFin: null
    });
    
    if (tournee) {
      console.log(`✅ [SYNC] Tournée trouvée: ${tournee.id}, collectes: ${tournee.collectes?.length || 0}`);
      const { _id, ...tourneeData } = tournee;
      return res.json(tourneeData);
    }
    
    console.log(`ℹ️ [SYNC] Pas de tournée en cours pour: ${email}`);
    return res.json(null);
    
  } catch (error) {
    console.error('❌ Erreur GET tournee en cours:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur', details: error.message });
  }
});

/**
 * POST /api/tournees/en-cours
 * Sauvegarde/met à jour une tournée en cours
 */
app.post('/api/tournees/en-cours', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    
    const tourneeData = sanitizeObject(req.body);
    
    if (!tourneeData.collectorEmail) {
      return res.status(400).json({ success: false, error: 'collectorEmail requis' });
    }
    
    tourneeData.lastUpdate = new Date().toISOString();
    
    console.log(`💾 [SYNC] Sauvegarde tournée: ${tourneeData.id}, collectes: ${tourneeData.collectes?.length || 0}`);
    
    const result = await db.collection(COLLECTIONS.TOURNEES_EN_COURS).updateOne(
      { collectorEmail: tourneeData.collectorEmail },
      { $set: { ...tourneeData, _id: tourneeData.collectorEmail } },
      { upsert: true }
    );
    
    console.log(`✅ [SYNC] Tournée sauvegardée`);
    res.json({ success: true, tourneeId: tourneeData.id });
    
  } catch (error) {
    console.error('❌ Erreur POST tournee en cours:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur', details: error.message });
  }
});

/**
 * DELETE /api/tournees/en-cours/:email
 * Supprime la tournée en cours (quand terminée)
 */
app.delete('/api/tournees/en-cours/:email', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    
    const email = decodeURIComponent(req.params.email);
    console.log(`🗑️ [SYNC] Suppression tournée pour: ${email}`);
    
    const result = await db.collection(COLLECTIONS.TOURNEES_EN_COURS).deleteOne({ collectorEmail: email });
    
    console.log(`✅ [SYNC] Supprimé: ${result.deletedCount > 0}`);
    return res.json({ success: true, deleted: result.deletedCount > 0 });
    
  } catch (error) {
    console.error('❌ Erreur DELETE tournee en cours:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur', details: error.message });
  }
});

/**
 * POST /api/tournees/paused
 * Sauvegarde une tournée mise en pause
 */
app.post('/api/tournees/paused', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    
    const tourneeData = sanitizeObject(req.body);
    
    if (!tourneeData.collectorEmail) {
      return res.status(400).json({ success: false, error: 'collectorEmail requis' });
    }
    
    console.log(`⏸️ [SYNC] Pause tournée pour: ${tourneeData.collectorEmail}`);
    
    const result = await db.collection(COLLECTIONS.TOURNEES_EN_COURS).updateOne(
      { collectorEmail: tourneeData.collectorEmail },
      { 
        $set: {
          ...tourneeData,
          _id: tourneeData.collectorEmail,
          isPaused: true,
          status: 'paused',
          pausedAt: new Date().toISOString(),
          lastUpdate: new Date().toISOString()
        }
      },
      { upsert: true }
    );
    
    console.log(`✅ [SYNC] Tournée en pause sauvegardée`);
    res.json({ success: true, tourneeId: tourneeData.id });
    
  } catch (error) {
    console.error('❌ Erreur POST tournee paused:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur', details: error.message });
  }
});

// ===== FIN ROUTES SYNCHRONISATION =====
// ===== AUTHENTIFICATION SÉCURISÉE =====
app.post('/api/auth/admin', async (req, res) => {
  try {
    const { email, password } = sanitizeObject(req.body);
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
    }
    const admin = await getAdmin();
    if (isAccountLocked(admin)) {
      await auditLog('ADMIN_LOGIN_LOCKED', email, { reason: 'Account locked' }, req);
      return res.status(423).json({ success: false, error: 'Compte verrouillé. Réessayez dans 15 minutes.' });
    }
    if (email !== admin.email) {
      await auditLog('ADMIN_LOGIN_FAILED', email, { reason: 'Invalid email' }, req);
      return res.status(401).json({ success: false, error: 'Identifiants incorrects' });
    }
    const isValid = await bcrypt.compare(password, admin.password);
    if (!isValid) {
      await auditLog('ADMIN_LOGIN_FAILED', email, { reason: 'Invalid password' }, req);
      return res.status(401).json({ success: false, error: 'Identifiants incorrects' });
    }
    const token = generateToken({ role: 'admin', email });
    await auditLog('ADMIN_LOGIN_SUCCESS', email, {}, req);
    res.json({ success: true, role: 'admin', token, expiresIn: JWT_EXPIRES_IN });
  } catch (error) {
    console.error('Erreur auth admin:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.post('/api/auth/collector', async (req, res) => {
  try {
    const { email, password } = sanitizeObject(req.body);
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, error: 'Format d\'email invalide' });
    }
    const collector = await getCollectorByEmail(email);
    if (!collector) {
      await auditLog('COLLECTOR_LOGIN_FAILED', email, { reason: 'Not found' }, req);
      return res.status(401).json({ success: false, error: 'Compte non trouvé' });
    }
    if (collector.status === 'pending') {
      return res.json({ success: false, error: 'pending' });
    }
    if (collector.status !== 'approved') {
      return res.status(401).json({ success: false, error: 'Compte non approuvé' });
    }
    if (isAccountLocked(collector)) {
      await auditLog('COLLECTOR_LOGIN_LOCKED', email, { reason: 'Account locked' }, req);
      return res.status(423).json({ success: false, error: 'Compte verrouillé. Réessayez dans 15 minutes.' });
    }
    const isValid = await bcrypt.compare(password, collector.password);
    if (!isValid) {
      await incrementLoginAttempts(COLLECTIONS.COLLECTORS, email);
      await auditLog('COLLECTOR_LOGIN_FAILED', email, { reason: 'Invalid password' }, req);
      return res.status(401).json({ success: false, error: 'Mot de passe incorrect' });
    }
    await resetLoginAttempts(COLLECTIONS.COLLECTORS, email);
    const token = generateToken({ role: 'collector', email, collectorNumber: collector.collectorNumber });
    const { password: _, loginAttempts, lockUntil, ...data } = collector;
    await auditLog('COLLECTOR_LOGIN_SUCCESS', email, {}, req);
    res.json({ success: true, role: 'collector', data, token, expiresIn: JWT_EXPIRES_IN });
  } catch (error) {
    console.error('Erreur auth collector:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.post('/api/auth/operator', async (req, res) => {
  try {
    const { email, password } = sanitizeObject(req.body);
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
    }
    const operator = await getOperatorByEmail(email);
    if (!operator) {
      await auditLog('OPERATOR_LOGIN_FAILED', email, { reason: 'Not found' }, req);
      return res.status(401).json({ success: false, error: 'Compte non trouvé' });
    }
    if (operator.status === 'pending') {
      return res.json({ success: false, error: 'pending' });
    }
    if (operator.status !== 'approved') {
      return res.status(401).json({ success: false, error: 'Compte non approuvé' });
    }
    if (isAccountLocked(operator)) {
      return res.status(423).json({ success: false, error: 'Compte verrouillé' });
    }
    const isValid = await bcrypt.compare(password, operator.password);
    if (!isValid) {
      await incrementLoginAttempts(COLLECTIONS.OPERATORS, email);
      return res.status(401).json({ success: false, error: 'Mot de passe incorrect' });
    }
    await resetLoginAttempts(COLLECTIONS.OPERATORS, email);
    const token = generateToken({ role: 'operator', email });
    const { password: _, loginAttempts, lockUntil, ...data } = operator;
    await auditLog('OPERATOR_LOGIN_SUCCESS', email, {}, req);
    res.json({ success: true, role: 'operator', data, token });
  } catch (error) {
    console.error('Erreur auth operator:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.post('/api/auth/restaurant', async (req, res) => {
  try {
    const { email, password } = sanitizeObject(req.body);
    console.log('=== AUTH RESTAURANT ===');
    console.log('Email:', email);
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
    }
    const restaurant = await getRestaurantByEmail(email);
    console.log('Restaurant trouvé:', restaurant ? 'Oui' : 'Non');
    if (restaurant) {
      console.log('- ID:', restaurant.id);
      console.log('- Status:', restaurant.status);
      console.log('- Has password:', !!restaurant.password);
      console.log('- Has tempPassword:', !!restaurant.tempPassword);
      console.log('- CreatedBy:', restaurant.createdBy);
    }
    if (!restaurant) {
      return res.status(401).json({ success: false, error: 'Compte non trouvé' });
    }
    if (restaurant.status === 'pending') {
      return res.json({ success: false, error: 'pending' });
    }
    if (restaurant.status === 'terminated') {
      return res.status(401).json({ success: false, error: 'Contrat résilié' });
    }
    const isApproved = restaurant.status === 'approved' || 
                       (restaurant.tempPassword && !restaurant.status) ||
                       (restaurant.createdBy === 'admin' && !restaurant.status);
    if (!isApproved) {
      return res.status(401).json({ success: false, error: 'Compte non approuvé' });
    }
    if (isAccountLocked(restaurant)) {
      return res.status(423).json({ success: false, error: 'Compte verrouillé' });
    }
    let isValid = false;
    let usedTempPassword = false;
    if (restaurant.password) {
      try {
        isValid = await bcrypt.compare(password, restaurant.password);
        console.log('Vérification mot de passe hashé:', isValid);
      } catch (bcryptError) {
        console.error('Erreur bcrypt:', bcryptError);
      }
    }
    if (!isValid && restaurant.tempPassword) {
      isValid = (password === restaurant.tempPassword);
      usedTempPassword = isValid;
      console.log('Vérification mot de passe provisoire:', isValid);
    }
    if (!isValid) {
      await incrementLoginAttempts(COLLECTIONS.RESTAURANTS, email);
      return res.status(401).json({ success: false, error: 'Mot de passe incorrect' });
    }
    if (!restaurant.status && (restaurant.tempPassword || restaurant.createdBy === 'admin')) {
      await updateRestaurant(restaurant.id, { status: 'approved' });
      console.log('Status mis à jour vers approved pour:', restaurant.id);
    }
    await resetLoginAttempts(COLLECTIONS.RESTAURANTS, email);
    const token = generateToken({ role: 'restaurant', email, id: restaurant.id });
    const { password: _, tempPassword: __, loginAttempts, lockUntil, ...data } = restaurant;
    await auditLog('RESTAURANT_LOGIN_SUCCESS', email, { usedTempPassword }, req);
    console.log('Connexion réussie pour:', email);
    res.json({ 
      success: true, 
      role: 'restaurant', 
      data: { ...data, usedTempPassword, needsContractSignature: !restaurant.contratStatus || restaurant.contratStatus !== 'signed' }, 
      token 
    });
  } catch (error) {
    console.error('Erreur auth restaurant:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({ success: true, user: req.user });
});

// ===== COLLECTEURS =====
app.post('/api/collectors/register', async (req, res) => {
  try {
    const { email, password, ...data } = sanitizeObject(req.body);
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, error: 'Format d\'email invalide' });
    }
    if (password.length < 8) {
      return res.status(400).json({ success: false, error: 'Le mot de passe doit contenir au moins 8 caractères' });
    }
    const existing = await getCollectorByEmail(email);
    if (existing) {
      return res.status(409).json({ success: false, error: 'Email déjà utilisé' });
    }
    await addCollector({
      email,
      password: await bcrypt.hash(password, BCRYPT_ROUNDS),
      ...data,
      status: 'pending',
      dateRequest: new Date().toISOString()
    });
    await auditLog('COLLECTOR_REGISTER', email, { status: 'pending' }, req);
    res.status(201).json({ success: true });
  } catch (error) {
    console.error('Erreur register collector:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.get('/api/collectors/pending', async (req, res) => {
  const collectors = await getCollectors('pending');
  res.json(collectors.map(({ password, loginAttempts, lockUntil, ...c }) => c));
});

app.get('/api/collectors/approved', async (req, res) => {
  const collectors = await getCollectors('approved');
  res.json(collectors.map(({ password, loginAttempts, lockUntil, ...c }) => c));
});

app.post('/api/collectors/:email/approve', async (req, res) => {
  try {
    const { email } = req.params;
    const collectorNumber = await generateCollectorNumber();
    await updateCollector(email, {
      status: 'approved',
      collectorNumber,
      dateApproval: new Date().toISOString()
    });
    await auditLog('COLLECTOR_APPROVED', email, { collectorNumber }, req);
    res.json({ success: true, collectorNumber });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.post('/api/collectors/:email/reject', async (req, res) => {
  const { email } = req.params;
  await deleteCollector(email);
  await auditLog('COLLECTOR_REJECTED', email, {}, req);
  res.json({ success: true });
});

app.delete('/api/collectors/:email', async (req, res) => {
  const { email } = req.params;
  await deleteCollector(email);
  await auditLog('COLLECTOR_DELETED', email, {}, req);
  res.json({ success: true });
});

// ===== OPÉRATEURS =====
app.post('/api/operators/register', async (req, res) => {
  try {
    const { email, password, ...data } = sanitizeObject(req.body);
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
    }
    const existing = await getOperatorByEmail(email);
    if (existing) {
      return res.status(409).json({ success: false, error: 'Email déjà utilisé' });
    }
    await addOperator({
      email,
      password: await bcrypt.hash(password, BCRYPT_ROUNDS),
      ...data,
      status: 'pending',
      dateRequest: new Date().toISOString()
    });
    await auditLog('OPERATOR_REGISTER', email, { status: 'pending' }, req);
    res.status(201).json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.get('/api/operators/pending', async (req, res) => {
  const operators = await getOperators('pending');
  res.json(operators.map(({ password, loginAttempts, lockUntil, ...o }) => o));
});

app.get('/api/operators/approved', async (req, res) => {
  const operators = await getOperators('approved');
  res.json(operators.map(({ password, loginAttempts, lockUntil, ...o }) => o));
});

app.post('/api/operators/:email/approve', async (req, res) => {
  const { email } = req.params;
  const operatorNumber = await generateOperatorNumber();
  await updateOperator(email, {
    status: 'approved',
    operatorNumber,
    dateApproval: new Date().toISOString()
  });
  await auditLog('OPERATOR_APPROVED', email, { operatorNumber }, req);
  res.json({ success: true, operatorNumber });
});

app.post('/api/operators/:email/reject', async (req, res) => {
  const { email } = req.params;
  await deleteOperator(email);
  await auditLog('OPERATOR_REJECTED', email, {}, req);
  res.json({ success: true });
});

app.delete('/api/operators/:email', async (req, res) => {
  const { email } = req.params;
  await deleteOperator(email);
  res.json({ success: true });
});

// ===== RESTAURANTS =====
app.post('/api/restaurants/register', async (req, res) => {
  try {
    const { email, password, id, qrCode, siret, ...data } = sanitizeObject(req.body);
    
    let existingBySiret = null;
    if (siret && db && isConnected) {
      existingBySiret = await db.collection(COLLECTIONS.RESTAURANTS).findOne({ siret });
    }
    
    if (existingBySiret) {
      if (email && email !== existingBySiret.email) {
        const existingByEmail = await getRestaurantByEmail(email);
        if (existingByEmail && existingByEmail.siret !== siret) {
          return res.status(409).json({ success: false, error: 'Cet email est déjà utilisé par un autre restaurant' });
        }
      }
      
      const isAccountFinalization = !existingBySiret.password && password;
      const isResubmission = existingBySiret.status === 'terminated';
      
      const updateData = {
        ...data,
        email: email || existingBySiret.email,
        dateRequest: new Date().toISOString()
      };
      
      if (password) {
        updateData.password = await bcrypt.hash(password, BCRYPT_ROUNDS);
      }
      
      if (isAccountFinalization && existingBySiret.status === 'approved') {
        updateData.status = 'approved';
        updateData.passwordSetDate = new Date().toISOString();
      } else {
        updateData.status = 'pending';
        updateData.isResubmission = isResubmission;
      }
      
      await updateRestaurant(existingBySiret.id, updateData);
      
      const logAction = isAccountFinalization ? 'RESTAURANT_FINALIZE_ACCOUNT' : 'RESTAURANT_RESUBMIT';
      await auditLog(logAction, email || existingBySiret.id, { status: updateData.status, siret, isAccountFinalization, isResubmission }, req);
      
      return res.status(200).json({ 
        success: true, 
        id: existingBySiret.id, 
        qrCode: existingBySiret.qrCode || existingBySiret.id,
        isAccountFinalization,
        isResubmission,
        status: updateData.status,
        message: isAccountFinalization ? 'Compte finalisé avec succès' : 'Demande de réinscription soumise'
      });
    }
    
    if (email) {
      const existingByEmail = await getRestaurantByEmail(email);
      if (existingByEmail) {
        return res.status(409).json({ success: false, error: 'Cet email est déjà utilisé' });
      }
    }
    
    let newQRCode = qrCode;
    if (!newQRCode || !newQRCode.startsWith('QR-')) {
      const allRestaurants = await getRestaurants();
      const existingNumbers = allRestaurants
        .filter(r => r.qrCode && r.qrCode.startsWith('QR-'))
        .map(r => parseInt(r.qrCode.replace('QR-', '')) || 0);
      const maxNumber = existingNumbers.length > 0 ? Math.max(...existingNumbers) : 0;
      newQRCode = `QR-${String(maxNumber + 1).padStart(5, '0')}`;
    }
    
    const existingQR = await getRestaurantByQRCode(newQRCode);
    if (existingQR) {
      const allRestaurants = await getRestaurants();
      const existingNumbers = allRestaurants
        .filter(r => r.qrCode && r.qrCode.startsWith('QR-'))
        .map(r => parseInt(r.qrCode.replace('QR-', '')) || 0);
      const maxNumber = existingNumbers.length > 0 ? Math.max(...existingNumbers) : 0;
      newQRCode = `QR-${String(maxNumber + 1).padStart(5, '0')}`;
    }
    
    const restaurantId = id || newQRCode;
    
    await addRestaurant({
      id: restaurantId,
      qrCode: newQRCode,
      email: email || '',
      password: password ? await bcrypt.hash(password, BCRYPT_ROUNDS) : null,
      siret: siret || '',
      ...data,
      status: 'pending',
      dateRequest: new Date().toISOString()
    });
    
    await auditLog('RESTAURANT_REGISTER', email || restaurantId, { status: 'pending', qrCode: newQRCode }, req);
    
    res.status(201).json({ success: true, id: restaurantId, qrCode: newQRCode });
  } catch (error) {
    console.error('Erreur register restaurant:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.get('/api/restaurants/pending', async (req, res) => {
  const restaurants = await getRestaurants('pending');
  res.json(restaurants.map(({ password, loginAttempts, lockUntil, ...r }) => r));
});

app.get('/api/restaurants', async (req, res) => {
  const all = await getRestaurants();
  const filtered = all.filter(r => r.status === 'approved' || r.status === 'terminated');
  res.json(filtered.map(({ password, loginAttempts, lockUntil, ...r }) => r));
});

app.get('/api/restaurants/qr/:qrCode', async (req, res) => {
  const restaurant = await getRestaurantByQRCode(req.params.qrCode);
  if (!restaurant || restaurant.status !== 'approved') {
    return res.status(404).json({ error: 'Restaurant non trouvé' });
  }
  const { password, loginAttempts, lockUntil, ...data } = restaurant;
  res.json(data);
});

app.get('/api/restaurants/siret/:siret', async (req, res) => {
  const siret = req.params.siret.replace(/\D/g, '');
  if (siret.length !== 14) {
    return res.status(400).json({ error: 'SIRET invalide (14 chiffres requis)' });
  }
  if (!db || !isConnected) {
    return res.status(503).json({ error: 'Base de données non disponible' });
  }
  const restaurant = await db.collection(COLLECTIONS.RESTAURANTS).findOne({ siret });
  if (!restaurant) {
    return res.status(404).json({ error: 'Restaurant non trouvé', exists: false });
  }
  const { password, loginAttempts, lockUntil, ...data } = restaurant;
  res.json({ ...data, exists: true });
});

app.post('/api/restaurants/:id/terminate', async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body || {};
    const restaurant = await getRestaurantById(id);
    if (!restaurant) {
      return res.status(404).json({ success: false, error: 'Restaurant non trouvé' });
    }
    const dateTerminated = new Date().toISOString();
    await updateRestaurant(id, {
      status: 'terminated',
      dateTerminated,
      terminationReason: reason || 'Fin de contrat'
    });
    await auditLog('RESTAURANT_TERMINATED', id, { reason, dateTerminated }, req);
    res.json({ success: true, dateTerminated, message: 'Contrat résilié avec succès' });
  } catch (error) {
    console.error('Erreur fin de contrat:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.post('/api/restaurants/:id/approve', async (req, res) => {
  try {
    const { id } = req.params;
    const { qrCode, password, ...updateData } = sanitizeObject(req.body);
    const restaurant = await getRestaurantById(id);
    if (!restaurant) {
      return res.status(404).json({ success: false, error: 'Restaurant non trouvé' });
    }
    const updates = {
      ...updateData,
      status: 'approved',
      qrCode: qrCode || restaurant.qrCode || `UCO-${Date.now()}`,
      dateApproval: new Date().toISOString()
    };
    if (password && !restaurant.password) {
      updates.password = await bcrypt.hash(password, BCRYPT_ROUNDS);
    }
    await updateRestaurant(id, updates);
    await auditLog('RESTAURANT_APPROVED', id, { qrCode: updates.qrCode }, req);
    res.json({ success: true, qrCode: updates.qrCode });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.post('/api/restaurants/:id/reject', async (req, res) => {
  const { id } = req.params;
  await deleteRestaurant(id);
  await auditLog('RESTAURANT_REJECTED', id, {}, req);
  res.json({ success: true });
});

app.post('/api/restaurants', async (req, res) => {
  try {
    const { id, qrCode, ...data } = sanitizeObject(req.body);
    const restaurantId = id || qrCode || uuidv4();
    const existing = await getRestaurantById(restaurantId);
    if (existing) {
      return res.status(409).json({ success: false, error: 'QR Code déjà attribué' });
    }
    await addRestaurant({
      ...data,
      id: restaurantId,
      qrCode: qrCode || restaurantId,
      status: data.status || 'approved',
      dateCreated: new Date().toISOString()
    });
    await auditLog('RESTAURANT_CREATED', restaurantId, {}, req);
    res.status(201).json({ success: true, id: restaurantId, qrCode: qrCode || restaurantId });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.put('/api/restaurants/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const restaurant = await getRestaurantById(id);
    if (!restaurant) {
      return res.status(404).json({ success: false, error: 'Restaurant non trouvé' });
    }
    await updateRestaurant(id, sanitizeObject(req.body));
    await auditLog('RESTAURANT_UPDATED', id, {}, req);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.put('/api/restaurants/:id/password', async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = sanitizeObject(req.body);
    if (!password || password.length < 8) {
      return res.status(400).json({ success: false, error: 'Mot de passe invalide (min 8 caractères)' });
    }
    const restaurant = await getRestaurantById(id);
    if (!restaurant) {
      return res.status(404).json({ success: false, error: 'Restaurant non trouvé' });
    }
    await updateRestaurant(id, { password: await bcrypt.hash(password, BCRYPT_ROUNDS) });
    await auditLog('RESTAURANT_PASSWORD_CHANGED', id, {}, req);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.post('/api/restaurants/:id/change-password', async (req, res) => {
  try {
    const { id } = req.params;
    const { oldPassword, newPassword } = sanitizeObject(req.body);
    if (!oldPassword) {
      return res.status(400).json({ success: false, error: 'Ancien mot de passe requis' });
    }
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ success: false, error: 'Nouveau mot de passe invalide (min 6 caractères)' });
    }
    const restaurant = await getRestaurantById(id);
    if (!restaurant) {
      return res.status(404).json({ success: false, error: 'Restaurant non trouvé' });
    }
    let isOldPasswordValid = false;
    if (restaurant.password) {
      isOldPasswordValid = await bcrypt.compare(oldPassword, restaurant.password);
    }
    if (!isOldPasswordValid && restaurant.tempPassword) {
      isOldPasswordValid = (oldPassword === restaurant.tempPassword);
    }
    if (!isOldPasswordValid) {
      return res.status(401).json({ success: false, error: 'Ancien mot de passe incorrect' });
    }
    await updateRestaurant(id, { 
      password: await bcrypt.hash(newPassword, BCRYPT_ROUNDS),
      tempPassword: null,
      passwordChangedAt: new Date().toISOString()
    });
    await auditLog('RESTAURANT_PASSWORD_CHANGED', id, { method: 'user_change' }, req);
    console.log('Mot de passe changé pour restaurant:', id);
    res.json({ success: true, message: 'Mot de passe modifié avec succès' });
  } catch (error) {
    console.error('Erreur changement mot de passe:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

// ===== COLLECTES =====
app.get('/api/collections', async (req, res) => {
  const collections = await getCollections();
  res.json(collections);
});

app.post('/api/collections', async (req, res) => {
  try {
    const collection = sanitizeObject({
      ...req.body,
      id: req.body.id || uuidv4()
    });
    await addCollection(collection);
    await auditLog('COLLECTION_CREATED', collection.id, { restaurantId: collection.restaurantId }, req);
    res.status(201).json({ success: true, id: collection.id });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

// ===== TOURNÉES =====
app.get('/api/tournees', async (req, res) => {
  const tournees = await getTournees();
  res.json(tournees);
});

app.post('/api/tournees', async (req, res) => {
  try {
    const tournee = sanitizeObject({
      ...req.body,
      id: req.body.id || uuidv4()
    });
    await addTournee(tournee);
    res.status(201).json({ success: true, id: tournee.id });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.put('/api/tournees/:id', async (req, res) => {
  const { id } = req.params;
  await updateTournee(id, sanitizeObject(req.body));
  res.json({ success: true });
});

// ===== RAPPORTS DE TOURNÉES =====
app.get('/api/rapports-tournees', async (req, res) => {
  try {
    if (!db || !isConnected) return res.json([]);
    const rapports = await db.collection('rapports_tournees').find({}).sort({ createdAt: -1 }).limit(100).toArray();
    res.json(rapports || []);
  } catch (error) {
    console.error('Erreur récupération rapports tournées:', error);
    res.json([]);
  }
});

app.post('/api/rapports-tournees', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non disponible' });
    }
    const rapport = sanitizeObject(req.body);
    rapport.createdAt = rapport.createdAt || new Date().toISOString();
    await db.collection('rapports_tournees').insertOne({
      ...rapport,
      _id: rapport.id || uuidv4()
    });
    console.log('📊 Nouveau rapport de tournée enregistré:', rapport.id);
    res.status(201).json({ success: true, id: rapport.id });
  } catch (error) {
    console.error('Erreur création rapport tournée:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

// ===== SETTINGS =====
app.get('/api/settings', async (req, res) => {
  const settings = await getSettings();
  const { admin, brevoApiKey, ...publicSettings } = settings;
  publicSettings.brevoApiKey = brevoApiKey ? '••••••••••••••••' : '';
  publicSettings.hasBrevoKey = !!brevoApiKey;
  res.json(publicSettings);
});

app.put('/api/settings', async (req, res) => {
  try {
    const { brevoApiKey, ...otherSettings } = req.body;
    const sanitizedSettings = sanitizeObject(otherSettings);
    if (brevoApiKey) {
      sanitizedSettings.brevoApiKey = brevoApiKey;
    }
    await updateSettings(sanitizedSettings);
    await auditLog('SETTINGS_UPDATED', 'admin', { fields: Object.keys(req.body) }, req);
    res.json({ success: true });
  } catch (error) {
    console.error('Erreur sauvegarde settings:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.put('/api/admin/password', async (req, res) => {
  try {
    const { currentPassword, newPassword } = sanitizeObject(req.body);
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, error: 'Mots de passe requis' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, error: 'Nouveau mot de passe trop court (min 8 caractères)' });
    }
    const admin = await getAdmin();
    const isValid = await bcrypt.compare(currentPassword, admin.password);
    if (!isValid) {
      await auditLog('ADMIN_PASSWORD_CHANGE_FAILED', admin.email, { reason: 'Invalid current password' }, req);
      return res.status(401).json({ success: false, error: 'Mot de passe actuel incorrect' });
    }
    const settings = await getSettings();
    await updateSettings({
      ...settings,
      admin: {
        ...admin,
        password: await bcrypt.hash(newPassword, BCRYPT_ROUNDS)
      }
    });
    await auditLog('ADMIN_PASSWORD_CHANGED', admin.email, {}, req);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

// ===== EMAIL (Brevo) =====
app.post('/api/send-email', async (req, res) => {
  try {
    const { to, subject, htmlContent, html, senderName, attachment, content, title } = req.body;
    if (!to || !subject) {
      return res.status(400).json({ success: false, error: 'Paramètres manquants' });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(to)) {
      return res.status(400).json({ success: false, error: 'Email destinataire invalide' });
    }
    const settings = await getSettings();
    const apiKey = settings.brevoApiKey;
    if (!apiKey) {
      return res.status(503).json({ success: false, error: 'Service email non configuré' });
    }
    let rawContent = content || htmlContent || html || '';
    rawContent = rawContent
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&nbsp;/g, ' ');
    let cleanContent = rawContent
      .replace(/<!DOCTYPE[^>]*>/gi, '')
      .replace(/<html[^>]*>/gi, '')
      .replace(/<\/html>/gi, '')
      .replace(/<head[^>]*>[\s\S]*?<\/head>/gi, '')
      .replace(/<body[^>]*>/gi, '')
      .replace(/<\/body>/gi, '')
      .replace(/<meta[^>]*>/gi, '')
      .trim();
    const finalHtml = '<html><head><meta charset="UTF-8"></head><body style="font-family:Arial,sans-serif;padding:20px;">' + cleanContent + '</body></html>';
    console.log('=== ENVOI EMAIL ===');
    console.log('To:', to);
    console.log('Subject:', subject);
    const emailPayload = {
      sender: { name: senderName || 'UCO AND CO', email: 'contact@uco-and-co.fr' },
      to: [{ email: to }],
      subject: subject.substring(0, 200),
      htmlContent: finalHtml
    };
    if (attachment && attachment.content && attachment.name) {
      emailPayload.attachment = [{ content: attachment.content, name: attachment.name.substring(0, 100) }];
    }
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'api-key': apiKey,
        'content-type': 'application/json'
      },
      body: JSON.stringify(emailPayload)
    });
    const responseData = await response.json();
    if (response.ok) {
      console.log('Email OK, messageId:', responseData.messageId);
      res.json({ success: true, messageId: responseData.messageId });
    } else {
      console.error('Erreur Brevo:', responseData);
      res.status(502).json({ success: false, error: responseData.message || 'Erreur Brevo' });
    }
  } catch (error) {
    console.error('Erreur email:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

// ===== SMS (Brevo) =====
app.post('/api/send-sms', async (req, res) => {
  try {
    const { to, message, content } = req.body;
    const smsMessage = message || content;
    console.log('=== ENVOI SMS ===');
    console.log('To (raw):', to);
    console.log('Message:', smsMessage?.substring(0, 50));
    if (!to || !smsMessage) {
      console.log('Erreur: Paramètres manquants');
      return res.status(400).json({ success: false, error: 'Paramètres manquants (to ou message)' });
    }
    const settings = await getSettings();
    if (!settings.brevoApiKey) {
      console.log('Erreur: Clé API Brevo non configurée');
      return res.status(503).json({ success: false, error: 'Clé API Brevo non configurée' });
    }
    if (!settings.smsEnabled) {
      console.log('Erreur: SMS désactivé dans les paramètres');
      return res.status(503).json({ success: false, error: 'SMS désactivé. Activez-le dans Paramètres.' });
    }
    let phoneNumber = typeof to === 'object' ? to.number : to;
    let countryCode = typeof to === 'object' ? to.countryCode : 'FR';
    phoneNumber = String(phoneNumber).replace(/[\s\.\-]/g, '');
    const prefixes = { 'FR': '+33', 'BE': '+32', 'CH': '+41', 'LU': '+352' };
    const prefix = prefixes[countryCode] || '+33';
    if (!phoneNumber.startsWith('+')) {
      phoneNumber = phoneNumber.startsWith('0') ? prefix + phoneNumber.slice(1) : prefix + phoneNumber;
    }
    console.log('Numéro formaté:', phoneNumber);
    const smsPayload = {
      sender: 'UCOANDCO',
      recipient: phoneNumber,
      content: smsMessage.slice(0, 160)
    };
    console.log('Payload SMS:', JSON.stringify(smsPayload));
    const response = await fetch('https://api.brevo.com/v3/transactionalSMS/sms', {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'api-key': settings.brevoApiKey,
        'content-type': 'application/json'
      },
      body: JSON.stringify(smsPayload)
    });
    const responseData = await response.json();
    console.log('Réponse Brevo SMS:', JSON.stringify(responseData));
    if (response.ok) {
      console.log('SMS envoyé avec succès');
      res.json({ success: true, messageId: responseData.messageId });
    } else {
      console.log('Erreur Brevo SMS:', responseData);
      let errorMsg = responseData.message || 'Erreur SMS Brevo';
      if (responseData.code === 'not_enough_credits') {
        errorMsg = 'Crédits SMS insuffisants. Achetez des crédits sur Brevo.';
      }
      res.status(502).json({ success: false, error: errorMsg, code: responseData.code });
    }
  } catch (error) {
    console.error('Erreur SMS:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur: ' + error.message });
  }
});

// ===== AUDIT LOGS =====
app.get('/api/audit-logs', authenticateToken, requireRole('admin'), async (req, res) => {
  if (!db || !isConnected) return res.json([]);
  try {
    const { limit = 100, action, userId } = req.query;
    const query = {};
    if (action) query.action = action;
    if (userId) query.userId = userId;
    const logs = await db.collection(COLLECTIONS.AUDIT_LOGS)
      .find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .toArray();
    res.json(logs);
  } catch (e) {
    console.error('Erreur audit logs:', e.message);
    res.json([]);
  }
});

// ===== STATISTIQUES =====
app.get('/api/stats', async (req, res) => {
  const restaurants = await getRestaurants();
  const collectors = await getCollectors('approved');
  const operators = await getOperators('approved');
  const collections = await getCollections();
  res.json({
    restaurants: restaurants.filter(r => r.status === 'approved').length,
    collectors: collectors.length,
    operators: operators.length,
    collections: collections.length,
    totalVolume: Math.round(collections.reduce((sum, c) => sum + (parseFloat(c.quantite) || 0), 0) * 100) / 100,
    totalAmount: Math.round(collections.reduce((sum, c) => sum + (parseFloat(c.montant) || 0), 0) * 100) / 100
  });
});

// ===== PARTENAIRES =====
app.get('/api/partners', async (req, res) => {
  try {
    if (!db || !isConnected) return res.json([]);
    const partners = await db.collection('partners').find({}).toArray();
    res.json(partners);
  } catch (error) {
    console.error('Erreur GET partners:', error);
    res.json([]);
  }
});

app.post('/api/partners', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const partner = req.body;
    if (!partner.id) {
      partner.id = 'partner_' + Date.now();
    }
    partner.createdAt = new Date().toISOString();
    await db.collection('partners').insertOne(partner);
    console.log('✅ Nouveau partenaire créé:', partner.name);
    res.json({ success: true, partner });
  } catch (error) {
    console.error('Erreur POST partner:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/api/partners/:id', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const { id } = req.params;
    const updates = req.body;
    updates.updatedAt = new Date().toISOString();
    const result = await db.collection('partners').updateOne({ id: id }, { $set: updates });
    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, error: 'Partenaire non trouvé' });
    }
    console.log('✅ Partenaire mis à jour:', id);
    res.json({ success: true });
  } catch (error) {
    console.error('Erreur PUT partner:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/partners/:id', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const { id } = req.params;
    const result = await db.collection('partners').deleteOne({ id: id });
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, error: 'Partenaire non trouvé' });
    }
    console.log('✅ Partenaire supprimé:', id);
    res.json({ success: true });
  } catch (error) {
    console.error('Erreur DELETE partner:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== PRESTATAIRES =====
const SERVICES_DISPONIBLES = [
  { id: 'bac_graisse', name: 'Entretien bac à graisse', icon: '🪣' },
  { id: 'hotte', name: 'Nettoyage hotte aspiration', icon: '🌀' },
  { id: 'extincteur', name: 'Installation extincteurs', icon: '🧯' },
  { id: 'deratisation', name: 'Dératisation', icon: '🐀' },
  { id: 'haccp', name: 'Formation HACCP', icon: '📋' },
  { id: 'frigoriste', name: 'Frigoriste', icon: '❄️' },
  { id: 'matieres_premieres', name: 'Livraison matières premières', icon: '🛒' },
  { id: 'comptable', name: 'Expert-comptable', icon: '📊' },
  { id: 'avocat', name: 'Avocat', icon: '⚖️' },
  { id: 'assurance', name: 'Assurance', icon: '🛡️' },
  { id: 'electricien', name: 'Électricien', icon: '⚡' },
  { id: 'plombier', name: 'Plombier', icon: '🔧' },
  { id: 'nettoyage', name: 'Nettoyage professionnel', icon: '🧹' },
  { id: 'securite', name: 'Sécurité incendie', icon: '🔥' },
  { id: 'autre', name: 'Autre service', icon: '📦' }
];

app.get('/api/services-disponibles', (req, res) => {
  res.json(SERVICES_DISPONIBLES);
});

app.get('/api/prestataires', async (req, res) => {
  try {
    if (!db || !isConnected) return res.json([]);
    const prestataires = await db.collection(COLLECTIONS.PRESTATAIRES).find({}).toArray();
    res.json(prestataires || []);
  } catch (error) {
    console.error('Erreur récupération prestataires:', error);
    res.json([]);
  }
});

app.get('/api/prestataires/:id', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const { id } = req.params;
    const prestataire = await db.collection(COLLECTIONS.PRESTATAIRES).findOne({
      $or: [{ id: sanitizeInput(id) }, { _id: sanitizeInput(id) }]
    });
    if (!prestataire) {
      return res.status(404).json({ success: false, error: 'Prestataire non trouvé' });
    }
    res.json(prestataire);
  } catch (error) {
    console.error('Erreur récupération prestataire:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.post('/api/prestataires', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const data = sanitizeObject(req.body);
    if (!data.enseigne) {
      return res.status(400).json({ success: false, error: 'Enseigne requise' });
    }
    if (!data.email) {
      return res.status(400).json({ success: false, error: 'Email requis' });
    }
    if (!data.services || data.services.length === 0) {
      return res.status(400).json({ success: false, error: 'Au moins un service requis' });
    }
    if (data.siret && data.siret !== 'EN_COURS') {
      const existingBySiret = await db.collection(COLLECTIONS.PRESTATAIRES).findOne({ siret: data.siret });
      if (existingBySiret) {
        return res.status(409).json({ success: false, error: 'Un prestataire avec ce SIRET existe déjà' });
      }
    }
    const existingByEmail = await db.collection(COLLECTIONS.PRESTATAIRES).findOne({ email: data.email });
    if (existingByEmail) {
      return res.status(409).json({ success: false, error: 'Un prestataire avec cet email existe déjà' });
    }
    const prestataireId = 'PREST_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    const newPrestataire = {
      ...data,
      id: prestataireId,
      _id: prestataireId,
      dateCreation: new Date().toISOString(),
      status: 'active',
      createdBy: req.body.createdBy || 'admin'
    };
    await db.collection(COLLECTIONS.PRESTATAIRES).insertOne(newPrestataire);
    console.log('✅ Nouveau prestataire créé:', prestataireId, '-', data.enseigne);
    await auditLog('PRESTATAIRE_CREATE', prestataireId, { enseigne: data.enseigne, services: data.services }, req);
    res.status(201).json({ success: true, id: prestataireId, prestataire: newPrestataire });
  } catch (error) {
    console.error('Erreur création prestataire:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.put('/api/prestataires/:id', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const { id } = req.params;
    const data = sanitizeObject(req.body);
    delete data._id;
    data.updatedAt = new Date().toISOString();
    const result = await db.collection(COLLECTIONS.PRESTATAIRES).updateOne(
      { $or: [{ id: sanitizeInput(id) }, { _id: sanitizeInput(id) }] },
      { $set: data }
    );
    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, error: 'Prestataire non trouvé' });
    }
    console.log('✅ Prestataire mis à jour:', id);
    await auditLog('PRESTATAIRE_UPDATE', id, { fields: Object.keys(data) }, req);
    res.json({ success: true });
  } catch (error) {
    console.error('Erreur mise à jour prestataire:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.delete('/api/prestataires/:id', authenticateToken, async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const { id } = req.params;
    const result = await db.collection(COLLECTIONS.PRESTATAIRES).deleteOne({
      $or: [{ id: sanitizeInput(id) }, { _id: sanitizeInput(id) }]
    });
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, error: 'Prestataire non trouvé' });
    }
    console.log('✅ Prestataire supprimé:', id);
    await auditLog('PRESTATAIRE_DELETE', id, {}, req);
    res.json({ success: true });
  } catch (error) {
    console.error('Erreur suppression prestataire:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.get('/api/prestataires/service/:serviceId', async (req, res) => {
  try {
    if (!db || !isConnected) return res.json([]);
    const { serviceId } = req.params;
    const prestataires = await db.collection(COLLECTIONS.PRESTATAIRES).find({
      services: sanitizeInput(serviceId),
      status: 'active'
    }).toArray();
    res.json(prestataires || []);
  } catch (error) {
    console.error('Erreur récupération prestataires par service:', error);
    res.json([]);
  }
});

// ===== AVIS CLIENTS =====
app.get('/api/avis', async (req, res) => {
  try {
    if (!db || !isConnected) return res.json([]);
    const avis = await db.collection(COLLECTIONS.AVIS).find({}).sort({ dateCreation: -1 }).toArray();
    res.json(avis || []);
  } catch (error) {
    console.error('Erreur récupération avis:', error);
    res.json([]);
  }
});

app.post('/api/avis', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const avisData = sanitizeObject(req.body);
    if (!avisData.id) {
      avisData.id = 'avis_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }
    avisData.dateCreation = avisData.dateCreation || new Date().toISOString();
    await db.collection(COLLECTIONS.AVIS).insertOne({ ...avisData, _id: avisData.id });
    console.log('Nouvel avis enregistré:', avisData.id);
    res.status(201).json({ success: true, id: avisData.id });
  } catch (error) {
    console.error('Erreur création avis:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.delete('/api/avis/:id', authenticateToken, async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const { id } = req.params;
    await db.collection(COLLECTIONS.AVIS).deleteOne({ id: sanitizeInput(id) });
    res.json({ success: true });
  } catch (error) {
    console.error('Erreur suppression avis:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.post('/api/avis/:id/read', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const { id } = req.params;
    await db.collection(COLLECTIONS.AVIS).updateOne(
      { $or: [{ id: sanitizeInput(id) }, { _id: sanitizeInput(id) }] },
      { $set: { isRead: true, readAt: new Date().toISOString() } }
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Erreur marquage avis lu:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.post('/api/avis/mark-all-read', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const result = await db.collection(COLLECTIONS.AVIS).updateMany(
      { isRead: { $ne: true } },
      { $set: { isRead: true, readAt: new Date().toISOString() } }
    );
    console.log(`✅ ${result.modifiedCount} avis marqués comme lus`);
    res.json({ success: true, count: result.modifiedCount });
  } catch (error) {
    console.error('Erreur marquage tous avis lus:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

// ===== STRIPE - PAIEMENTS ABONNEMENTS =====
const STRIPE_PLANS = {
  starter: { name: 'Starter', price: 0, stripePriceId: null },
  simple: { name: 'Simple', price: 1499, stripePriceId: null },
  premium: { name: 'Premium', price: 1999, stripePriceId: null }
};

async function initializeStripePrices(stripe) {
  try {
    const products = await stripe.products.list({ limit: 10 });
    for (const [planId, plan] of Object.entries(STRIPE_PLANS)) {
      if (plan.price === 0) continue;
      let product = products.data.find(p => p.metadata?.planId === planId);
      if (!product) {
        product = await stripe.products.create({
          name: `Abonnement UCO ${plan.name}`,
          description: `Services partenaires UCO AND CO - Formule ${plan.name}`,
          metadata: { planId }
        });
        console.log(`✅ Produit Stripe créé: ${plan.name}`);
      }
      const prices = await stripe.prices.list({ product: product.id, limit: 5 });
      let price = prices.data.find(p => p.recurring?.interval === 'month' && p.unit_amount === plan.price);
      if (!price) {
        price = await stripe.prices.create({
          product: product.id,
          unit_amount: plan.price,
          currency: 'eur',
          recurring: { interval: 'month' },
          metadata: { planId }
        });
        console.log(`✅ Prix Stripe créé: ${plan.name} - ${plan.price/100}€/mois`);
      }
      STRIPE_PLANS[planId].stripePriceId = price.id;
      STRIPE_PLANS[planId].stripeProductId = product.id;
    }
    console.log('✅ Prix Stripe initialisés');
  } catch (error) {
    console.error('⚠️ Erreur initialisation prix Stripe:', error.message);
  }
}

app.post('/api/stripe/create-subscription', async (req, res) => {
  try {
    const { restaurantId, plan, email, enseigne, siret } = req.body;
    console.log('📦 Création abonnement:', { restaurantId, plan, email, enseigne });
    const settings = await getSettings();
    if (!settings?.stripeSecretKey) {
      console.log('❌ stripeSecretKey manquante dans settings');
      return res.status(400).json({ success: false, error: 'Stripe non configuré' });
    }
    console.log('✅ Clé Stripe trouvée');
    const stripe = require('stripe')(settings.stripeSecretKey);
    if (plan === 'starter' || STRIPE_PLANS[plan]?.price === 0) {
      return res.json({ success: true, free: true, message: 'Formule gratuite - pas de paiement requis' });
    }
    if (!STRIPE_PLANS[plan]) {
      console.log('❌ Plan inconnu:', plan);
      return res.status(400).json({ success: false, error: `Plan inconnu: ${plan}` });
    }
    if (!STRIPE_PLANS[plan].stripePriceId) {
      console.log('🔄 Initialisation des prix Stripe...');
      await initializeStripePrices(stripe);
    }
    const planConfig = STRIPE_PLANS[plan];
    console.log('📋 Config du plan:', { plan, stripePriceId: planConfig?.stripePriceId, price: planConfig?.price });
    if (!planConfig?.stripePriceId) {
      console.log('⚠️ Prix non trouvé, création directe...');
      try {
        const product = await stripe.products.create({
          name: `Abonnement UCO ${planConfig.name}`,
          description: `Services partenaires UCO AND CO - Formule ${planConfig.name}`,
          metadata: { planId: plan }
        });
        const price = await stripe.prices.create({
          product: product.id,
          unit_amount: planConfig.price,
          currency: 'eur',
          recurring: { interval: 'month' },
          metadata: { planId: plan }
        });
        STRIPE_PLANS[plan].stripePriceId = price.id;
        STRIPE_PLANS[plan].stripeProductId = product.id;
        console.log('✅ Prix créé directement:', price.id);
      } catch (createError) {
        console.error('❌ Erreur création prix:', createError.message);
        return res.status(400).json({ success: false, error: 'Erreur création prix Stripe: ' + createError.message });
      }
    }
    if (!STRIPE_PLANS[plan].stripePriceId) {
      console.log('❌ Prix toujours non disponible après création');
      return res.status(400).json({ success: false, error: 'Impossible de configurer le prix Stripe' });
    }
    let customer;
    const existingCustomers = await stripe.customers.list({ email, limit: 1 });
    if (existingCustomers.data.length > 0) {
      customer = existingCustomers.data[0];
      await stripe.customers.update(customer.id, { name: enseigne, metadata: { restaurantId, siret } });
    } else {
      customer = await stripe.customers.create({ email, name: enseigne, metadata: { restaurantId, siret } });
    }
    const session = await stripe.checkout.sessions.create({
      customer: customer.id,
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [{ price: STRIPE_PLANS[plan].stripePriceId, quantity: 1 }],
      subscription_data: { metadata: { restaurantId, siret, plan } },
      success_url: `${req.headers.origin || 'https://uco-and-co.fr'}?subscription=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.headers.origin || 'https://uco-and-co.fr'}?subscription=cancelled`,
      metadata: { restaurantId, siret, plan },
      payment_method_collection: 'always'
    });
    console.log(`✅ Session Stripe créée: ${session.id} pour ${enseigne} (${plan})`);
    res.json({ success: true, sessionId: session.id, url: session.url });
  } catch (error) {
    console.error('Erreur création subscription Stripe:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/stripe/create-checkout-session', async (req, res) => {
  req.body.plan = req.body.plan || 'simple';
  return res.redirect(307, '/api/stripe/create-subscription');
});

app.post('/api/stripe/webhook', async (req, res) => {
  try {
    const settings = await getSettings();
    if (!settings?.stripeSecretKey || !settings?.stripeWebhookSecret) {
      console.log('❌ Webhook: Stripe non configuré');
      return res.status(400).json({ error: 'Stripe non configuré' });
    }
    const stripe = require('stripe')(settings.stripeSecretKey);
    const sig = req.headers['stripe-signature'];
    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, settings.stripeWebhookSecret);
    } catch (err) {
      console.error('❌ Erreur signature webhook:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    console.log(`📥 Webhook Stripe reçu: ${event.type}`);
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const { restaurantId, siret, plan } = session.metadata || {};
        console.log('📋 Metadata reçues:', { restaurantId, siret, plan });
        if (!restaurantId && !siret) {
          console.error('❌ Aucun identifiant restaurant dans les metadata');
          break;
        }
        let cardLast4 = '****';
        if (session.subscription) {
          try {
            const subscription = await stripe.subscriptions.retrieve(session.subscription);
            if (subscription.default_payment_method) {
              const pm = await stripe.paymentMethods.retrieve(subscription.default_payment_method);
              cardLast4 = pm.card?.last4 || '****';
            }
          } catch (e) { console.log('⚠️ Impossible de récupérer la carte:', e.message); }
        }
        const searchCriteria = [];
        if (restaurantId) {
          searchCriteria.push({ id: restaurantId });
          searchCriteria.push({ qrCode: restaurantId });
        }
        if (siret) searchCriteria.push({ siret: siret });
        if (session.customer_email) searchCriteria.push({ email: session.customer_email });
        console.log('🔍 Recherche restaurant avec:', JSON.stringify(searchCriteria));
        if (db && isConnected) {
          const updateResult = await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
            { $or: searchCriteria },
            {
              $set: {
                subscription: {
                  plan: plan || 'simple',
                  status: 'active',
                  stripeCustomerId: session.customer,
                  stripeSubscriptionId: session.subscription,
                  startDate: new Date().toISOString(),
                  lastPaymentDate: new Date().toISOString(),
                  cardLast4
                }
              }
            }
          );
          console.log('📊 Résultat mise à jour:', { matched: updateResult.matchedCount, modified: updateResult.modifiedCount });
          if (updateResult.matchedCount === 0) {
            console.error('❌ Aucun restaurant trouvé avec les critères:', searchCriteria);
          } else {
            console.log(`✅ Abonnement ${plan} activé pour: ${restaurantId || siret}`);
          }
        }
        break;
      }
      case 'invoice.payment_succeeded': {
        const invoice = event.data.object;
        if (invoice.subscription && invoice.billing_reason !== 'subscription_create' && db && isConnected) {
          await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
            { 'subscription.stripeSubscriptionId': invoice.subscription },
            { 
              $set: { 
                'subscription.lastPaymentDate': new Date().toISOString(),
                'subscription.status': 'active'
              }
            }
          );
          console.log(`✅ Prélèvement mensuel réussi pour subscription: ${invoice.subscription}`);
        }
        break;
      }
      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        if (invoice.subscription && db && isConnected) {
          await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
            { 'subscription.stripeSubscriptionId': invoice.subscription },
            { 
              $set: { 
                'subscription.status': 'payment_failed',
                'subscription.lastFailedAt': new Date().toISOString()
              },
              $inc: { 'subscription.failedAttempts': 1 }
            }
          );
          console.log(`⚠️ Échec paiement pour subscription: ${invoice.subscription}`);
        }
        break;
      }
      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        if (db && isConnected) {
          await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
            { 'subscription.stripeSubscriptionId': subscription.id },
            { $set: { 'subscription.status': 'cancelled', 'subscription.endDate': new Date().toISOString() } }
          );
        }
        console.log(`❌ Abonnement Stripe annulé: ${subscription.id}`);
        break;
      }
    }
    res.json({ received: true });
  } catch (error) {
    console.error('Erreur webhook Stripe:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/stripe/cancel-subscription', async (req, res) => {
  try {
    const { subscriptionId } = req.body;
    const settings = await getSettings();
    if (!settings?.stripeSecretKey) {
      return res.status(400).json({ success: false, error: 'Stripe non configuré' });
    }
    const stripe = require('stripe')(settings.stripeSecretKey);
    const subscription = await stripe.subscriptions.update(subscriptionId, { cancel_at_period_end: true });
    console.log('✅ Abonnement marqué pour annulation:', subscriptionId);
    res.json({ success: true, subscription });
  } catch (error) {
    console.error('Erreur annulation abonnement:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/stripe/customer-portal', async (req, res) => {
  try {
    const { customerId } = req.body;
    const settings = await getSettings();
    if (!settings?.stripeSecretKey) {
      return res.status(400).json({ success: false, error: 'Stripe non configuré' });
    }
    const stripe = require('stripe')(settings.stripeSecretKey);
    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: `${req.headers.origin || 'https://uco-and-co.fr'}`
    });
    res.json({ success: true, url: session.url });
  } catch (error) {
    console.error('Erreur portail client:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== QONTO - FACTURES =====
app.post('/api/qonto/configure', async (req, res) => {
  try {
    const { organizationId, secretKey } = req.body;
    if (!organizationId || !secretKey) {
      return res.status(400).json({ success: false, error: 'Organization ID et Secret Key requis' });
    }
    const qontoAuth = `${organizationId}:${secretKey}`;
    const testResponse = await fetch('https://thirdparty.qonto.com/v2/organization', {
      headers: { 'Authorization': qontoAuth, 'Content-Type': 'application/json' }
    });
    if (!testResponse.ok) {
      return res.status(400).json({ success: false, error: 'Identifiants Qonto invalides' });
    }
    const orgData = await testResponse.json();
    if (db && isConnected) {
      await db.collection('settings').updateOne(
        {},
        { $set: { qontoOrganizationId: organizationId, qontoSecretKey: secretKey, qontoOrganizationName: orgData.organization?.name } },
        { upsert: true }
      );
    }
    console.log('✅ Qonto configuré pour:', orgData.organization?.name);
    res.json({ success: true, organizationName: orgData.organization?.name });
  } catch (error) {
    console.error('Erreur configuration Qonto:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/qonto/status', async (req, res) => {
  try {
    const settings = await getSettings();
    if (!settings?.qontoOrganizationId) {
      return res.json({ success: true, configured: false });
    }
    const qontoAuth = `${settings.qontoOrganizationId}:${settings.qontoSecretKey}`;
    const testResponse = await fetch('https://thirdparty.qonto.com/v2/organization', {
      headers: { 'Authorization': qontoAuth, 'Content-Type': 'application/json' }
    });
    const connected = testResponse.ok;
    res.json({ 
      success: true, 
      configured: true,
      connected,
      organizationName: settings.qontoOrganizationName
    });
  } catch (error) {
    console.error('Erreur statut Qonto:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== GESTION DES ERREURS =====
app.use((err, req, res, next) => {
  console.error(`[${req.requestId}] Erreur:`, err.message);
  if (err.message === 'Non autorisé par CORS') {
    return res.status(403).json({ success: false, error: 'Accès non autorisé' });
  }
  res.status(500).json({ success: false, error: 'Erreur serveur interne' });
});

// Route 404 - DOIT ÊTRE EN DERNIER
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Route non trouvée' });
});

// =============================================
// DÉMARRAGE DU SERVEUR
// =============================================
async function startServer() {
  await connectDB();
  
  try {
    const settings = await getSettings();
    if (settings?.stripeSecretKey && settings?.stripeEnabled) {
      console.log('🔄 Initialisation des prix Stripe...');
      const stripe = require('stripe')(settings.stripeSecretKey);
      await initializeStripePrices(stripe);
      console.log('✅ Prix Stripe initialisés:', {
        simple: STRIPE_PLANS.simple.stripePriceId ? '✅' : '❌',
        premium: STRIPE_PLANS.premium.stripePriceId ? '✅' : '❌'
      });
    } else {
      console.log('⚠️ Stripe non configuré ou désactivé');
    }
  } catch (stripeError) {
    console.error('⚠️ Erreur initialisation Stripe:', stripeError.message);
  }
  
  app.listen(PORT, () => {
    console.log('');
    console.log('🛢️  ========================================');
    console.log('🛢️  UCO AND CO - Backend API (SÉCURISÉ)');
    console.log('🛢️  ========================================');
    console.log(`🚀 Serveur démarré sur le port ${PORT}`);
    console.log(`📊 Base de données: ${isConnected ? 'MongoDB Atlas ✅' : 'Mode mémoire ⚠️'}`);
    console.log('🔒 Sécurité activée:');
    console.log('   ✅ Helmet (Headers sécurisés)');
    console.log('   ✅ CORS restreint');
    console.log('   ✅ Rate limiting');
    console.log('   ✅ Sanitization NoSQL/XSS');
    console.log('   ✅ JWT Authentication');
    console.log('   ✅ Bcrypt (12 rounds)');
    console.log('   ✅ Verrouillage de compte');
    console.log('   ✅ Audit logs');
    console.log('   ✅ Reconnexion auto MongoDB');
    console.log('   ✅ Anti-crash global');
    console.log('');
  });
}

startServer();
