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
// CONFIGURATION SÉCURITÉ
// =============================================
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = '24h';
const BCRYPT_ROUNDS = 12; // Plus sécurisé que 10
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 minutes

// =============================================
// MIDDLEWARES DE SÉCURITÉ
// =============================================

// 1. Helmet - Headers HTTP de sécurité
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

// 2. CORS sécurisé
const allowedOrigins = [
  'https://uco-and-co.netlify.app',
  'https://uco-and-co.fr',
  'https://www.uco-and-co.fr',
  process.env.FRONTEND_URL,
  'http://localhost:3000', // Dev only
  'http://localhost:5173'  // Dev only
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // Permettre les requêtes sans origin (mobile apps, Postman)
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

// 3. Rate Limiting - Protection contre les attaques par force brute
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500, // 500 requêtes par IP par 15 minutes (augmenté)
  message: { success: false, error: 'Trop de requêtes, réessayez dans 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Ne pas limiter les requêtes de santé et les GET settings
    return req.path === '/api/health' || (req.path === '/api/settings' && req.method === 'GET');
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // 20 tentatives de connexion (augmenté)
  message: { success: false, error: 'Trop de tentatives de connexion, réessayez dans 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
});

const strictLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 heure
  max: 10, // 10 requêtes par heure pour reset password (augmenté)
  message: { success: false, error: 'Limite atteinte, réessayez plus tard' },
});

app.use('/api/', generalLimiter);
app.use('/api/auth/', authLimiter);
app.use('/api/password-reset', strictLimiter);

// 4. Trust proxy (requis pour Render et le rate limiting)
app.set('trust proxy', 1);

// 5. Body parser avec limite
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 6. Sanitization contre les injections NoSQL
app.use(mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    console.warn(`🚫 Tentative d'injection NoSQL détectée: ${key}`);
  }
}));

// 6. Protection XSS
app.use(xss());

// 7. Protection contre la pollution des paramètres HTTP
app.use(hpp());

// 8. Logging des requêtes (pour audit)
app.use((req, res, next) => {
  const requestId = uuidv4().slice(0, 8);
  req.requestId = requestId;
  
  // Log uniquement en production pour les routes sensibles
  if (req.path.includes('/auth') || req.path.includes('/password')) {
    console.log(`[${new Date().toISOString()}] ${requestId} ${req.method} ${req.path} - IP: ${req.ip}`);
  }
  
  // Ajouter l'ID de requête dans la réponse
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

// Structure initiale
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

// Collections MongoDB
const COLLECTIONS = {
  SETTINGS: 'settings',
  COLLECTORS: 'collectors',
  OPERATORS: 'operators',
  RESTAURANTS: 'restaurants',
  COLLECTIONS: 'collections',
  TOURNEES: 'tournees',
  AUDIT_LOGS: 'auditLogs',
  SESSIONS: 'sessions',
  DOCUMENTS: 'documents',
  CAMPAIGNS: 'campaigns',
  AVIS: 'avis'
};

// Cache avec TTL
const cache = {
  settings: null,
  lastSettingsUpdate: 0,
  TTL: 60000 // 1 minute
};

// Fonction utilitaire pour récupérer les settings de manière fiable
async function getSettings() {
  try {
    // Vérifier le cache
    if (cache.settings && (Date.now() - cache.lastSettingsUpdate) < cache.TTL) {
      return cache.settings;
    }
    
    // Récupérer tous les documents settings et les fusionner
    const allSettings = await db.collection('settings').find({}).toArray();
    
    if (allSettings.length === 0) {
      console.log('⚠️ Aucun document settings trouvé');
      return null;
    }
    
    // Fusionner tous les documents en un seul (le plus récent écrase)
    let mergedSettings = {};
    for (const doc of allSettings) {
      mergedSettings = { ...mergedSettings, ...doc };
    }
    
    // Mettre à jour le cache
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
    console.error('❌ Erreur récupération settings:', error);
    return null;
  }
}

// =============================================
// FONCTIONS UTILITAIRES DE SÉCURITÉ
// =============================================

// Validation d'email
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Validation de mot de passe fort
function isStrongPassword(password) {
  // Minimum 8 caractères, 1 majuscule, 1 minuscule, 1 chiffre, 1 caractère spécial
  const strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return strongRegex.test(password);
}

// Sanitization des entrées
function sanitizeInput(input, key = '') {
  if (typeof input !== 'string') return input;
  
  // Ne pas limiter la longueur pour les champs base64, signatures, contrat, etc.
  const unlimitedFields = ['restaurant', 'admin', 'collecteur', 'base64', 'content', 'data', 'signature', 'contrat', 'bordereau'];
  const isUnlimited = unlimitedFields.some(f => key.toLowerCase().includes(f));
  
  const sanitized = input
    .replace(/[<>]/g, '') // Enlever les balises HTML
    .trim();
  
  // Limiter la longueur seulement pour les champs normaux
  return isUnlimited ? sanitized : sanitized.slice(0, 5000);
}

// Sanitization récursive d'un objet
function sanitizeObject(obj, parentKey = '') {
  if (typeof obj !== 'object' || obj === null) {
    return sanitizeInput(obj, parentKey);
  }
  
  const sanitized = Array.isArray(obj) ? [] : {};
  for (const key of Object.keys(obj)) {
    // Bloquer les clés commençant par $ (opérateurs MongoDB)
    if (key.startsWith('$')) continue;
    sanitized[key] = sanitizeObject(obj[key], key);
  }
  return sanitized;
}

// Génération de token JWT
function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// Vérification de token JWT
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// Middleware d'authentification JWT
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

// Middleware de vérification de rôle
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Accès non autorisé' });
    }
    next();
  };
}

// Log d'audit
async function auditLog(action, userId, details, req) {
  if (!db) return;
  
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

// Vérification du verrouillage de compte
function isAccountLocked(user) {
  if (!user.lockUntil) return false;
  return new Date(user.lockUntil) > new Date();
}

// Incrémenter les tentatives de connexion
async function incrementLoginAttempts(collection, identifier) {
  if (!db) return;
  
  const update = {
    $inc: { loginAttempts: 1 }
  };
  
  // Verrouiller si max atteint
  const user = await db.collection(collection).findOne({ email: identifier });
  if (user && user.loginAttempts >= MAX_LOGIN_ATTEMPTS - 1) {
    update.$set = { lockUntil: new Date(Date.now() + LOCK_TIME).toISOString() };
  }
  
  await db.collection(collection).updateOne({ email: identifier }, update);
}

// Réinitialiser les tentatives de connexion
async function resetLoginAttempts(collection, identifier) {
  if (!db) return;
  await db.collection(collection).updateOne(
    { email: identifier },
    { $set: { loginAttempts: 0, lockUntil: null } }
  );
}

// =============================================
// CONNEXION MONGODB SÉCURISÉE
// =============================================
async function connectDB() {
  if (!MONGODB_URI) {
    console.warn('⚠️ MONGODB_URI non configurée - Mode mémoire uniquement');
    return false;
  }

  try {
    console.log('🔄 Connexion sécurisée à MongoDB Atlas...');
    mongoClient = new MongoClient(MONGODB_URI, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    
    await mongoClient.connect();
    db = mongoClient.db(DB_NAME);
    
    // Créer les index
    await db.collection(COLLECTIONS.COLLECTORS).createIndex({ email: 1 }, { unique: true, sparse: true });
    await db.collection(COLLECTIONS.OPERATORS).createIndex({ email: 1 }, { unique: true, sparse: true });
    await db.collection(COLLECTIONS.RESTAURANTS).createIndex({ id: 1 }, { unique: true });
    await db.collection(COLLECTIONS.RESTAURANTS).createIndex({ qrCode: 1 }, { sparse: true });
    await db.collection(COLLECTIONS.RESTAURANTS).createIndex({ email: 1 }, { sparse: true });
    await db.collection(COLLECTIONS.AUDIT_LOGS).createIndex({ timestamp: -1 });
    await db.collection(COLLECTIONS.AUDIT_LOGS).createIndex({ action: 1 });
    await db.collection(COLLECTIONS.SESSIONS).createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    
    // Initialiser les settings
    const existingSettings = await db.collection(COLLECTIONS.SETTINGS).findOne({ _id: 'main' });
    if (!existingSettings) {
      await db.collection(COLLECTIONS.SETTINGS).insertOne({ 
        _id: 'main', 
        ...initialData.settings, 
        admin: initialData.admin 
      });
    }
    
    console.log('✅ Connecté à MongoDB Atlas avec succès (mode sécurisé)');
    return true;
  } catch (error) {
    console.error('❌ Erreur connexion MongoDB:', error.message);
    return false;
  }
}

// Gestion gracieuse de la fermeture
process.on('SIGINT', async () => {
  console.log('\n🛑 Arrêt du serveur...');
  if (mongoClient) {
    await mongoClient.close();
    console.log('✅ Connexion MongoDB fermée');
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n🛑 Arrêt du serveur (SIGTERM)...');
  if (mongoClient) {
    await mongoClient.close();
  }
  process.exit(0);
});

// =============================================
// FONCTIONS D'ACCÈS AUX DONNÉES
// =============================================

// getSettings est définie plus haut avec gestion robuste des documents multiples

async function updateSettings(newSettings) {
  if (!db) return false;
  
  try {
    // Récupérer les settings existants pour les préserver
    const existingSettings = await getSettings() || {};
    
    // Merger les nouveaux settings avec les existants (préserver admin et autres champs)
    const mergedSettings = {
      ...existingSettings,
      ...newSettings,
      // Préserver les sous-objets importants
      admin: existingSettings.admin, // Ne jamais écraser admin via cette fonction
      reviewLinks: {
        ...(existingSettings.reviewLinks || {}),
        ...(newSettings.reviewLinks || {})
      }
    };
    
    // Si brevoApiKey n'est pas fourni, garder l'ancien
    if (!newSettings.brevoApiKey && existingSettings.brevoApiKey) {
      mergedSettings.brevoApiKey = existingSettings.brevoApiKey;
    }
    
    // Si stripeSecretKey n'est pas fourni, garder l'ancien
    if (!newSettings.stripeSecretKey && existingSettings.stripeSecretKey) {
      mergedSettings.stripeSecretKey = existingSettings.stripeSecretKey;
    }
    
    // Si stripePublicKey n'est pas fourni ou est masqué, garder l'ancien
    if ((!newSettings.stripePublicKey || newSettings.stripePublicKey.startsWith('••••')) && existingSettings.stripePublicKey) {
      mergedSettings.stripePublicKey = existingSettings.stripePublicKey;
    }
    
    // Si stripeWebhookSecret n'est pas fourni, garder l'ancien
    if (!newSettings.stripeWebhookSecret && existingSettings.stripeWebhookSecret) {
      mergedSettings.stripeWebhookSecret = existingSettings.stripeWebhookSecret;
    }
    
    // Si qontoSecretKey n'est pas fourni, garder l'ancien
    if (!newSettings.qontoSecretKey && existingSettings.qontoSecretKey) {
      mergedSettings.qontoSecretKey = existingSettings.qontoSecretKey;
    }
    
    // Si qontoOrganizationId n'est pas fourni, garder l'ancien
    if (!newSettings.qontoOrganizationId && existingSettings.qontoOrganizationId) {
      mergedSettings.qontoOrganizationId = existingSettings.qontoOrganizationId;
    }
    
    // Si qontoOrganizationName n'est pas fourni, garder l'ancien
    if (!newSettings.qontoOrganizationName && existingSettings.qontoOrganizationName) {
      mergedSettings.qontoOrganizationName = existingSettings.qontoOrganizationName;
    }
    
    // Supprimer _id du merged pour éviter les erreurs
    delete mergedSettings._id;
    
    // Trouver le document existant ou utiliser 'main' comme fallback
    const existingDoc = await db.collection(COLLECTIONS.SETTINGS).findOne({});
    const docId = existingDoc?._id || 'main';
    
    await db.collection(COLLECTIONS.SETTINGS).updateOne(
      { _id: docId },
      { $set: mergedSettings },
      { upsert: true }
    );
    
    // Invalider le cache
    cache.settings = null;
    cache.lastSettingsUpdate = 0;
    
    console.log('✅ Settings mis à jour avec succès');
    return true;
  } catch (error) {
    console.error('❌ Erreur updateSettings:', error);
    return false;
  }
}

async function getAdmin() {
  const settings = await getSettings();
  return settings.admin || initialData.admin;
}

// Collecteurs
async function getCollectors(status = null) {
  if (!db) return [];
  const query = status ? { status } : {};
  return await db.collection(COLLECTIONS.COLLECTORS).find(query).toArray();
}

async function getCollectorByEmail(email) {
  if (!db) return null;
  return await db.collection(COLLECTIONS.COLLECTORS).findOne({ email: sanitizeInput(email) });
}

async function addCollector(collector) {
  if (!db) return null;
  const sanitized = sanitizeObject(collector);
  const result = await db.collection(COLLECTIONS.COLLECTORS).insertOne({
    ...sanitized,
    _id: sanitized.email,
    loginAttempts: 0,
    lockUntil: null,
    createdAt: new Date().toISOString()
  });
  return result.insertedId;
}

async function updateCollector(email, data) {
  if (!db) return false;
  await db.collection(COLLECTIONS.COLLECTORS).updateOne(
    { email: sanitizeInput(email) },
    { $set: { ...sanitizeObject(data), updatedAt: new Date().toISOString() } }
  );
  return true;
}

async function deleteCollector(email) {
  if (!db) return false;
  await db.collection(COLLECTIONS.COLLECTORS).deleteOne({ email: sanitizeInput(email) });
  return true;
}

// Opérateurs
async function getOperators(status = null) {
  if (!db) return [];
  const query = status ? { status } : {};
  return await db.collection(COLLECTIONS.OPERATORS).find(query).toArray();
}

async function getOperatorByEmail(email) {
  if (!db) return null;
  return await db.collection(COLLECTIONS.OPERATORS).findOne({ email: sanitizeInput(email) });
}

async function addOperator(operator) {
  if (!db) return null;
  const sanitized = sanitizeObject(operator);
  const result = await db.collection(COLLECTIONS.OPERATORS).insertOne({
    ...sanitized,
    _id: sanitized.email,
    loginAttempts: 0,
    lockUntil: null,
    createdAt: new Date().toISOString()
  });
  return result.insertedId;
}

async function updateOperator(email, data) {
  if (!db) return false;
  await db.collection(COLLECTIONS.OPERATORS).updateOne(
    { email: sanitizeInput(email) },
    { $set: { ...sanitizeObject(data), updatedAt: new Date().toISOString() } }
  );
  return true;
}

async function deleteOperator(email) {
  if (!db) return false;
  await db.collection(COLLECTIONS.OPERATORS).deleteOne({ email: sanitizeInput(email) });
  return true;
}

// Restaurants
async function getRestaurants(status = null) {
  if (!db) return [];
  const query = status ? { status } : {};
  return await db.collection(COLLECTIONS.RESTAURANTS).find(query).toArray();
}

async function getRestaurantById(id) {
  if (!db) return null;
  const sanitizedId = sanitizeInput(id);
  // Chercher par id, siret ou qrCode
  return await db.collection(COLLECTIONS.RESTAURANTS).findOne({ 
    $or: [
      { id: sanitizedId },
      { siret: sanitizedId },
      { qrCode: sanitizedId }
    ]
  });
}

async function getRestaurantByQRCode(qrCode) {
  if (!db) return null;
  return await db.collection(COLLECTIONS.RESTAURANTS).findOne({ qrCode: sanitizeInput(qrCode) });
}

async function getRestaurantByEmail(email) {
  if (!db) return null;
  return await db.collection(COLLECTIONS.RESTAURANTS).findOne({ email: sanitizeInput(email) });
}

async function addRestaurant(restaurant) {
  if (!db) return null;
  const sanitized = sanitizeObject(restaurant);
  const result = await db.collection(COLLECTIONS.RESTAURANTS).insertOne({
    ...sanitized,
    _id: sanitized.id,
    loginAttempts: 0,
    lockUntil: null,
    createdAt: new Date().toISOString()
  });
  return result.insertedId;
}

async function updateRestaurant(id, data) {
  if (!db) return false;
  const sanitizedId = sanitizeInput(id);
  // Chercher par id, siret ou qrCode
  await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
    { $or: [{ id: sanitizedId }, { siret: sanitizedId }, { qrCode: sanitizedId }] },
    { $set: { ...sanitizeObject(data), updatedAt: new Date().toISOString() } }
  );
  return true;
}

async function deleteRestaurant(id) {
  if (!db) return false;
  await db.collection(COLLECTIONS.RESTAURANTS).deleteOne({ id: sanitizeInput(id) });
  return true;
}

// Collections
async function getCollections() {
  if (!db) return [];
  return await db.collection(COLLECTIONS.COLLECTIONS).find({}).sort({ date: -1 }).toArray();
}

async function addCollection(collection) {
  if (!db) return null;
  const sanitized = sanitizeObject(collection);
  const result = await db.collection(COLLECTIONS.COLLECTIONS).insertOne({
    ...sanitized,
    _id: sanitized.id || uuidv4(),
    createdAt: new Date().toISOString()
  });
  return result.insertedId;
}

// Tournées
async function getTournees() {
  if (!db) return [];
  return await db.collection(COLLECTIONS.TOURNEES).find({}).sort({ dateDepart: -1 }).toArray();
}

async function addTournee(tournee) {
  if (!db) return null;
  const sanitized = sanitizeObject(tournee);
  const result = await db.collection(COLLECTIONS.TOURNEES).insertOne({
    ...sanitized,
    _id: sanitized.id || uuidv4(),
    createdAt: new Date().toISOString()
  });
  return result.insertedId;
}

async function updateTournee(id, data) {
  if (!db) return false;
  await db.collection(COLLECTIONS.TOURNEES).updateOne(
    { _id: sanitizeInput(id) },
    { $set: sanitizeObject(data) }
  );
  return true;
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

// Proxy pour l'API recherche entreprises (SIRET)
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

// Proxy pour l'API geo.api.gouv.fr (villes par code postal)
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

// ===== ROUTES API =====

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    database: db ? 'MongoDB Atlas' : 'Non connecté',
    persistent: db !== null,
    secure: true,
    timestamp: new Date().toISOString()
  });
});

// Endpoint de test email - envoie un email HTML simple pour vérifier que Brevo fonctionne
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
    
    // HTML très simple - exactement comme le test curl qui fonctionnait
    const simpleHtml = '<html><head><meta charset="UTF-8"></head><body><h1 style="color:green;">Test UCO AND CO</h1><p>Si ce texte est <strong>vert</strong>, le HTML fonctionne correctement!</p><p>Date: ' + new Date().toLocaleString('fr-FR') + '</p></body></html>';
    
    console.log('=== TEST EMAIL ===');
    console.log('To:', to);
    console.log('HTML:', simpleHtml);
    
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
    console.log('Brevo response:', responseData);
    
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

// ===== AUTHENTIFICATION SÉCURISÉE =====
app.post('/api/auth/admin', async (req, res) => {
  try {
    const { email, password } = sanitizeObject(req.body);
    
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
    }
    
    const admin = await getAdmin();
    
    // Vérifier le verrouillage
    if (isAccountLocked(admin)) {
      await auditLog('ADMIN_LOGIN_LOCKED', email, { reason: 'Account locked' }, req);
      return res.status(423).json({ 
        success: false, 
        error: 'Compte verrouillé. Réessayez dans 15 minutes.' 
      });
    }
    
    if (email !== admin.email) {
      await auditLog('ADMIN_LOGIN_FAILED', email, { reason: 'Invalid email' }, req);
      return res.status(401).json({ success: false, error: 'Identifiants incorrects' });
    }
    
    const isValid = await bcrypt.compare(password, admin.password);
    
    if (!isValid) {
      await auditLog('ADMIN_LOGIN_FAILED', email, { reason: 'Invalid password' }, req);
      // Incrémenter les tentatives (pour admin, on stocke dans settings)
      return res.status(401).json({ success: false, error: 'Identifiants incorrects' });
    }
    
    // Succès - Générer token
    const token = generateToken({ role: 'admin', email });
    
    await auditLog('ADMIN_LOGIN_SUCCESS', email, {}, req);
    
    res.json({ 
      success: true, 
      role: 'admin',
      token,
      expiresIn: JWT_EXPIRES_IN
    });
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
      return res.status(423).json({ 
        success: false, 
        error: 'Compte verrouillé. Réessayez dans 15 minutes.' 
      });
    }
    
    const isValid = await bcrypt.compare(password, collector.password);
    
    if (!isValid) {
      await incrementLoginAttempts(COLLECTIONS.COLLECTORS, email);
      await auditLog('COLLECTOR_LOGIN_FAILED', email, { reason: 'Invalid password' }, req);
      return res.status(401).json({ success: false, error: 'Mot de passe incorrect' });
    }
    
    // Succès
    await resetLoginAttempts(COLLECTIONS.COLLECTORS, email);
    
    const token = generateToken({ 
      role: 'collector', 
      email,
      collectorNumber: collector.collectorNumber 
    });
    
    const { password: _, loginAttempts, lockUntil, ...data } = collector;
    
    await auditLog('COLLECTOR_LOGIN_SUCCESS', email, {}, req);
    
    res.json({ 
      success: true, 
      role: 'collector', 
      data,
      token,
      expiresIn: JWT_EXPIRES_IN
    });
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
    
    // Si le restaurant a été créé par l'admin (a un tempPassword) mais pas de status, on le considère comme approved
    const isApproved = restaurant.status === 'approved' || 
                       (restaurant.tempPassword && !restaurant.status) ||
                       (restaurant.createdBy === 'admin' && !restaurant.status);
    
    if (!isApproved) {
      return res.status(401).json({ success: false, error: 'Compte non approuvé' });
    }
    
    if (isAccountLocked(restaurant)) {
      return res.status(423).json({ success: false, error: 'Compte verrouillé' });
    }
    
    // Vérifier le mot de passe (hashé OU provisoire)
    let isValid = false;
    let usedTempPassword = false;
    
    // D'abord vérifier le mot de passe hashé (si existe)
    if (restaurant.password) {
      try {
        isValid = await bcrypt.compare(password, restaurant.password);
        console.log('Vérification mot de passe hashé:', isValid);
      } catch (bcryptError) {
        console.error('Erreur bcrypt:', bcryptError);
      }
    }
    
    // Si pas valide et qu'il y a un mot de passe provisoire, le vérifier
    if (!isValid && restaurant.tempPassword) {
      isValid = (password === restaurant.tempPassword);
      usedTempPassword = isValid;
      console.log('Vérification mot de passe provisoire:', isValid);
    }
    
    if (!isValid) {
      await incrementLoginAttempts(COLLECTIONS.RESTAURANTS, email);
      return res.status(401).json({ success: false, error: 'Mot de passe incorrect' });
    }
    
    // Si le restaurant n'avait pas de status, le mettre à jour
    if (!restaurant.status && (restaurant.tempPassword || restaurant.createdBy === 'admin')) {
      await updateRestaurant(restaurant.id, { status: 'approved' });
      console.log('Status mis à jour vers approved pour:', restaurant.id);
    }
    
    await resetLoginAttempts(COLLECTIONS.RESTAURANTS, email);
    
    const token = generateToken({ role: 'restaurant', email, id: restaurant.id });
    const { password: _, tempPassword: __, loginAttempts, lockUntil, ...data } = restaurant;
    
    await auditLog('RESTAURANT_LOGIN_SUCCESS', email, { usedTempPassword }, req);
    
    console.log('Connexion réussie pour:', email);
    
    // Indiquer si le mot de passe provisoire a été utilisé (pour inciter à le changer)
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

// Vérification de token
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
    
    // Vérifier force du mot de passe (optionnel mais recommandé)
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
    
    // Si un SIRET est fourni, vérifier s'il existe déjà
    let existingBySiret = null;
    if (siret) {
      existingBySiret = await db.collection(COLLECTIONS.RESTAURANTS).findOne({ siret });
    }
    
    // Si le SIRET existe déjà
    if (existingBySiret) {
      // Cas 1: Restaurant créé par admin sans mot de passe → Le restaurant finalise son compte
      // Cas 2: Restaurant résilié qui veut se réinscrire
      // Dans les deux cas, on permet la mise à jour
      
      // Vérifier si l'email est différent ET appartient à un autre restaurant
      if (email && email !== existingBySiret.email) {
        const existingByEmail = await getRestaurantByEmail(email);
        if (existingByEmail && existingByEmail.siret !== siret) {
          return res.status(409).json({ success: false, error: 'Cet email est déjà utilisé par un autre restaurant' });
        }
      }
      
      // Déterminer si c'est une finalisation de compte (ajout de mot de passe) ou une réinscription
      const isAccountFinalization = !existingBySiret.password && password;
      const isResubmission = existingBySiret.status === 'terminated';
      
      // Préparer les données de mise à jour
      const updateData = {
        ...data,
        email: email || existingBySiret.email,
        dateRequest: new Date().toISOString()
      };
      
      // Ajouter le mot de passe hashé si fourni
      if (password) {
        updateData.password = await bcrypt.hash(password, BCRYPT_ROUNDS);
      }
      
      // Déterminer le nouveau statut
      if (isAccountFinalization && existingBySiret.status === 'approved') {
        // Compte déjà approuvé, juste besoin du mot de passe → reste approved
        updateData.status = 'approved';
        updateData.passwordSetDate = new Date().toISOString();
      } else {
        // Réinscription ou nouveau compte → passe en pending
        updateData.status = 'pending';
        updateData.isResubmission = isResubmission;
      }
      
      await updateRestaurant(existingBySiret.id, updateData);
      
      const logAction = isAccountFinalization ? 'RESTAURANT_FINALIZE_ACCOUNT' : 'RESTAURANT_RESUBMIT';
      await auditLog(logAction, email || existingBySiret.id, { 
        status: updateData.status, 
        siret,
        isAccountFinalization,
        isResubmission
      }, req);
      
      return res.status(200).json({ 
        success: true, 
        id: existingBySiret.id, 
        qrCode: existingBySiret.qrCode || existingBySiret.id,
        isAccountFinalization,
        isResubmission,
        status: updateData.status,
        message: isAccountFinalization 
          ? 'Compte finalisé avec succès' 
          : 'Demande de réinscription soumise'
      });
    }
    
    // Nouveau restaurant (SIRET non existant)
    // Vérifier si l'email est déjà utilisé
    if (email) {
      const existingByEmail = await getRestaurantByEmail(email);
      if (existingByEmail) {
        return res.status(409).json({ success: false, error: 'Cet email est déjà utilisé' });
      }
    }
    
    // Générer un QR Code au format QR-XXXXX
    let newQRCode = qrCode;
    if (!newQRCode || !newQRCode.startsWith('QR-')) {
      // Trouver le prochain numéro disponible
      const allRestaurants = await getRestaurants();
      const existingNumbers = allRestaurants
        .filter(r => r.qrCode && r.qrCode.startsWith('QR-'))
        .map(r => parseInt(r.qrCode.replace('QR-', '')) || 0);
      const maxNumber = existingNumbers.length > 0 ? Math.max(...existingNumbers) : 0;
      newQRCode = `QR-${String(maxNumber + 1).padStart(5, '0')}`;
    }
    
    // Vérifier que le QR Code n'existe pas déjà
    const existingQR = await getRestaurantByQRCode(newQRCode);
    if (existingQR) {
      // Générer un nouveau numéro
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

// Recherche par SIRET (retourne même les restaurants résiliés pour conserver le QR Code)
app.get('/api/restaurants/siret/:siret', async (req, res) => {
  const siret = req.params.siret.replace(/\D/g, '');
  
  if (siret.length !== 14) {
    return res.status(400).json({ error: 'SIRET invalide (14 chiffres requis)' });
  }
  
  if (!db) {
    return res.status(503).json({ error: 'Base de données non disponible' });
  }
  
  const restaurant = await db.collection(COLLECTIONS.RESTAURANTS).findOne({ siret });
  
  if (!restaurant) {
    return res.status(404).json({ error: 'Restaurant non trouvé', exists: false });
  }
  
  const { password, loginAttempts, lockUntil, ...data } = restaurant;
  res.json({ ...data, exists: true });
});

// Fin de contrat restaurant
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
    
    res.json({ 
      success: true, 
      dateTerminated,
      message: 'Contrat résilié avec succès'
    });
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

// Endpoint pour changer le mot de passe avec vérification de l'ancien
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
    
    // Vérifier l'ancien mot de passe (hashé ou provisoire)
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
    
    // Mettre à jour le mot de passe et supprimer le tempPassword
    await updateRestaurant(id, { 
      password: await bcrypt.hash(newPassword, BCRYPT_ROUNDS),
      tempPassword: null, // Supprimer le mot de passe provisoire
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

// ===== SETTINGS =====
app.get('/api/settings', async (req, res) => {
  const settings = await getSettings();
  // Ne pas renvoyer les infos sensibles (admin, clé Brevo complète)
  const { admin, brevoApiKey, ...publicSettings } = settings;
  
  // Indiquer si la clé Brevo existe sans la révéler
  publicSettings.brevoApiKey = brevoApiKey ? '••••••••••••••••' : '';
  publicSettings.hasBrevoKey = !!brevoApiKey;
  
  res.json(publicSettings);
});

app.put('/api/settings', async (req, res) => {
  try {
    // Ne pas sanitizer brevoApiKey car elle peut contenir des caractères spéciaux
    const { brevoApiKey, ...otherSettings } = req.body;
    const sanitizedSettings = sanitizeObject(otherSettings);
    
    // Ajouter brevoApiKey sans sanitization si elle existe
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
    
    // Récupérer le contenu brut
    let rawContent = content || htmlContent || html || '';
    
    // Décoder les entités HTML (le problème!)
    rawContent = rawContent
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&nbsp;/g, ' ');
    
    // Supprimer TOUTES les balises structurelles HTML
    let cleanContent = rawContent
      .replace(/<!DOCTYPE[^>]*>/gi, '')
      .replace(/<html[^>]*>/gi, '')
      .replace(/<\/html>/gi, '')
      .replace(/<head[^>]*>[\s\S]*?<\/head>/gi, '')
      .replace(/<body[^>]*>/gi, '')
      .replace(/<\/body>/gi, '')
      .replace(/<meta[^>]*>/gi, '')
      .trim();
    
    // Construire le HTML EXACTEMENT comme le test qui fonctionne
    const finalHtml = '<html><head><meta charset="UTF-8"></head><body style="font-family:Arial,sans-serif;padding:20px;">' + cleanContent + '</body></html>';
    
    console.log('=== ENVOI EMAIL ===');
    console.log('To:', to);
    console.log('Subject:', subject);
    console.log('Final HTML (150 chars):', finalHtml.substring(0, 150));
    
    const emailPayload = {
      sender: { 
        name: senderName || 'UCO AND CO', 
        email: 'contact@uco-and-co.fr' 
      },
      to: [{ email: to }],
      subject: subject.substring(0, 200),
      htmlContent: finalHtml
    };
    
    if (attachment && attachment.content && attachment.name) {
      emailPayload.attachment = [{ 
        content: attachment.content, 
        name: attachment.name.substring(0, 100) 
      }];
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
    const { to, message, content } = req.body; // Accepter 'content' comme alias
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
      // Message d'erreur explicite selon le code
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

// ===== AUDIT LOGS (Admin only) =====
app.get('/api/audit-logs', authenticateToken, requireRole('admin'), async (req, res) => {
  if (!db) return res.json([]);
  
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

// ===== GESTION DES ERREURS =====
app.use((err, req, res, next) => {
  console.error(`[${req.requestId}] Erreur:`, err.message);
  
  if (err.message === 'Non autorisé par CORS') {
    return res.status(403).json({ success: false, error: 'Accès non autorisé' });
  }
  
  res.status(500).json({ success: false, error: 'Erreur serveur interne' });
});

// ===== PARTENAIRES PRESTATAIRES =====
app.get('/api/partners', async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const partners = await db.collection('partners').find({}).toArray();
    res.json(partners);
  } catch (error) {
    console.error('Erreur GET partners:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/partners', async (req, res) => {
  try {
    if (!db) {
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
    if (!db) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const { id } = req.params;
    const updates = req.body;
    updates.updatedAt = new Date().toISOString();
    
    const result = await db.collection('partners').updateOne(
      { id: id },
      { $set: updates }
    );
    
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
    if (!db) {
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

// ===== STRIPE - PAIEMENTS ABONNEMENTS =====

// Créer une session de paiement Stripe
// =============================================
// STRIPE - GESTION COMPLÈTE DES ABONNEMENTS
// =============================================

// Configuration des prix (à créer dans Stripe Dashboard ou via API)
const STRIPE_PLANS = {
  starter: { name: 'Starter', price: 0, stripePriceId: null }, // Gratuit
  simple: { name: 'Simple', price: 1499, stripePriceId: null }, // 14.99€
  premium: { name: 'Premium', price: 1999, stripePriceId: null } // 19.99€
};

// Créer ou récupérer les prix Stripe au démarrage
async function initializeStripePrices(stripe) {
  try {
    // Chercher les produits existants
    const products = await stripe.products.list({ limit: 10 });
    
    for (const [planId, plan] of Object.entries(STRIPE_PLANS)) {
      if (plan.price === 0) continue; // Ignorer le plan gratuit
      
      let product = products.data.find(p => p.metadata?.planId === planId);
      
      if (!product) {
        // Créer le produit
        product = await stripe.products.create({
          name: `Abonnement UCO ${plan.name}`,
          description: `Services partenaires UCO AND CO - Formule ${plan.name}`,
          metadata: { planId }
        });
        console.log(`✅ Produit Stripe créé: ${plan.name}`);
      }
      
      // Chercher le prix récurrent
      const prices = await stripe.prices.list({ product: product.id, limit: 5 });
      let price = prices.data.find(p => p.recurring?.interval === 'month' && p.unit_amount === plan.price);
      
      if (!price) {
        // Créer le prix
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

// Créer une session de paiement pour nouvel abonnement
app.post('/api/stripe/create-subscription', async (req, res) => {
  try {
    const { restaurantId, plan, email, enseigne, siret } = req.body;
    
    const settings = await getSettings();
    if (!settings?.stripeSecretKey) {
      return res.status(400).json({ success: false, error: 'Stripe non configuré' });
    }
    
    const stripe = require('stripe')(settings.stripeSecretKey);
    
    // Initialiser les prix si pas encore fait
    if (!STRIPE_PLANS[plan]?.stripePriceId && plan !== 'starter') {
      await initializeStripePrices(stripe);
    }
    
    // Plan gratuit - pas besoin de Stripe
    if (plan === 'starter' || STRIPE_PLANS[plan]?.price === 0) {
      return res.json({ 
        success: true, 
        free: true,
        message: 'Formule gratuite - pas de paiement requis'
      });
    }
    
    const planConfig = STRIPE_PLANS[plan];
    if (!planConfig?.stripePriceId) {
      return res.status(400).json({ success: false, error: 'Plan invalide ou non configuré' });
    }
    
    // Créer ou récupérer le client Stripe
    let customer;
    const existingCustomers = await stripe.customers.list({ email, limit: 1 });
    
    if (existingCustomers.data.length > 0) {
      customer = existingCustomers.data[0];
      // Mettre à jour les métadonnées
      await stripe.customers.update(customer.id, {
        name: enseigne,
        metadata: { restaurantId, siret }
      });
    } else {
      customer = await stripe.customers.create({
        email,
        name: enseigne,
        metadata: { restaurantId, siret }
      });
    }
    
    // Créer la session Checkout
    const session = await stripe.checkout.sessions.create({
      customer: customer.id,
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [{
        price: planConfig.stripePriceId,
        quantity: 1
      }],
      subscription_data: {
        metadata: { restaurantId, siret, plan }
      },
      success_url: `${req.headers.origin || 'https://uco-and-co.fr'}?subscription=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.headers.origin || 'https://uco-and-co.fr'}?subscription=cancelled`,
      metadata: { restaurantId, siret, plan },
      // Permettre la mise à jour de la carte pour les prélèvements futurs
      payment_method_collection: 'always',
      // Configurer les relances automatiques
      subscription_data: {
        metadata: { restaurantId, siret, plan },
      }
    });
    
    console.log(`✅ Session Stripe créée: ${session.id} pour ${enseigne} (${plan})`);
    res.json({ success: true, sessionId: session.id, url: session.url });
    
  } catch (error) {
    console.error('Erreur création subscription Stripe:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Créer un Payment Intent pour paiement direct (sans subscription)
app.post('/api/stripe/create-payment-intent', async (req, res) => {
  try {
    const { restaurantId, amount, email, enseigne, description } = req.body;
    
    const settings = await getSettings();
    if (!settings?.stripeSecretKey) {
      return res.status(400).json({ success: false, error: 'Stripe non configuré' });
    }
    
    const stripe = require('stripe')(settings.stripeSecretKey);
    
    // Créer ou récupérer le client
    let customer;
    const existingCustomers = await stripe.customers.list({ email, limit: 1 });
    
    if (existingCustomers.data.length > 0) {
      customer = existingCustomers.data[0];
    } else {
      customer = await stripe.customers.create({
        email,
        name: enseigne,
        metadata: { restaurantId }
      });
    }
    
    // Créer le Payment Intent
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100), // Convertir en centimes
      currency: 'eur',
      customer: customer.id,
      description: description || `Paiement UCO AND CO - ${enseigne}`,
      metadata: { restaurantId },
      automatic_payment_methods: { enabled: true },
      setup_future_usage: 'off_session' // Permettre les prélèvements futurs
    });
    
    res.json({ 
      success: true, 
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id
    });
    
  } catch (error) {
    console.error('Erreur création Payment Intent:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Changer de formule (upgrade/downgrade)
app.post('/api/stripe/change-plan', async (req, res) => {
  try {
    const { restaurantId, newPlan } = req.body;
    
    const settings = await getSettings();
    if (!settings?.stripeSecretKey) {
      return res.status(400).json({ success: false, error: 'Stripe non configuré' });
    }
    
    const stripe = require('stripe')(settings.stripeSecretKey);
    
    // Récupérer le restaurant
    const restaurant = await db.collection(COLLECTIONS.RESTAURANTS).findOne({
      $or: [{ id: restaurantId }, { siret: restaurantId }]
    });
    
    if (!restaurant?.subscription?.stripeSubscriptionId) {
      return res.status(400).json({ success: false, error: 'Aucun abonnement Stripe actif' });
    }
    
    // Initialiser les prix si nécessaire
    if (!STRIPE_PLANS[newPlan]?.stripePriceId) {
      await initializeStripePrices(stripe);
    }
    
    const newPlanConfig = STRIPE_PLANS[newPlan];
    if (!newPlanConfig?.stripePriceId && newPlan !== 'starter') {
      return res.status(400).json({ success: false, error: 'Plan invalide' });
    }
    
    // Si downgrade vers starter (gratuit), annuler l'abonnement
    if (newPlan === 'starter') {
      await stripe.subscriptions.cancel(restaurant.subscription.stripeSubscriptionId);
      
      await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
        { $or: [{ id: restaurantId }, { siret: restaurantId }] },
        { 
          $set: { 
            'subscription.plan': 'starter',
            'subscription.status': 'active',
            'subscription.previousPlan': restaurant.subscription.plan,
            'subscription.planChangedAt': new Date().toISOString()
          },
          $unset: {
            'subscription.stripeSubscriptionId': ''
          }
        }
      );
      
      return res.json({ success: true, message: 'Abonnement annulé, passage à Starter' });
    }
    
    // Récupérer l'abonnement Stripe
    const subscription = await stripe.subscriptions.retrieve(restaurant.subscription.stripeSubscriptionId);
    
    // Mettre à jour l'abonnement avec le nouveau prix
    const updatedSubscription = await stripe.subscriptions.update(subscription.id, {
      items: [{
        id: subscription.items.data[0].id,
        price: newPlanConfig.stripePriceId
      }],
      proration_behavior: 'create_prorations', // Facturer au prorata
      metadata: { ...subscription.metadata, plan: newPlan }
    });
    
    // Mettre à jour en base
    await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
      { $or: [{ id: restaurantId }, { siret: restaurantId }] },
      { 
        $set: { 
          'subscription.plan': newPlan,
          'subscription.previousPlan': restaurant.subscription.plan,
          'subscription.planChangedAt': new Date().toISOString()
        }
      }
    );
    
    console.log(`✅ Changement de plan: ${restaurant.enseigne} - ${restaurant.subscription.plan} → ${newPlan}`);
    
    res.json({ 
      success: true, 
      message: `Changement vers ${newPlanConfig.name} effectué`,
      prorated: true
    });
    
  } catch (error) {
    console.error('Erreur changement plan:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Mettre à jour la carte de paiement
app.post('/api/stripe/update-payment-method', async (req, res) => {
  try {
    const { restaurantId } = req.body;
    
    const settings = await getSettings();
    if (!settings?.stripeSecretKey) {
      return res.status(400).json({ success: false, error: 'Stripe non configuré' });
    }
    
    const stripe = require('stripe')(settings.stripeSecretKey);
    
    const restaurant = await db.collection(COLLECTIONS.RESTAURANTS).findOne({
      $or: [{ id: restaurantId }, { siret: restaurantId }]
    });
    
    if (!restaurant?.subscription?.stripeCustomerId) {
      return res.status(400).json({ success: false, error: 'Aucun client Stripe trouvé' });
    }
    
    // Créer une session de configuration de carte
    const session = await stripe.billingPortal.sessions.create({
      customer: restaurant.subscription.stripeCustomerId,
      return_url: `${req.headers.origin || 'https://uco-and-co.fr'}?payment_updated=true`
    });
    
    res.json({ success: true, url: session.url });
    
  } catch (error) {
    console.error('Erreur mise à jour carte:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Endpoint legacy pour compatibilité
app.post('/api/stripe/create-checkout-session', async (req, res) => {
  // Rediriger vers le nouvel endpoint
  req.body.plan = req.body.plan || 'simple';
  return res.redirect(307, '/api/stripe/create-subscription');
});

// Webhook Stripe pour les événements de paiement
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const settings = await getSettings();
    if (!settings?.stripeSecretKey || !settings?.stripeWebhookSecret) {
      return res.status(400).json({ error: 'Stripe non configuré' });
    }
    
    const stripe = require('stripe')(settings.stripeSecretKey);
    const sig = req.headers['stripe-signature'];
    
    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, settings.stripeWebhookSecret);
    } catch (err) {
      console.error('Erreur signature webhook:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    
    console.log(`📥 Webhook Stripe reçu: ${event.type}`);
    
    // Gérer les événements
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const { restaurantId, siret, plan } = session.metadata;
        const identifier = restaurantId || siret;
        
        // Récupérer les infos du payment method
        let cardLast4 = '****';
        if (session.payment_method_types?.includes('card') && session.subscription) {
          try {
            const subscription = await stripe.subscriptions.retrieve(session.subscription);
            if (subscription.default_payment_method) {
              const pm = await stripe.paymentMethods.retrieve(subscription.default_payment_method);
              cardLast4 = pm.card?.last4 || '****';
            }
          } catch (e) { console.log('Impossible de récupérer la carte:', e.message); }
        }
        
        // Mettre à jour l'abonnement du restaurant
        await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
          { $or: [{ id: identifier }, { siret: identifier }] },
          {
            $set: {
              subscription: {
                plan,
                status: 'active',
                stripeCustomerId: session.customer,
                stripeSubscriptionId: session.subscription,
                startDate: new Date().toISOString(),
                lastPaymentDate: new Date().toISOString(),
                cardLast4
              }
            },
            $unset: {
              'subscription.failedAttempts': '',
              'subscription.firstFailedAt': '',
              'subscription.blockedAt': '',
              'subscription.blockedReason': ''
            }
          }
        );
        
        console.log(`✅ Abonnement ${plan} activé pour: ${identifier}`);
        
        // Envoyer email de confirmation
        const restaurant = await db.collection(COLLECTIONS.RESTAURANTS).findOne({
          $or: [{ id: identifier }, { siret: identifier }]
        });
        
        if (restaurant) {
          try {
            const PLANS = { starter: 'Starter', simple: 'Simple', premium: 'Premium' };
            const emailHtml = `
              <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
                <div style="background:#6bb44a;padding:20px;text-align:center;border-radius:10px 10px 0 0;">
                  <h1 style="color:white;margin:0;">🎉 Abonnement activé !</h1>
                </div>
                <div style="background:#f9f9f9;padding:30px;border-radius:0 0 10px 10px;">
                  <p>Bonjour,</p>
                  <p>Votre abonnement <strong>${PLANS[plan]}</strong> est maintenant actif !</p>
                  <div style="background:#f0fdf4;border:1px solid #86efac;border-radius:8px;padding:15px;margin:20px 0;">
                    <p style="margin:5px 0;"><strong>Formule :</strong> ${PLANS[plan]}</p>
                    <p style="margin:5px 0;"><strong>Carte :</strong> **** **** **** ${cardLast4}</p>
                    <p style="margin:5px 0;"><strong>Prélèvement :</strong> Mensuel automatique</p>
                  </div>
                  <p>Vous pouvez dès maintenant profiter de tous vos services partenaires.</p>
                  <p>L'équipe UCO AND CO</p>
                </div>
              </div>
            `;
            
            await fetch(`http://localhost:${PORT}/api/send-email`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                to: restaurant.email,
                subject: `🎉 Abonnement ${PLANS[plan]} activé - UCO AND CO`,
                htmlContent: emailHtml
              })
            });
          } catch (e) { console.error('Erreur email confirmation:', e); }
        }
        
        break;
      }
      
      case 'invoice.payment_succeeded': {
        const invoice = event.data.object;
        
        if (invoice.subscription && invoice.billing_reason !== 'subscription_create') {
          // Paiement récurrent (pas le premier)
          const restaurant = await db.collection(COLLECTIONS.RESTAURANTS).findOneAndUpdate(
            { 'subscription.stripeSubscriptionId': invoice.subscription },
            { 
              $set: { 
                'subscription.lastPaymentDate': new Date().toISOString(),
                'subscription.status': 'active'
              },
              $unset: {
                'subscription.failedAttempts': '',
                'subscription.firstFailedAt': '',
                'subscription.lastFailedAt': '',
                'subscription.nextRetryAt': ''
              }
            },
            { returnDocument: 'after' }
          );
          
          if (restaurant.value) {
            console.log(`✅ Prélèvement mensuel réussi: ${restaurant.value.enseigne}`);
            
            // Générer la facture
            try {
              const r = restaurant.value;
              const PLANS = {
                starter: { name: 'Starter', price: 0 },
                simple: { name: 'Simple', price: 14.99 },
                premium: { name: 'Premium', price: 19.99 }
              };
              
              const plan = PLANS[r.subscription?.plan];
              const priceTTC = invoice.amount_paid / 100;
              const priceHT = (priceTTC / 1.20).toFixed(2);
              const tva = (priceTTC - parseFloat(priceHT)).toFixed(2);
              
              const invoiceNumber = `FAC-${new Date().getFullYear()}${String(new Date().getMonth()+1).padStart(2,'0')}-${String(Math.floor(Math.random()*10000)).padStart(5,'0')}`;
              
              const invoiceData = {
                invoiceNumber,
                date: new Date().toLocaleDateString('fr-FR'),
                clientName: r.societe || r.enseigne,
                clientAddress: r.adresse?.rue || '',
                clientPostalCode: r.adresse?.codePostal || '',
                clientCity: r.adresse?.ville || '',
                clientSiret: r.siret === 'EN_COURS' ? 'En cours' : r.siret,
                clientEmail: r.email,
                planName: plan?.name || r.subscription?.plan,
                priceHT,
                tva,
                priceTTC: priceTTC.toFixed(2),
                cardLast4: r.subscription?.cardLast4 || '****',
                restaurantId: r.siret || r.id
              };
              
              const invoicePDF = await generateInvoicePDF(invoiceData);
              
              await db.collection('invoices').insertOne({
                ...invoiceData,
                pdfBase64: invoicePDF.toString('base64'),
                stripeInvoiceId: invoice.id,
                createdAt: new Date()
              });
              
              // Envoyer la facture par email
              const emailHtml = `
                <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
                  <div style="background:#6bb44a;padding:20px;text-align:center;border-radius:10px 10px 0 0;">
                    <h1 style="color:white;margin:0;">📄 Facture ${invoiceNumber}</h1>
                  </div>
                  <div style="background:#f9f9f9;padding:30px;border-radius:0 0 10px 10px;">
                    <p>Bonjour,</p>
                    <p>Votre prélèvement mensuel a été effectué avec succès.</p>
                    <div style="background:#fff;border:1px solid #ddd;border-radius:8px;padding:15px;margin:20px 0;">
                      <p style="margin:5px 0;"><strong>Montant :</strong> ${priceTTC.toFixed(2)}€ TTC</p>
                      <p style="margin:5px 0;"><strong>Formule :</strong> ${plan?.name}</p>
                      <p style="margin:5px 0;"><strong>Carte :</strong> **** ${r.subscription?.cardLast4}</p>
                    </div>
                    <p>Votre facture est disponible dans votre espace client.</p>
                    <p>L'équipe UCO AND CO</p>
                  </div>
                </div>
              `;
              
              await fetch(`http://localhost:${PORT}/api/send-email`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  to: r.email,
                  subject: `📄 Facture ${invoiceNumber} - UCO AND CO`,
                  htmlContent: emailHtml
                })
              });
              
              // Attacher à Qonto
              attachInvoiceToQonto(invoicePDF, invoiceData).catch(err => 
                console.error('Erreur Qonto:', err)
              );
              
              console.log(`📄 Facture ${invoiceNumber} générée`);
            } catch (invoiceError) {
              console.error('Erreur génération facture:', invoiceError);
            }
          }
        }
        break;
      }
      
      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        
        if (invoice.subscription) {
          const restaurant = await db.collection(COLLECTIONS.RESTAURANTS).findOne({
            'subscription.stripeSubscriptionId': invoice.subscription
          });
          
          if (restaurant) {
            const now = new Date();
            const failedAttempts = (restaurant.subscription?.failedAttempts || 0) + 1;
            const firstFailedAt = restaurant.subscription?.firstFailedAt || now.toISOString();
            const daysSinceFirstFail = Math.floor((now - new Date(firstFailedAt)) / (1000 * 60 * 60 * 24));
            
            console.log(`⚠️ Échec paiement: ${restaurant.enseigne} - Tentative ${failedAttempts}, jour ${daysSinceFirstFail}`);
            
            // Après 30 jours, bloquer le compte
            if (daysSinceFirstFail >= 30) {
              await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
                { _id: restaurant._id },
                { 
                  $set: { 
                    'subscription.status': 'blocked',
                    'subscription.blockedAt': now.toISOString(),
                    'subscription.blockedReason': 'Prélèvements refusés pendant plus de 30 jours',
                    'subscription.failedAttempts': failedAttempts
                  } 
                }
              );
              
              // Annuler l'abonnement Stripe
              const stripe = require('stripe')(settings.stripeSecretKey);
              await stripe.subscriptions.cancel(invoice.subscription);
              
              // Notification de blocage
              const emailHtml = `
                <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
                  <div style="background:#dc2626;padding:20px;text-align:center;border-radius:10px 10px 0 0;">
                    <h1 style="color:white;margin:0;">⚠️ Compte bloqué</h1>
                  </div>
                  <div style="background:#f9f9f9;padding:30px;border-radius:0 0 10px 10px;">
                    <p>Bonjour,</p>
                    <p>Malgré nos relances, nous n'avons pas pu prélever votre abonnement depuis plus de 30 jours.</p>
                    <p>Votre compte est désormais <strong>bloqué</strong>.</p>
                    <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:15px;margin:20px 0;">
                      <p style="margin:0;"><strong>Pour retrouver l'accès :</strong></p>
                      <p style="margin:10px 0 0 0;">Connectez-vous sur <a href="https://uco-and-co.fr">uco-and-co.fr</a> et régularisez votre situation.</p>
                    </div>
                    <p>Contact : 06 10 25 10 63 | contact@uco-and-co.com</p>
                  </div>
                </div>
              `;
              
              await fetch(`http://localhost:${PORT}/api/send-email`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  to: restaurant.email,
                  subject: '⚠️ Votre compte UCO AND CO est bloqué',
                  htmlContent: emailHtml
                })
              });
              
              if (restaurant.tel) {
                await fetch(`http://localhost:${PORT}/api/send-sms`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    to: restaurant.tel,
                    message: `UCO AND CO: Compte bloque. Regularisez sur uco-and-co.fr. Contact: 0610251063`
                  })
                });
              }
              
              console.log(`🚫 Compte bloqué: ${restaurant.enseigne}`);
            } else {
              // Mettre à jour le statut d'échec
              await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
                { _id: restaurant._id },
                { 
                  $set: { 
                    'subscription.status': 'payment_failed',
                    'subscription.failedAttempts': failedAttempts,
                    'subscription.firstFailedAt': firstFailedAt,
                    'subscription.lastFailedAt': now.toISOString()
                  } 
                }
              );
              
              // Notification d'échec
              const daysRemaining = 30 - daysSinceFirstFail;
              const emailHtml = `
                <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
                  <div style="background:#f59e0b;padding:20px;text-align:center;border-radius:10px 10px 0 0;">
                    <h1 style="color:white;margin:0;">⚠️ Échec de prélèvement</h1>
                  </div>
                  <div style="background:#f9f9f9;padding:30px;border-radius:0 0 10px 10px;">
                    <p>Bonjour,</p>
                    <p>Nous n'avons pas pu prélever votre abonnement <strong>${restaurant.subscription?.plan}</strong>.</p>
                    <div style="background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;padding:15px;margin:20px 0;">
                      <p style="margin:0;"><strong>Tentative ${failedAttempts}</strong></p>
                      <p style="margin:10px 0 0 0;color:#92400e;">⚠️ Votre compte sera bloqué dans ${daysRemaining} jours sans régularisation.</p>
                    </div>
                    <p>Veuillez mettre à jour votre carte de paiement dans votre espace client.</p>
                    <p>Contact : 06 10 25 10 63</p>
                  </div>
                </div>
              `;
              
              await fetch(`http://localhost:${PORT}/api/send-email`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  to: restaurant.email,
                  subject: `⚠️ Échec de prélèvement - ${daysRemaining} jours restants`,
                  htmlContent: emailHtml
                })
              });
              
              if (restaurant.tel) {
                await fetch(`http://localhost:${PORT}/api/send-sms`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    to: restaurant.tel,
                    message: `UCO AND CO: Echec prelevement. Regularisez sous ${daysRemaining} jours. Espace client: uco-and-co.fr`
                  })
                });
              }
            }
          }
        }
        break;
      }
      
      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        
        await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
          { 'subscription.stripeSubscriptionId': subscription.id },
          { 
            $set: { 
              'subscription.status': 'cancelled', 
              'subscription.endDate': new Date().toISOString(),
              'subscription.plan': 'starter' // Repasse en gratuit
            } 
          }
        );
        console.log(`❌ Abonnement Stripe annulé: ${subscription.id}`);
        break;
      }
      
      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        
        // Mettre à jour le plan si changé
        if (subscription.metadata?.plan) {
          await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
            { 'subscription.stripeSubscriptionId': subscription.id },
            { $set: { 'subscription.plan': subscription.metadata.plan } }
          );
        }
        break;
      }
    }
    
    res.json({ received: true });
    
  } catch (error) {
    console.error('Erreur webhook Stripe:', error);
    res.status(500).json({ error: error.message });
  }
});

// Annuler un abonnement Stripe
app.post('/api/stripe/cancel-subscription', async (req, res) => {
  try {
    const { subscriptionId } = req.body;
    
    const settings = await getSettings();
    if (!settings?.stripeSecretKey) {
      return res.status(400).json({ success: false, error: 'Stripe non configuré' });
    }
    
    const stripe = require('stripe')(settings.stripeSecretKey);
    
    // Annuler à la fin de la période en cours
    const subscription = await stripe.subscriptions.update(subscriptionId, {
      cancel_at_period_end: true
    });
    
    console.log('✅ Abonnement marqué pour annulation:', subscriptionId);
    res.json({ success: true, subscription });
    
  } catch (error) {
    console.error('Erreur annulation abonnement:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Récupérer le portail client Stripe
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

// ===== AVIS CLIENTS =====
app.get('/api/avis', async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const avis = await db.collection(COLLECTIONS.AVIS).find({}).sort({ dateCreation: -1 }).toArray();
    res.json(avis || []);
  } catch (error) {
    console.error('Erreur récupération avis:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.post('/api/avis', async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const avisData = sanitizeObject(req.body);
    
    if (!avisData.id) {
      avisData.id = 'avis_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }
    
    avisData.dateCreation = avisData.dateCreation || new Date().toISOString();
    
    await db.collection(COLLECTIONS.AVIS).insertOne({
      ...avisData,
      _id: avisData.id
    });
    
    console.log('Nouvel avis enregistré:', avisData.id);
    res.status(201).json({ success: true, id: avisData.id });
  } catch (error) {
    console.error('Erreur création avis:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

app.delete('/api/avis/:id', authenticateToken, async (req, res) => {
  try {
    if (!db) {
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

// Marquer un avis comme lu
app.post('/api/avis/:id/read', async (req, res) => {
  try {
    if (!db) {
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

// Marquer tous les avis comme lus
app.post('/api/avis/mark-all-read', async (req, res) => {
  try {
    if (!db) {
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

// =============================================
// INTÉGRATION QONTO - FACTURES AUTOMATIQUES
// =============================================

// Fonction pour générer une facture PDF
async function generateInvoicePDF(invoiceData) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 50, size: 'A4' });
      const chunks = [];
      
      doc.on('data', chunk => chunks.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);
      
      // Couleurs UCO AND CO
      const vertPrincipal = '#6bb44a';
      const vertFonce = '#2d5016';
      
      // En-tête
      doc.fillColor(vertPrincipal)
         .rect(0, 0, doc.page.width, 100)
         .fill();
      
      doc.fillColor('white')
         .fontSize(28)
         .font('Helvetica-Bold')
         .text('FACTURE', 50, 35);
      
      doc.fontSize(12)
         .font('Helvetica')
         .text(invoiceData.invoiceNumber, 50, 65);
      
      // Informations UCO AND CO
      doc.fillColor('black')
         .fontSize(10)
         .font('Helvetica-Bold')
         .text('UCO AND CO', 50, 120);
      
      doc.font('Helvetica')
         .text('119 Route de la Varenne', 50, 135)
         .text('28270 Rueil La Gadelière', 50, 148)
         .text('SIRET: 953 315 041 00012', 50, 161)
         .text('TVA: FR 953 315 041', 50, 174);
      
      // Informations facture (droite)
      doc.font('Helvetica-Bold')
         .text('Date:', 400, 120);
      doc.font('Helvetica')
         .text(invoiceData.date, 450, 120);
      
      doc.font('Helvetica-Bold')
         .text('N° Facture:', 400, 135);
      doc.font('Helvetica')
         .text(invoiceData.invoiceNumber, 450, 135);
      
      // Client
      doc.fillColor(vertPrincipal)
         .rect(50, 210, 250, 20)
         .fill();
      
      doc.fillColor('white')
         .font('Helvetica-Bold')
         .fontSize(10)
         .text('FACTURÉ À', 55, 215);
      
      doc.fillColor('black')
         .font('Helvetica-Bold')
         .text(invoiceData.clientName, 50, 240);
      
      doc.font('Helvetica')
         .text(invoiceData.clientAddress, 50, 255)
         .text(`${invoiceData.clientPostalCode} ${invoiceData.clientCity}`, 50, 268)
         .text(`SIRET: ${invoiceData.clientSiret}`, 50, 281)
         .text(`Email: ${invoiceData.clientEmail}`, 50, 294);
      
      // Tableau des articles
      const tableTop = 340;
      
      // En-tête du tableau
      doc.fillColor(vertPrincipal)
         .rect(50, tableTop, 495, 25)
         .fill();
      
      doc.fillColor('white')
         .font('Helvetica-Bold')
         .fontSize(10)
         .text('Description', 55, tableTop + 8)
         .text('Prix HT', 380, tableTop + 8)
         .text('TVA', 430, tableTop + 8)
         .text('Total TTC', 480, tableTop + 8);
      
      // Ligne de l'article
      const itemY = tableTop + 35;
      doc.fillColor('black')
         .font('Helvetica')
         .text(`Abonnement mensuel ${invoiceData.planName}`, 55, itemY)
         .text(`${invoiceData.priceHT}€`, 380, itemY)
         .text(`${invoiceData.tva}€`, 430, itemY)
         .text(`${invoiceData.priceTTC}€`, 480, itemY);
      
      // Ligne de séparation
      doc.moveTo(50, itemY + 20).lineTo(545, itemY + 20).stroke('#ddd');
      
      // Totaux
      const totalsY = itemY + 40;
      doc.font('Helvetica')
         .text('Sous-total HT:', 350, totalsY)
         .text(`${invoiceData.priceHT}€`, 480, totalsY);
      
      doc.text('TVA (20%):', 350, totalsY + 18)
         .text(`${invoiceData.tva}€`, 480, totalsY + 18);
      
      doc.fillColor(vertPrincipal)
         .rect(340, totalsY + 38, 205, 25)
         .fill();
      
      doc.fillColor('white')
         .font('Helvetica-Bold')
         .text('TOTAL TTC:', 350, totalsY + 45)
         .text(`${invoiceData.priceTTC}€`, 480, totalsY + 45);
      
      // Informations de paiement
      doc.fillColor('black')
         .font('Helvetica')
         .fontSize(9)
         .text(`Paiement par carte bancaire **** **** **** ${invoiceData.cardLast4}`, 50, totalsY + 90);
      
      doc.text(`Date de paiement: ${invoiceData.date}`, 50, totalsY + 105);
      
      // Pied de page
      const footerY = 720;
      doc.fillColor('#666')
         .fontSize(8)
         .text('UCO AND CO - Collecte et valorisation des huiles alimentaires usagées', 50, footerY, { align: 'center', width: 495 })
         .text('Tél: 06 10 25 10 63 | Email: contact@uco-and-co.com | www.uco-and-co.fr', 50, footerY + 12, { align: 'center', width: 495 });
      
      doc.end();
    } catch (error) {
      reject(error);
    }
  });
}

// Fonction pour envoyer une facture à Qonto
async function attachInvoiceToQonto(invoicePDF, invoiceData) {
  try {
    const settings = await getSettings();
    
    if (!settings?.qontoOrganizationId || !settings?.qontoSecretKey) {
      console.log('⚠️ Qonto non configuré - facture non attachée');
      return { success: false, error: 'Qonto non configuré' };
    }
    
    const qontoAuth = `${settings.qontoOrganizationId}:${settings.qontoSecretKey}`;
    
    // 1. Récupérer les transactions récentes pour trouver celle correspondante
    const transactionsResponse = await fetch(
      `https://thirdparty.qonto.com/v2/transactions?status=completed&side=credit`,
      {
        headers: {
          'Authorization': qontoAuth,
          'Content-Type': 'application/json'
        }
      }
    );
    
    if (!transactionsResponse.ok) {
      console.error('Erreur récupération transactions Qonto:', await transactionsResponse.text());
      return { success: false, error: 'Erreur API Qonto' };
    }
    
    const transactionsData = await transactionsResponse.json();
    
    // Chercher la transaction correspondante (montant et date proche)
    const targetAmount = parseFloat(invoiceData.priceTTC);
    const invoiceDate = new Date(invoiceData.date);
    
    const matchingTransaction = transactionsData.transactions?.find(t => {
      const txAmount = Math.abs(t.amount);
      const txDate = new Date(t.settled_at || t.emitted_at);
      const timeDiff = Math.abs(txDate - invoiceDate);
      const daysDiff = timeDiff / (1000 * 60 * 60 * 24);
      
      // Match si montant identique et moins de 2 jours d'écart
      return Math.abs(txAmount - targetAmount) < 0.01 && daysDiff < 2;
    });
    
    if (!matchingTransaction) {
      console.log('⚠️ Transaction Qonto correspondante non trouvée');
      // Stocker la facture pour retry plus tard
      await db.collection('pending_qonto_invoices').insertOne({
        invoiceData,
        invoicePDF: invoicePDF.toString('base64'),
        createdAt: new Date(),
        status: 'pending'
      });
      return { success: false, error: 'Transaction non trouvée - mise en attente' };
    }
    
    // 2. Uploader la facture comme pièce jointe
    const FormData = require('form-data');
    const formData = new FormData();
    formData.append('file', invoicePDF, {
      filename: `${invoiceData.invoiceNumber}.pdf`,
      contentType: 'application/pdf'
    });
    
    const attachmentResponse = await fetch(
      `https://thirdparty.qonto.com/v2/transactions/${matchingTransaction.id}/attachments`,
      {
        method: 'POST',
        headers: {
          'Authorization': qontoAuth,
          ...formData.getHeaders()
        },
        body: formData
      }
    );
    
    if (!attachmentResponse.ok) {
      console.error('Erreur upload facture Qonto:', await attachmentResponse.text());
      return { success: false, error: 'Erreur upload facture' };
    }
    
    console.log(`✅ Facture ${invoiceData.invoiceNumber} attachée à la transaction Qonto ${matchingTransaction.id}`);
    
    // Enregistrer dans la base
    await db.collection('qonto_invoices').insertOne({
      invoiceNumber: invoiceData.invoiceNumber,
      transactionId: matchingTransaction.id,
      restaurantId: invoiceData.restaurantId,
      amount: invoiceData.priceTTC,
      attachedAt: new Date()
    });
    
    return { success: true, transactionId: matchingTransaction.id };
    
  } catch (error) {
    console.error('Erreur intégration Qonto:', error);
    return { success: false, error: error.message };
  }
}

// Endpoint pour configurer Qonto (sans auth car vérifié par Qonto directement)
app.post('/api/qonto/configure', async (req, res) => {
  try {
    const { organizationId, secretKey } = req.body;
    
    if (!organizationId || !secretKey) {
      return res.status(400).json({ success: false, error: 'Organization ID et Secret Key requis' });
    }
    
    // Tester la connexion
    const qontoAuth = `${organizationId}:${secretKey}`;
    const testResponse = await fetch('https://thirdparty.qonto.com/v2/organization', {
      headers: {
        'Authorization': qontoAuth,
        'Content-Type': 'application/json'
      }
    });
    
    if (!testResponse.ok) {
      return res.status(400).json({ success: false, error: 'Identifiants Qonto invalides' });
    }
    
    const orgData = await testResponse.json();
    
    // Sauvegarder les identifiants
    await db.collection('settings').updateOne(
      {},
      { 
        $set: { 
          qontoOrganizationId: organizationId, 
          qontoSecretKey: secretKey,
          qontoOrganizationName: orgData.organization?.name 
        } 
      },
      { upsert: true }
    );
    
    console.log('✅ Qonto configuré pour:', orgData.organization?.name);
    res.json({ success: true, organizationName: orgData.organization?.name });
    
  } catch (error) {
    console.error('Erreur configuration Qonto:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Endpoint pour générer et attacher une facture manuellement
app.post('/api/invoices/generate', authenticateToken, async (req, res) => {
  try {
    const { restaurantId, planId, amount, cardLast4 } = req.body;
    
    // Récupérer le restaurant
    const restaurant = await db.collection(COLLECTIONS.RESTAURANTS).findOne({
      $or: [{ id: restaurantId }, { siret: restaurantId }]
    });
    
    if (!restaurant) {
      return res.status(404).json({ success: false, error: 'Restaurant non trouvé' });
    }
    
    const PLANS = {
      starter: { name: 'Starter', price: 0 },
      simple: { name: 'Simple', price: 14.99 },
      premium: { name: 'Premium', price: 19.99 }
    };
    
    const plan = PLANS[planId];
    const priceTTC = amount || plan?.price || 0;
    const priceHT = (priceTTC / 1.20).toFixed(2);
    const tva = (priceTTC - parseFloat(priceHT)).toFixed(2);
    
    const invoiceNumber = `FAC-${new Date().getFullYear()}${String(new Date().getMonth()+1).padStart(2,'0')}-${String(Math.floor(Math.random()*10000)).padStart(5,'0')}`;
    
    const invoiceData = {
      invoiceNumber,
      date: new Date().toLocaleDateString('fr-FR'),
      clientName: restaurant.societe || restaurant.enseigne,
      clientAddress: restaurant.adresse?.rue || '',
      clientPostalCode: restaurant.adresse?.codePostal || '',
      clientCity: restaurant.adresse?.ville || '',
      clientSiret: restaurant.siret === 'EN_COURS' ? 'En cours' : restaurant.siret,
      clientEmail: restaurant.email,
      planName: plan?.name || planId,
      priceHT,
      tva,
      priceTTC: priceTTC.toFixed(2),
      cardLast4: cardLast4 || '****',
      restaurantId
    };
    
    // Générer le PDF
    const invoicePDF = await generateInvoicePDF(invoiceData);
    
    // Attacher à Qonto
    const qontoResult = await attachInvoiceToQonto(invoicePDF, invoiceData);
    
    // Sauvegarder la facture dans la base
    await db.collection('invoices').insertOne({
      ...invoiceData,
      pdfBase64: invoicePDF.toString('base64'),
      qontoAttached: qontoResult.success,
      qontoTransactionId: qontoResult.transactionId,
      createdAt: new Date()
    });
    
    res.json({ 
      success: true, 
      invoiceNumber,
      qontoAttached: qontoResult.success,
      pdfBase64: invoicePDF.toString('base64')
    });
    
  } catch (error) {
    console.error('Erreur génération facture:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Endpoint pour récupérer les factures d'un restaurant
app.get('/api/invoices/:restaurantId', authenticateToken, async (req, res) => {
  try {
    const { restaurantId } = req.params;
    const invoices = await db.collection('invoices')
      .find({ restaurantId: sanitizeInput(restaurantId) })
      .sort({ createdAt: -1 })
      .toArray();
    
    res.json({ success: true, invoices });
  } catch (error) {
    console.error('Erreur récupération factures:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Job pour réessayer les factures en attente (appelé périodiquement)
app.post('/api/qonto/retry-pending', authenticateToken, async (req, res) => {
  try {
    const pendingInvoices = await db.collection('pending_qonto_invoices')
      .find({ status: 'pending' })
      .limit(10)
      .toArray();
    
    const results = [];
    
    for (const pending of pendingInvoices) {
      const invoicePDF = Buffer.from(pending.invoicePDF, 'base64');
      const result = await attachInvoiceToQonto(invoicePDF, pending.invoiceData);
      
      if (result.success) {
        await db.collection('pending_qonto_invoices').updateOne(
          { _id: pending._id },
          { $set: { status: 'attached', attachedAt: new Date() } }
        );
      }
      
      results.push({ invoiceNumber: pending.invoiceData.invoiceNumber, ...result });
    }
    
    res.json({ success: true, processed: results.length, results });
    
  } catch (error) {
    console.error('Erreur retry Qonto:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Statut de l'intégration Qonto
app.get('/api/qonto/status', async (req, res) => {
  try {
    const settings = await getSettings();
    
    if (!settings?.qontoOrganizationId) {
      return res.json({ 
        success: true, 
        configured: false 
      });
    }
    
    // Tester la connexion
    const qontoAuth = `${settings.qontoOrganizationId}:${settings.qontoSecretKey}`;
    const testResponse = await fetch('https://thirdparty.qonto.com/v2/organization', {
      headers: {
        'Authorization': qontoAuth,
        'Content-Type': 'application/json'
      }
    });
    
    const connected = testResponse.ok;
    
    // Stats
    const totalInvoices = await db.collection('invoices').countDocuments();
    const attachedInvoices = await db.collection('invoices').countDocuments({ qontoAttached: true });
    const pendingInvoices = await db.collection('pending_qonto_invoices').countDocuments({ status: 'pending' });
    
    res.json({ 
      success: true, 
      configured: true,
      connected,
      organizationName: settings.qontoOrganizationName,
      stats: {
        totalInvoices,
        attachedInvoices,
        pendingInvoices
      }
    });
    
  } catch (error) {
    console.error('Erreur statut Qonto:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Route 404 - DOIT ÊTRE EN DERNIER
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Route non trouvée' });
});

// =============================================
// GESTION DES ABONNEMENTS ET PRÉLÈVEMENTS
// =============================================

// Changement de formule (upgrade/downgrade)
app.post('/api/subscription/change', async (req, res) => {
  try {
    const { restaurantId, newPlan, cardInfo } = req.body;
    
    const restaurant = await db.collection(COLLECTIONS.RESTAURANTS).findOne({
      $or: [{ id: restaurantId }, { siret: restaurantId }]
    });
    
    if (!restaurant) {
      return res.status(404).json({ success: false, error: 'Restaurant non trouvé' });
    }
    
    const PLANS = {
      starter: { name: 'Starter', price: 0 },
      simple: { name: 'Simple', price: 14.99 },
      premium: { name: 'Premium', price: 19.99 }
    };
    
    const currentPlan = restaurant.subscription?.plan;
    const newPlanInfo = PLANS[newPlan];
    
    if (!newPlanInfo) {
      return res.status(400).json({ success: false, error: 'Formule invalide' });
    }
    
    // Si upgrade vers une formule payante, on doit avoir les infos de carte
    if (newPlanInfo.price > 0 && !restaurant.subscription?.cardToken && !cardInfo) {
      return res.status(400).json({ success: false, error: 'Informations de carte requises pour cette formule' });
    }
    
    // Calculer le prorata si changement en cours de mois
    const now = new Date();
    const lastPayment = restaurant.subscription?.lastPaymentDate ? new Date(restaurant.subscription.lastPaymentDate) : now;
    const daysInMonth = 30;
    const daysUsed = Math.floor((now - lastPayment) / (1000 * 60 * 60 * 24));
    const daysRemaining = Math.max(0, daysInMonth - daysUsed);
    
    let amountToPay = 0;
    let prorata = null;
    
    if (newPlanInfo.price > (PLANS[currentPlan]?.price || 0)) {
      // Upgrade : facturer la différence au prorata
      const priceDiff = newPlanInfo.price - (PLANS[currentPlan]?.price || 0);
      amountToPay = (priceDiff / daysInMonth) * daysRemaining;
      prorata = {
        type: 'upgrade',
        daysRemaining,
        priceDiff,
        amount: amountToPay.toFixed(2)
      };
    }
    // Downgrade : prend effet au prochain cycle, pas de remboursement
    
    // Mettre à jour l'abonnement
    const updateData = {
      'subscription.plan': newPlan,
      'subscription.previousPlan': currentPlan,
      'subscription.planChangedAt': now.toISOString(),
      'subscription.status': 'active'
    };
    
    // Stocker les infos de carte si fournies (pour prélèvements futurs)
    if (cardInfo) {
      updateData['subscription.cardLast4'] = cardInfo.last4;
      updateData['subscription.cardExpiry'] = cardInfo.expiry;
      updateData['subscription.cardToken'] = cardInfo.token; // Token sécurisé pour prélèvements
    }
    
    await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
      { $or: [{ id: restaurantId }, { siret: restaurantId }] },
      { $set: updateData }
    );
    
    console.log(`✅ Changement de formule: ${restaurant.enseigne} - ${currentPlan} → ${newPlan}`);
    
    res.json({ 
      success: true, 
      previousPlan: currentPlan,
      newPlan,
      prorata,
      message: prorata ? `Montant au prorata: ${prorata.amount}€` : 'Changement effectué'
    });
    
  } catch (error) {
    console.error('Erreur changement formule:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Endpoint pour enregistrer un échec de paiement et gérer les relances
app.post('/api/subscription/payment-failed', async (req, res) => {
  try {
    const { restaurantId, reason } = req.body;
    
    const restaurant = await db.collection(COLLECTIONS.RESTAURANTS).findOne({
      $or: [{ id: restaurantId }, { siret: restaurantId }]
    });
    
    if (!restaurant) {
      return res.status(404).json({ success: false, error: 'Restaurant non trouvé' });
    }
    
    const now = new Date();
    const failedAttempts = (restaurant.subscription?.failedAttempts || 0) + 1;
    const firstFailedAt = restaurant.subscription?.firstFailedAt || now.toISOString();
    const daysSinceFirstFail = Math.floor((now - new Date(firstFailedAt)) / (1000 * 60 * 60 * 24));
    
    // Après 30 jours d'échecs, bloquer le compte
    if (daysSinceFirstFail >= 30) {
      await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
        { $or: [{ id: restaurantId }, { siret: restaurantId }] },
        { 
          $set: { 
            'subscription.status': 'blocked',
            'subscription.blockedAt': now.toISOString(),
            'subscription.blockedReason': 'Prélèvements refusés pendant plus de 30 jours',
            'subscription.failedAttempts': failedAttempts
          } 
        }
      );
      
      // Envoyer notification de blocage
      const settings = await getSettings();
      
      // Email de blocage
      try {
        const emailHtml = `
          <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
            <div style="background:#dc2626;padding:20px;text-align:center;border-radius:10px 10px 0 0;">
              <h1 style="color:white;margin:0;">⚠️ Compte bloqué</h1>
            </div>
            <div style="background:#f9f9f9;padding:30px;border-radius:0 0 10px 10px;">
              <p>Bonjour,</p>
              <p>Malgré nos relances, nous n'avons pas pu prélever votre abonnement <strong>${restaurant.subscription?.plan}</strong> depuis plus de 30 jours.</p>
              <p>Votre compte est désormais <strong>bloqué</strong>.</p>
              <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:15px;margin:20px 0;">
                <p style="margin:0;"><strong>Pour retrouver l'accès à votre compte :</strong></p>
                <p style="margin:10px 0 0 0;">Connectez-vous sur <a href="https://uco-and-co.fr">uco-and-co.fr</a> et régularisez votre situation.</p>
              </div>
              <p>Pour toute question, contactez-nous :</p>
              <p>📞 06 10 25 10 63<br/>📧 contact@uco-and-co.com</p>
            </div>
          </div>
        `;
        
        await fetch(`http://localhost:${PORT}/api/send-email`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            to: restaurant.email,
            subject: '⚠️ Votre compte UCO AND CO est bloqué',
            htmlContent: emailHtml
          })
        });
      } catch (e) { console.error('Erreur email blocage:', e); }
      
      // SMS de blocage
      if (restaurant.tel) {
        try {
          await fetch(`http://localhost:${PORT}/api/send-sms`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              to: restaurant.tel,
              message: `UCO AND CO: Votre compte est bloque suite aux prelevements refuses. Regularisez sur uco-and-co.fr ou appelez le 0610251063`
            })
          });
        } catch (e) { console.error('Erreur SMS blocage:', e); }
      }
      
      console.log(`🚫 Compte bloqué: ${restaurant.enseigne} - ${failedAttempts} échecs sur ${daysSinceFirstFail} jours`);
      
      return res.json({ 
        success: true, 
        status: 'blocked',
        message: 'Compte bloqué après 30 jours d\'échecs'
      });
    }
    
    // Sinon, enregistrer l'échec et programmer la prochaine relance
    const nextRetryDate = new Date(now.getTime() + 2 * 24 * 60 * 60 * 1000); // +2 jours
    
    await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
      { $or: [{ id: restaurantId }, { siret: restaurantId }] },
      { 
        $set: { 
          'subscription.status': 'payment_failed',
          'subscription.failedAttempts': failedAttempts,
          'subscription.firstFailedAt': firstFailedAt,
          'subscription.lastFailedAt': now.toISOString(),
          'subscription.nextRetryAt': nextRetryDate.toISOString(),
          'subscription.lastFailReason': reason
        } 
      }
    );
    
    // Envoyer notification d'échec (seulement si c'est un nouvel échec ou tous les 2 jours)
    if (failedAttempts === 1 || failedAttempts % 1 === 0) { // À chaque tentative
      // Email d'échec
      try {
        const attemptsRemaining = Math.max(0, 15 - failedAttempts); // ~15 tentatives sur 30 jours
        const emailHtml = `
          <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
            <div style="background:#f59e0b;padding:20px;text-align:center;border-radius:10px 10px 0 0;">
              <h1 style="color:white;margin:0;">⚠️ Échec de prélèvement</h1>
            </div>
            <div style="background:#f9f9f9;padding:30px;border-radius:0 0 10px 10px;">
              <p>Bonjour,</p>
              <p>Nous n'avons pas pu prélever votre abonnement <strong>${restaurant.subscription?.plan}</strong> de <strong>${restaurant.subscription?.plan === 'simple' ? '14,99€' : '19,99€'}</strong>.</p>
              <div style="background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;padding:15px;margin:20px 0;">
                <p style="margin:0;"><strong>Tentative ${failedAttempts}/15</strong></p>
                <p style="margin:10px 0 0 0;">Prochaine tentative: ${nextRetryDate.toLocaleDateString('fr-FR')}</p>
                <p style="margin:10px 0 0 0;color:#92400e;">⚠️ Sans régularisation sous 30 jours, votre compte sera bloqué.</p>
              </div>
              <p>Veuillez vérifier votre moyen de paiement ou contactez-nous :</p>
              <p>📞 06 10 25 10 63<br/>📧 contact@uco-and-co.com</p>
            </div>
          </div>
        `;
        
        await fetch(`http://localhost:${PORT}/api/send-email`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            to: restaurant.email,
            subject: `⚠️ Échec de prélèvement - Tentative ${failedAttempts}/15`,
            htmlContent: emailHtml
          })
        });
      } catch (e) { console.error('Erreur email échec:', e); }
      
      // SMS d'échec
      if (restaurant.tel) {
        try {
          await fetch(`http://localhost:${PORT}/api/send-sms`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              to: restaurant.tel,
              message: `UCO AND CO: Echec prelevement (${failedAttempts}/15). Prochaine tentative le ${nextRetryDate.toLocaleDateString('fr-FR')}. Verifiez votre moyen de paiement.`
            })
          });
        } catch (e) { console.error('Erreur SMS échec:', e); }
      }
    }
    
    console.log(`⚠️ Échec paiement: ${restaurant.enseigne} - Tentative ${failedAttempts}, prochain essai le ${nextRetryDate.toLocaleDateString('fr-FR')}`);
    
    res.json({ 
      success: true, 
      status: 'payment_failed',
      failedAttempts,
      nextRetryAt: nextRetryDate.toISOString(),
      daysUntilBlock: 30 - daysSinceFirstFail
    });
    
  } catch (error) {
    console.error('Erreur enregistrement échec:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Endpoint pour régulariser un compte bloqué
app.post('/api/subscription/regularize', async (req, res) => {
  try {
    const { restaurantId, cardInfo, plan } = req.body;
    
    const restaurant = await db.collection(COLLECTIONS.RESTAURANTS).findOne({
      $or: [{ id: restaurantId }, { siret: restaurantId }]
    });
    
    if (!restaurant) {
      return res.status(404).json({ success: false, error: 'Restaurant non trouvé' });
    }
    
    if (restaurant.subscription?.status !== 'blocked') {
      return res.status(400).json({ success: false, error: 'Le compte n\'est pas bloqué' });
    }
    
    // Réactiver le compte avec la nouvelle carte
    const now = new Date();
    
    await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
      { $or: [{ id: restaurantId }, { siret: restaurantId }] },
      { 
        $set: { 
          'subscription.status': 'active',
          'subscription.plan': plan || restaurant.subscription.plan,
          'subscription.reactivatedAt': now.toISOString(),
          'subscription.lastPaymentDate': now.toISOString(),
          'subscription.cardLast4': cardInfo.last4,
          'subscription.cardExpiry': cardInfo.expiry,
          'subscription.cardToken': cardInfo.token
        },
        $unset: {
          'subscription.blockedAt': '',
          'subscription.blockedReason': '',
          'subscription.failedAttempts': '',
          'subscription.firstFailedAt': '',
          'subscription.lastFailedAt': '',
          'subscription.nextRetryAt': '',
          'subscription.lastFailReason': ''
        }
      }
    );
    
    console.log(`✅ Compte réactivé: ${restaurant.enseigne}`);
    
    // Email de confirmation
    try {
      const emailHtml = `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
          <div style="background:#6bb44a;padding:20px;text-align:center;border-radius:10px 10px 0 0;">
            <h1 style="color:white;margin:0;">✅ Compte réactivé !</h1>
          </div>
          <div style="background:#f9f9f9;padding:30px;border-radius:0 0 10px 10px;">
            <p>Bonjour,</p>
            <p>Votre compte UCO AND CO a été réactivé avec succès !</p>
            <p>Vous avez de nouveau accès à tous les services de votre formule <strong>${plan || restaurant.subscription.plan}</strong>.</p>
            <p>Merci de votre confiance.</p>
            <p>L'équipe UCO AND CO</p>
          </div>
        </div>
      `;
      
      await fetch(`http://localhost:${PORT}/api/send-email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          to: restaurant.email,
          subject: '✅ Votre compte UCO AND CO est réactivé !',
          htmlContent: emailHtml
        })
      });
    } catch (e) { console.error('Erreur email réactivation:', e); }
    
    res.json({ 
      success: true, 
      message: 'Compte réactivé avec succès'
    });
    
  } catch (error) {
    console.error('Erreur régularisation:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Vérifier le statut d'un compte (pour la connexion)
app.get('/api/subscription/status/:restaurantId', async (req, res) => {
  try {
    const { restaurantId } = req.params;
    
    const restaurant = await db.collection(COLLECTIONS.RESTAURANTS).findOne({
      $or: [{ id: restaurantId }, { siret: restaurantId }]
    });
    
    if (!restaurant) {
      return res.status(404).json({ success: false, error: 'Restaurant non trouvé' });
    }
    
    const subscription = restaurant.subscription || {};
    
    res.json({
      success: true,
      status: subscription.status || 'none',
      plan: subscription.plan,
      isBlocked: subscription.status === 'blocked',
      blockedReason: subscription.blockedReason,
      blockedAt: subscription.blockedAt,
      failedAttempts: subscription.failedAttempts,
      nextRetryAt: subscription.nextRetryAt
    });
    
  } catch (error) {
    console.error('Erreur statut subscription:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Job pour traiter les prélèvements automatiques (à appeler via cron externe)
app.post('/api/subscription/process-payments', async (req, res) => {
  try {
    const { apiKey } = req.body;
    
    // Vérifier la clé API (sécurité basique pour le cron)
    const settings = await getSettings();
    if (apiKey !== settings?.cronApiKey && apiKey !== 'UCO_CRON_2024') {
      return res.status(401).json({ success: false, error: 'Non autorisé' });
    }
    
    const now = new Date();
    const results = {
      processed: 0,
      success: 0,
      failed: 0,
      retried: 0,
      details: []
    };
    
    // 1. Trouver les abonnements à prélever (dernier paiement > 30 jours)
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    
    const restaurantsToCharge = await db.collection(COLLECTIONS.RESTAURANTS).find({
      'subscription.status': 'active',
      'subscription.plan': { $in: ['simple', 'premium'] },
      'subscription.lastPaymentDate': { $lt: thirtyDaysAgo.toISOString() }
    }).toArray();
    
    for (const restaurant of restaurantsToCharge) {
      results.processed++;
      
      // Ici, intégrer avec Stripe pour le prélèvement réel
      // Pour l'instant, simuler le résultat
      const paymentSuccess = Math.random() > 0.1; // 90% de succès en simulation
      
      if (paymentSuccess) {
        await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
          { _id: restaurant._id },
          { 
            $set: { 
              'subscription.lastPaymentDate': now.toISOString()
            },
            $unset: {
              'subscription.failedAttempts': '',
              'subscription.firstFailedAt': '',
              'subscription.lastFailedAt': ''
            }
          }
        );
        results.success++;
        results.details.push({ restaurant: restaurant.enseigne, status: 'success' });
      } else {
        // Enregistrer l'échec via l'endpoint dédié
        await fetch(`http://localhost:${PORT}/api/subscription/payment-failed`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            restaurantId: restaurant.siret || restaurant.id,
            reason: 'Prélèvement automatique refusé'
          })
        });
        results.failed++;
        results.details.push({ restaurant: restaurant.enseigne, status: 'failed' });
      }
    }
    
    // 2. Réessayer les paiements échoués dont la date de retry est passée
    const failedToRetry = await db.collection(COLLECTIONS.RESTAURANTS).find({
      'subscription.status': 'payment_failed',
      'subscription.nextRetryAt': { $lte: now.toISOString() }
    }).toArray();
    
    for (const restaurant of failedToRetry) {
      results.retried++;
      
      // Réessayer le prélèvement
      const retrySuccess = Math.random() > 0.3; // 70% de succès en retry
      
      if (retrySuccess) {
        await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
          { _id: restaurant._id },
          { 
            $set: { 
              'subscription.status': 'active',
              'subscription.lastPaymentDate': now.toISOString()
            },
            $unset: {
              'subscription.failedAttempts': '',
              'subscription.firstFailedAt': '',
              'subscription.lastFailedAt': '',
              'subscription.nextRetryAt': ''
            }
          }
        );
        results.success++;
        results.details.push({ restaurant: restaurant.enseigne, status: 'retry_success' });
        
        // Notification de succès
        console.log(`✅ Prélèvement réussi après retry: ${restaurant.enseigne}`);
      } else {
        // Enregistrer le nouvel échec
        await fetch(`http://localhost:${PORT}/api/subscription/payment-failed`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            restaurantId: restaurant.siret || restaurant.id,
            reason: 'Retry prélèvement refusé'
          })
        });
        results.details.push({ restaurant: restaurant.enseigne, status: 'retry_failed' });
      }
    }
    
    console.log(`💳 Traitement prélèvements: ${results.processed} traités, ${results.success} réussis, ${results.failed} échoués, ${results.retried} retentés`);
    
    res.json({ success: true, results });
    
  } catch (error) {
    console.error('Erreur traitement prélèvements:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// =============================================
// DÉMARRAGE DU SERVEUR
// =============================================
async function startServer() {
  await connectDB();
  
  app.listen(PORT, () => {
    console.log('');
    console.log('🛢️  ========================================');
    console.log('🛢️  UCO AND CO - Backend API (SÉCURISÉ)');
    console.log('🛢️  ========================================');
    console.log(`🚀 Serveur démarré sur le port ${PORT}`);
    console.log(`📊 Base de données: ${db ? 'MongoDB Atlas ✅' : 'Mode mémoire ⚠️'}`);
    console.log('🔒 Sécurité activée:');
    console.log('   ✅ Helmet (Headers sécurisés)');
    console.log('   ✅ CORS restreint');
    console.log('   ✅ Rate limiting');
    console.log('   ✅ Sanitization NoSQL/XSS');
    console.log('   ✅ JWT Authentication');
    console.log('   ✅ Bcrypt (12 rounds)');
    console.log('   ✅ Verrouillage de compte');
    console.log('   ✅ Audit logs');
    console.log('');
  });
}

startServer();
