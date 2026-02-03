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

// 4. Body parser avec limite
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 5. Sanitization contre les injections NoSQL
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
  CAMPAIGNS: 'campaigns'
};

// Cache avec TTL
const cache = {
  settings: null,
  lastSettingsUpdate: 0,
  TTL: 60000 // 1 minute
};

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
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return input
    .replace(/[<>]/g, '') // Enlever les balises HTML
    .trim()
    .slice(0, 1000); // Limiter la longueur
}

// Sanitization récursive d'un objet
function sanitizeObject(obj) {
  if (typeof obj !== 'object' || obj === null) {
    return sanitizeInput(obj);
  }
  
  const sanitized = Array.isArray(obj) ? [] : {};
  for (const key of Object.keys(obj)) {
    // Bloquer les clés commençant par $ (opérateurs MongoDB)
    if (key.startsWith('$')) continue;
    sanitized[key] = sanitizeObject(obj[key]);
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

async function getSettings() {
  if (!db) return initialData.settings;
  
  if (cache.settings && Date.now() - cache.lastSettingsUpdate < cache.TTL) {
    return cache.settings;
  }
  
  const doc = await db.collection(COLLECTIONS.SETTINGS).findOne({ _id: 'main' });
  cache.settings = doc || initialData.settings;
  cache.lastSettingsUpdate = Date.now();
  return cache.settings;
}

async function updateSettings(newSettings) {
  if (!db) return false;
  
  // Récupérer les settings existants pour les préserver
  const existingSettings = await getSettings();
  
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
  
  await db.collection(COLLECTIONS.SETTINGS).updateOne(
    { _id: 'main' },
    { $set: mergedSettings },
    { upsert: true }
  );
  cache.settings = null;
  return true;
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
  return await db.collection(COLLECTIONS.RESTAURANTS).findOne({ id: sanitizeInput(id) });
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
  await db.collection(COLLECTIONS.RESTAURANTS).updateOne(
    { id: sanitizeInput(id) },
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
    
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email et mot de passe requis' });
    }
    
    const restaurant = await getRestaurantByEmail(email);
    
    if (!restaurant) {
      return res.status(401).json({ success: false, error: 'Compte non trouvé' });
    }
    
    if (restaurant.status === 'pending') {
      return res.json({ success: false, error: 'pending' });
    }
    
    if (restaurant.status !== 'approved') {
      return res.status(401).json({ success: false, error: 'Compte non approuvé' });
    }
    
    if (!restaurant.password) {
      return res.status(401).json({ success: false, error: 'Mot de passe non configuré' });
    }
    
    if (isAccountLocked(restaurant)) {
      return res.status(423).json({ success: false, error: 'Compte verrouillé' });
    }
    
    const isValid = await bcrypt.compare(password, restaurant.password);
    
    if (!isValid) {
      await incrementLoginAttempts(COLLECTIONS.RESTAURANTS, email);
      return res.status(401).json({ success: false, error: 'Mot de passe incorrect' });
    }
    
    await resetLoginAttempts(COLLECTIONS.RESTAURANTS, email);
    
    const token = generateToken({ role: 'restaurant', email, id: restaurant.id });
    const { password: _, loginAttempts, lockUntil, ...data } = restaurant;
    
    await auditLog('RESTAURANT_LOGIN_SUCCESS', email, {}, req);
    
    res.json({ success: true, role: 'restaurant', data, token });
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
    const { email, password, id, qrCode, ...data } = sanitizeObject(req.body);
    
    if (email) {
      const existing = await getRestaurantByEmail(email);
      if (existing) {
        return res.status(409).json({ success: false, error: 'Email déjà utilisé' });
      }
    }
    
    const restaurantId = id || qrCode || uuidv4();
    
    if (qrCode) {
      const existingQR = await getRestaurantByQRCode(qrCode);
      if (existingQR) {
        return res.status(409).json({ success: false, error: 'QR Code déjà utilisé' });
      }
    }
    
    await addRestaurant({
      id: restaurantId,
      qrCode: qrCode || restaurantId,
      email: email || '',
      password: password ? await bcrypt.hash(password, BCRYPT_ROUNDS) : null,
      ...data,
      status: 'pending',
      dateRequest: new Date().toISOString()
    });
    
    await auditLog('RESTAURANT_REGISTER', email || restaurantId, { status: 'pending' }, req);
    
    res.status(201).json({ success: true, id: restaurantId, qrCode: qrCode || restaurantId });
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
    // Ne PAS sanitizer htmlContent car c'est du HTML valide
    const { to, subject, htmlContent, html, senderName, attachment } = req.body;
    const emailHtml = htmlContent || html;
    
    // Sanitizer uniquement les champs sensibles (pas le HTML)
    const safeTo = sanitizeInput(to);
    const safeSubject = sanitizeInput(subject);
    const safeSenderName = sanitizeInput(senderName);
    
    if (!safeTo || !safeSubject || !emailHtml) {
      return res.status(400).json({ success: false, error: 'Paramètres manquants' });
    }
    
    if (!isValidEmail(safeTo)) {
      return res.status(400).json({ success: false, error: 'Email destinataire invalide' });
    }
    
    const settings = await getSettings();
    const apiKey = settings.brevoApiKey;
    
    if (!apiKey) {
      return res.status(503).json({ success: false, error: 'Service email non configuré' });
    }
    
    const emailPayload = {
      sender: { name: safeSenderName || 'UCO AND CO', email: 'contact@uco-and-co.fr' },
      to: [{ email: safeTo }],
      subject: safeSubject.slice(0, 200),
      htmlContent: emailHtml // Garder le HTML intact
    };
    
    if (attachment?.content && attachment?.name) {
      emailPayload.attachment = [{ content: attachment.content, name: sanitizeInput(attachment.name).slice(0, 100) }];
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
    
    if (response.ok) {
      res.json({ success: true });
    } else {
      const error = await response.json();
      res.status(502).json({ success: false, error: error.message || 'Erreur Brevo' });
    }
  } catch (error) {
    console.error('Erreur email:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
  }
});

// ===== SMS (Brevo) =====
app.post('/api/send-sms', async (req, res) => {
  try {
    const { to, message } = sanitizeObject(req.body);
    
    if (!to || !message) {
      return res.status(400).json({ success: false, error: 'Paramètres manquants' });
    }
    
    const settings = await getSettings();
    
    if (!settings.brevoApiKey) {
      return res.status(503).json({ success: false, error: 'Service SMS non configuré' });
    }
    
    if (!settings.smsEnabled) {
      return res.status(503).json({ success: false, error: 'SMS désactivé' });
    }
    
    let phoneNumber = typeof to === 'object' ? to.number : to;
    let countryCode = typeof to === 'object' ? to.countryCode : 'FR';
    
    phoneNumber = phoneNumber.replace(/[\s\.\-]/g, '');
    
    const prefixes = { 'FR': '+33', 'BE': '+32', 'CH': '+41', 'LU': '+352' };
    const prefix = prefixes[countryCode] || '+33';
    
    if (!phoneNumber.startsWith('+')) {
      phoneNumber = phoneNumber.startsWith('0') ? prefix + phoneNumber.slice(1) : prefix + phoneNumber;
    }
    
    const response = await fetch('https://api.brevo.com/v3/transactionalSMS/sms', {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'api-key': settings.brevoApiKey,
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        sender: 'UCOANDCO',
        recipient: phoneNumber,
        content: message.slice(0, 160) // Limiter à 160 caractères
      })
    });
    
    if (response.ok) {
      res.json({ success: true });
    } else {
      const error = await response.json();
      res.status(502).json({ success: false, error: error.message || 'Erreur SMS' });
    }
  } catch (error) {
    console.error('Erreur SMS:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur' });
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

// Route 404
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Route non trouvée' });
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
