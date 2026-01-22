const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// =============================================
// BASE DE DONNÉES JSON (Simple et fiable)
// =============================================
const DB_FILE = path.join(__dirname, 'database.json');

// Structure initiale de la base de données
const initialDB = {
  admin: {
    email: 'contact@uco-and-co.com',
    password: bcrypt.hashSync('30Septembre2006A$', 10)
  },
  collectors: [],
  operators: [],
  restaurants: [],
  collections: [],
  tournees: [],
  settings: {
    email: 'contact@uco-and-co.com',
    brevoApiKey: ''
  }
};

// Charger ou créer la base de données
function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const data = fs.readFileSync(DB_FILE, 'utf8');
      return JSON.parse(data);
    }
  } catch (e) {
    console.log('Erreur lecture DB, création nouvelle:', e.message);
  }
  saveDB(initialDB);
  return initialDB;
}

// Sauvegarder la base de données
function saveDB(data) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error('Erreur sauvegarde DB:', e.message);
  }
}

// Charger la DB au démarrage
let db = loadDB();

// =============================================
// FONCTIONS UTILITAIRES
// =============================================

// Générer un numéro de collecteur unique
function generateCollectorNumber() {
  const existingNumbers = db.collectors
    .filter(c => c.status === 'approved' && c.collectorNumber)
    .map(c => c.collectorNumber);
  
  let num = 1;
  while (existingNumbers.includes(num)) {
    num++;
  }
  return num;
}

// Générer un numéro d'opérateur unique
function generateOperatorNumber() {
  const existingNumbers = db.operators
    .filter(o => o.status === 'approved' && o.operatorNumber)
    .map(o => o.operatorNumber);
  
  let num = 1;
  while (existingNumbers.includes(num)) {
    num++;
  }
  return num;
}

// Générer un numéro d'ordre: AAMMJJ-XXX-YY
function generateNumeroOrdre(collectorNumber, date) {
  const d = new Date(date);
  const aa = String(d.getFullYear()).slice(-2);
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const jj = String(d.getDate()).padStart(2, '0');
  const colNum = String(collectorNumber).padStart(3, '0');
  
  // Compter les collectes du jour pour ce collecteur
  const dateStr = d.toISOString().split('T')[0];
  const todayCollections = db.collections.filter(c => {
    const cDate = new Date(c.date).toISOString().split('T')[0];
    return c.collectorNumber === collectorNumber && cDate === dateStr;
  });
  
  const ordre = String(todayCollections.length + 1).padStart(2, '0');
  return `${aa}${mm}${jj}-${colNum}-${ordre}`;
}

// =============================================
// ROUTES - HEALTH CHECK
// =============================================
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// =============================================
// ROUTES - AUTHENTIFICATION
// =============================================

// Login Admin
app.post('/api/auth/admin', (req, res) => {
  const { email, password } = req.body;
  
  if (email === db.admin.email && bcrypt.compareSync(password, db.admin.password)) {
    res.json({ success: true, user: { email: db.admin.email, role: 'admin' } });
  } else {
    res.json({ success: false, error: 'Identifiants incorrects' });
  }
});

// Login Collecteur
app.post('/api/auth/collector', (req, res) => {
  const { email, password } = req.body;
  
  const collector = db.collectors.find(c => c.email === email && c.status === 'approved');
  
  if (collector && bcrypt.compareSync(password, collector.password)) {
    const { password: _, ...userData } = collector;
    res.json({ success: true, user: userData });
  } else {
    res.json({ success: false, error: 'Identifiants incorrects ou compte non approuvé' });
  }
});

// Login Opérateur
app.post('/api/auth/operator', (req, res) => {
  const { email, password } = req.body;
  
  const operator = db.operators.find(o => o.email === email && o.status === 'approved');
  
  if (operator && bcrypt.compareSync(password, operator.password)) {
    const { password: _, ...userData } = operator;
    res.json({ success: true, user: userData });
  } else {
    res.json({ success: false, error: 'Identifiants incorrects ou compte non approuvé' });
  }
});

// Login Restaurant
app.post('/api/auth/restaurant', (req, res) => {
  const { email, password } = req.body;
  
  const restaurant = db.restaurants.find(r => r.email === email && r.status === 'approved');
  
  if (restaurant && restaurant.password && bcrypt.compareSync(password, restaurant.password)) {
    const { password: _, ...userData } = restaurant;
    res.json({ success: true, user: userData });
  } else {
    res.json({ success: false, error: 'Identifiants incorrects ou compte non approuvé' });
  }
});

// =============================================
// ROUTES - COLLECTEURS
// =============================================

// Inscription collecteur
app.post('/api/collectors/register', (req, res) => {
  const { email, password, ...data } = req.body;
  
  // Vérifier si email déjà utilisé
  if (db.collectors.find(c => c.email === email)) {
    return res.json({ success: false, error: 'Email déjà utilisé' });
  }
  
  const collector = {
    id: uuidv4(),
    email,
    password: bcrypt.hashSync(password, 10),
    ...data,
    status: 'pending',
    dateRequest: new Date().toISOString()
  };
  
  db.collectors.push(collector);
  saveDB(db);
  
  res.json({ success: true, id: collector.id });
});

// Liste des collecteurs en attente
app.get('/api/collectors/pending', (req, res) => {
  const pending = db.collectors
    .filter(c => c.status === 'pending')
    .map(({ password, ...c }) => c);
  res.json(pending);
});

// Liste des collecteurs approuvés
app.get('/api/collectors/approved', (req, res) => {
  const approved = db.collectors
    .filter(c => c.status === 'approved')
    .map(({ password, ...c }) => c);
  res.json(approved);
});

// Approuver un collecteur
app.post('/api/collectors/:id/approve', (req, res) => {
  const collector = db.collectors.find(c => c.id === req.params.id);
  
  if (!collector) {
    return res.json({ success: false, error: 'Collecteur non trouvé' });
  }
  
  collector.status = 'approved';
  collector.collectorNumber = generateCollectorNumber();
  collector.dateApproval = new Date().toISOString();
  
  saveDB(db);
  
  res.json({ success: true, collectorNumber: collector.collectorNumber });
});

// Refuser un collecteur
app.post('/api/collectors/:id/reject', (req, res) => {
  const index = db.collectors.findIndex(c => c.id === req.params.id);
  
  if (index === -1) {
    return res.json({ success: false, error: 'Collecteur non trouvé' });
  }
  
  db.collectors.splice(index, 1);
  saveDB(db);
  
  res.json({ success: true });
});

// Supprimer un collecteur
app.delete('/api/collectors/:id', (req, res) => {
  const index = db.collectors.findIndex(c => c.id === req.params.id);
  
  if (index === -1) {
    return res.json({ success: false, error: 'Collecteur non trouvé' });
  }
  
  db.collectors.splice(index, 1);
  saveDB(db);
  
  res.json({ success: true });
});

// Mettre à jour le mot de passe d'un collecteur
app.put('/api/collectors/:id/password', (req, res) => {
  const { password } = req.body;
  const collector = db.collectors.find(c => c.id === req.params.id || c.email === req.params.id);
  
  if (!collector) {
    return res.json({ success: false, error: 'Collecteur non trouvé' });
  }
  
  collector.password = bcrypt.hashSync(password, 10);
  saveDB(db);
  
  res.json({ success: true });
});

// =============================================
// ROUTES - OPÉRATEURS
// =============================================

// Inscription opérateur
app.post('/api/operators/register', (req, res) => {
  const { email, password, ...data } = req.body;
  
  if (db.operators.find(o => o.email === email)) {
    return res.json({ success: false, error: 'Email déjà utilisé' });
  }
  
  const operator = {
    id: uuidv4(),
    email,
    password: bcrypt.hashSync(password, 10),
    ...data,
    status: 'pending',
    dateRequest: new Date().toISOString()
  };
  
  db.operators.push(operator);
  saveDB(db);
  
  res.json({ success: true, id: operator.id });
});

// Liste des opérateurs en attente
app.get('/api/operators/pending', (req, res) => {
  const pending = db.operators
    .filter(o => o.status === 'pending')
    .map(({ password, ...o }) => o);
  res.json(pending);
});

// Liste des opérateurs approuvés
app.get('/api/operators/approved', (req, res) => {
  const approved = db.operators
    .filter(o => o.status === 'approved')
    .map(({ password, ...o }) => o);
  res.json(approved);
});

// Approuver un opérateur
app.post('/api/operators/:id/approve', (req, res) => {
  const operator = db.operators.find(o => o.id === req.params.id);
  
  if (!operator) {
    return res.json({ success: false, error: 'Opérateur non trouvé' });
  }
  
  operator.status = 'approved';
  operator.operatorNumber = generateOperatorNumber();
  operator.dateApproval = new Date().toISOString();
  
  saveDB(db);
  
  res.json({ success: true, operatorNumber: operator.operatorNumber });
});

// Refuser un opérateur
app.post('/api/operators/:id/reject', (req, res) => {
  const index = db.operators.findIndex(o => o.id === req.params.id);
  
  if (index === -1) {
    return res.json({ success: false, error: 'Opérateur non trouvé' });
  }
  
  db.operators.splice(index, 1);
  saveDB(db);
  
  res.json({ success: true });
});

// Supprimer un opérateur
app.delete('/api/operators/:id', (req, res) => {
  const index = db.operators.findIndex(o => o.id === req.params.id);
  
  if (index === -1) {
    return res.json({ success: false, error: 'Opérateur non trouvé' });
  }
  
  db.operators.splice(index, 1);
  saveDB(db);
  
  res.json({ success: true });
});

// Mettre à jour le mot de passe d'un opérateur
app.put('/api/operators/:id/password', (req, res) => {
  const { password } = req.body;
  const operator = db.operators.find(o => o.id === req.params.id || o.email === req.params.id);
  
  if (!operator) {
    return res.json({ success: false, error: 'Opérateur non trouvé' });
  }
  
  operator.password = bcrypt.hashSync(password, 10);
  saveDB(db);
  
  res.json({ success: true });
});

// =============================================
// ROUTES - RESTAURANTS
// =============================================

// Inscription restaurant
app.post('/api/restaurants/register', (req, res) => {
  const { email, ...data } = req.body;
  
  if (db.restaurants.find(r => r.email === email)) {
    return res.json({ success: false, error: 'Email déjà utilisé' });
  }
  
  const restaurant = {
    id: uuidv4(),
    email,
    ...data,
    status: 'pending',
    dateRequest: new Date().toISOString()
  };
  
  db.restaurants.push(restaurant);
  saveDB(db);
  
  res.json({ success: true, id: restaurant.id });
});

// Liste des restaurants en attente
app.get('/api/restaurants/pending', (req, res) => {
  const pending = db.restaurants
    .filter(r => r.status === 'pending')
    .map(({ password, ...r }) => r);
  res.json(pending);
});

// Liste des restaurants approuvés
app.get('/api/restaurants', (req, res) => {
  const approved = db.restaurants
    .filter(r => r.status === 'approved')
    .map(({ password, ...r }) => r);
  res.json(approved);
});

// Rechercher un restaurant par QR code
app.get('/api/restaurants/qr/:qrCode', (req, res) => {
  const restaurant = db.restaurants.find(r => r.qrCode === req.params.qrCode && r.status === 'approved');
  
  if (!restaurant) {
    return res.status(404).json({ error: 'Restaurant non trouvé' });
  }
  
  const { password, ...data } = restaurant;
  res.json(data);
});

// Approuver un restaurant
app.post('/api/restaurants/:id/approve', (req, res) => {
  const restaurant = db.restaurants.find(r => r.id === req.params.id);
  
  if (!restaurant) {
    return res.json({ success: false, error: 'Restaurant non trouvé' });
  }
  
  const { qrCode, password, ...updateData } = req.body;
  
  Object.assign(restaurant, updateData);
  restaurant.status = 'approved';
  restaurant.qrCode = qrCode || `UCO-${Date.now()}`;
  restaurant.dateApproval = new Date().toISOString();
  
  if (password) {
    restaurant.password = bcrypt.hashSync(password, 10);
  }
  
  saveDB(db);
  
  res.json({ success: true, qrCode: restaurant.qrCode });
});

// Refuser un restaurant
app.post('/api/restaurants/:id/reject', (req, res) => {
  const index = db.restaurants.findIndex(r => r.id === req.params.id);
  
  if (index === -1) {
    return res.json({ success: false, error: 'Restaurant non trouvé' });
  }
  
  db.restaurants.splice(index, 1);
  saveDB(db);
  
  res.json({ success: true });
});

// Ajouter un restaurant (admin)
app.post('/api/restaurants', (req, res) => {
  const restaurant = {
    id: uuidv4(),
    ...req.body,
    status: 'approved',
    dateCreated: new Date().toISOString()
  };
  
  db.restaurants.push(restaurant);
  saveDB(db);
  
  res.json({ success: true, id: restaurant.id });
});

// Modifier un restaurant
app.put('/api/restaurants/:id', (req, res) => {
  const restaurant = db.restaurants.find(r => r.id === req.params.id);
  
  if (!restaurant) {
    return res.json({ success: false, error: 'Restaurant non trouvé' });
  }
  
  Object.assign(restaurant, req.body);
  saveDB(db);
  
  res.json({ success: true });
});

// Supprimer un restaurant
app.delete('/api/restaurants/:id', (req, res) => {
  const index = db.restaurants.findIndex(r => r.id === req.params.id);
  
  if (index === -1) {
    return res.json({ success: false, error: 'Restaurant non trouvé' });
  }
  
  db.restaurants.splice(index, 1);
  saveDB(db);
  
  res.json({ success: true });
});

// Mettre à jour le mot de passe d'un restaurant
app.put('/api/restaurants/:id/password', (req, res) => {
  const { password } = req.body;
  const restaurant = db.restaurants.find(r => r.id === req.params.id || r.email === req.params.id);
  
  if (!restaurant) {
    return res.json({ success: false, error: 'Restaurant non trouvé' });
  }
  
  restaurant.password = password; // Non hashé pour les restaurants (comparaison directe)
  saveDB(db);
  
  res.json({ success: true });
});

// =============================================
// ROUTES - COLLECTES
// =============================================

// Créer une collecte
app.post('/api/collections', (req, res) => {
  const { collectorNumber, ...data } = req.body;
  
  const dateNow = new Date().toISOString();
  const numeroOrdre = generateNumeroOrdre(collectorNumber, dateNow);
  
  // Trouver le restaurant
  const restaurant = db.restaurants.find(r => r.id === data.restaurantId);
  
  const collection = {
    id: uuidv4(),
    numeroOrdre,
    date: dateNow,
    collectorNumber,
    ...data,
    restaurant: restaurant || null
  };
  
  db.collections.push(collection);
  saveDB(db);
  
  res.json({ 
    success: true, 
    collectionId: collection.id, 
    numeroOrdre,
    date: dateNow,
    restaurant
  });
});

// Liste des collectes
app.get('/api/collections', (req, res) => {
  res.json(db.collections);
});

// Collectes par collecteur
app.get('/api/collections/collector/:id', (req, res) => {
  const collections = db.collections.filter(c => c.collectorId === req.params.id);
  res.json(collections);
});

// Détail d'une collecte
app.get('/api/collections/:id', (req, res) => {
  const collection = db.collections.find(c => c.id === req.params.id);
  
  if (!collection) {
    return res.status(404).json({ error: 'Collecte non trouvée' });
  }
  
  res.json(collection);
});

// =============================================
// ROUTES - TOURNÉES
// =============================================

// Créer une tournée
app.post('/api/tournees', (req, res) => {
  const tournee = {
    id: uuidv4(),
    ...req.body,
    dateCreated: new Date().toISOString()
  };
  
  db.tournees.push(tournee);
  saveDB(db);
  
  res.json({ success: true, id: tournee.id });
});

// Récupérer une tournée par collecteur et date
app.get('/api/tournees/:collectorId/:date', (req, res) => {
  const tournee = db.tournees.find(t => 
    t.collectorId === req.params.collectorId && 
    t.date === req.params.date
  );
  
  if (!tournee) {
    return res.status(404).json({ error: 'Tournée non trouvée' });
  }
  
  res.json(tournee);
});

// Mettre à jour une tournée
app.put('/api/tournees/:id', (req, res) => {
  const tournee = db.tournees.find(t => t.id === req.params.id);
  
  if (!tournee) {
    return res.json({ success: false, error: 'Tournée non trouvée' });
  }
  
  Object.assign(tournee, req.body);
  saveDB(db);
  
  res.json({ success: true });
});

// =============================================
// ROUTES - STATISTIQUES
// =============================================

app.get('/api/statistics', (req, res) => {
  const totalCollections = db.collections.length;
  const totalVolume = db.collections.reduce((sum, c) => sum + (c.volume || 0), 0);
  const totalRestaurants = db.restaurants.filter(r => r.status === 'approved').length;
  const totalCollectors = db.collectors.filter(c => c.status === 'approved').length;
  
  res.json({
    totalCollections,
    totalVolume,
    totalRestaurants,
    totalCollectors
  });
});

// =============================================
// ROUTES - PARAMÈTRES ADMIN
// =============================================

// Récupérer les paramètres
app.get('/api/settings', (req, res) => {
  // Initialiser settings si non existant
  if (!db.settings) {
    db.settings = {
      email: 'contact@uco-and-co.com',
      brevoApiKey: ''
    };
    saveDB(db);
  }
  res.json(db.settings);
});

// Mettre à jour les paramètres
app.post('/api/settings', (req, res) => {
  const { email, brevoApiKey } = req.body;
  
  if (!db.settings) {
    db.settings = {};
  }
  
  if (email !== undefined) db.settings.email = email;
  if (brevoApiKey !== undefined) db.settings.brevoApiKey = brevoApiKey;
  
  saveDB(db);
  
  res.json({ success: true, settings: db.settings });
});

// =============================================
// DÉMARRAGE DU SERVEUR
// =============================================

app.listen(PORT, () => {
  console.log(`🚀 UCO Backend running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
});
