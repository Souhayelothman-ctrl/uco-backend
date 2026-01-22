const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Database setup
const db = new Database(path.join(__dirname, 'uco_database.db'));

// Initialize database tables
db.exec(`
  -- Table Admin
  CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nom TEXT,
    prenom TEXT,
    tel TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Table Collecteurs
  CREATE TABLE IF NOT EXISTS collectors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collector_number INTEGER UNIQUE,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nom TEXT NOT NULL,
    prenom TEXT NOT NULL,
    tel TEXT,
    permis_numero TEXT,
    permis_date_obtention TEXT,
    permis_lieu_obtention TEXT,
    permis_categories TEXT,
    status TEXT DEFAULT 'pending',
    date_request DATETIME DEFAULT CURRENT_TIMESTAMP,
    date_approved DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Table Opérateurs
  CREATE TABLE IF NOT EXISTS operators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operator_number INTEGER UNIQUE,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nom TEXT NOT NULL,
    prenom TEXT NOT NULL,
    tel TEXT,
    status TEXT DEFAULT 'pending',
    date_request DATETIME DEFAULT CURRENT_TIMESTAMP,
    date_approved DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Table Restaurants
  CREATE TABLE IF NOT EXISTS restaurants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    restaurant_id TEXT UNIQUE,
    enseigne TEXT NOT NULL,
    societe TEXT,
    siret TEXT,
    type_producteur TEXT,
    adresse TEXT,
    gerant TEXT,
    tel TEXT,
    email TEXT,
    password TEXT,
    frequence INTEGER DEFAULT 14,
    qr_code TEXT UNIQUE,
    prix_litre REAL DEFAULT 0,
    gps TEXT,
    rib TEXT,
    certificate_id TEXT,
    individual_certification TEXT DEFAULT 'No',
    legal_type TEXT,
    scope_sourcing_contact TEXT,
    outgoing_material TEXT DEFAULT 'Used cooking oil (UCO) entirely of veg. origin',
    max_capacity_per_year INTEGER,
    renewable_capacity_per_year INTEGER,
    measuring_unit TEXT DEFAULT 'litres',
    status TEXT DEFAULT 'pending',
    activation_code TEXT,
    activation_expires DATETIME,
    date_request DATETIME DEFAULT CURRENT_TIMESTAMP,
    date_approved DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Table Collectes
  CREATE TABLE IF NOT EXISTS collections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collection_id TEXT UNIQUE NOT NULL,
    numero_ordre TEXT UNIQUE NOT NULL,
    date DATETIME NOT NULL,
    restaurant_id INTEGER NOT NULL,
    collector_id INTEGER,
    collector_number INTEGER,
    collector_name TEXT,
    volume REAL NOT NULL,
    conditionnement_type TEXT,
    conditionnement_nombre_futs INTEGER,
    conditionnement_volume_fut INTEGER,
    price REAL NOT NULL,
    payment_modes TEXT,
    payment_amounts TEXT,
    col_signature TEXT,
    resto_signature TEXT,
    bordereau_sent INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (restaurant_id) REFERENCES restaurants(id),
    FOREIGN KEY (collector_id) REFERENCES collectors(id)
  );

  -- Table Tournées
  CREATE TABLE IF NOT EXISTS tournees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tournee_id TEXT UNIQUE NOT NULL,
    collector_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    etapes TEXT,
    status TEXT DEFAULT 'en_cours',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (collector_id) REFERENCES collectors(id)
  );

  -- Table Paramètres Admin
  CREATE TABLE IF NOT EXISTS admin_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value TEXT
  );
`);

// Insert default admin if not exists
const defaultAdmin = db.prepare('SELECT * FROM admin WHERE email = ?').get('contact@uco-and-co.com');
if (!defaultAdmin) {
  const hashedPassword = bcrypt.hashSync('30Septembre2006A$', 10);
  db.prepare('INSERT INTO admin (email, password, nom, prenom) VALUES (?, ?, ?, ?)').run(
    'contact@uco-and-co.com', hashedPassword, 'Admin', 'UCO'
  );
}

// =============================================
// HELPER FUNCTIONS
// =============================================

// Générer le numéro d'ordre: AAMMJJ-COL-XX
function generateNumeroOrdre(collectorNumber, date) {
  const d = new Date(date);
  const aa = String(d.getFullYear()).slice(-2);
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const jj = String(d.getDate()).padStart(2, '0');
  const colNum = String(collectorNumber).padStart(3, '0');
  
  // Compter les collectes du jour pour ce collecteur
  const dateStr = `${d.getFullYear()}-${mm}-${jj}`;
  const count = db.prepare(`
    SELECT COUNT(*) as count FROM collections 
    WHERE collector_number = ? 
    AND DATE(date) = DATE(?)
  `).get(collectorNumber, dateStr);
  
  const ordre = String((count?.count || 0) + 1).padStart(2, '0');
  
  return `${aa}${mm}${jj}-${colNum}-${ordre}`;
}

// Générer un numéro de collecteur unique
function generateCollectorNumber() {
  const result = db.prepare('SELECT MAX(collector_number) as max FROM collectors').get();
  return (result?.max || 0) + 1;
}

// Générer un numéro d'opérateur unique
function generateOperatorNumber() {
  const result = db.prepare('SELECT MAX(operator_number) as max FROM operators').get();
  return (result?.max || 0) + 1;
}

// Générer un code d'activation
function generateActivationCode() {
  return Math.random().toString(36).substring(2, 8).toUpperCase();
}

// =============================================
// AUTH ROUTES
// =============================================

// Login Admin
app.post('/api/auth/admin', (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = db.prepare('SELECT * FROM admin WHERE email = ?').get(email);
    
    if (!admin || !bcrypt.compareSync(password, admin.password)) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }
    
    res.json({ 
      success: true, 
      user: { 
        id: admin.id, 
        email: admin.email, 
        nom: admin.nom, 
        prenom: admin.prenom,
        role: 'admin' 
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login Collecteur
app.post('/api/auth/collector', (req, res) => {
  try {
    const { email, password } = req.body;
    const collector = db.prepare('SELECT * FROM collectors WHERE email = ? AND status = ?').get(email, 'approved');
    
    if (!collector || !bcrypt.compareSync(password, collector.password)) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect, ou compte non approuvé' });
    }
    
    res.json({ 
      success: true, 
      user: { 
        id: collector.id, 
        collectorNumber: collector.collector_number,
        email: collector.email, 
        nom: collector.nom, 
        prenom: collector.prenom,
        tel: collector.tel ? JSON.parse(collector.tel) : null,
        permis: collector.permis_numero ? {
          numero: collector.permis_numero,
          dateObtention: collector.permis_date_obtention,
          lieuObtention: collector.permis_lieu_obtention,
          categories: collector.permis_categories ? JSON.parse(collector.permis_categories) : []
        } : null,
        role: 'collector' 
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login Opérateur
app.post('/api/auth/operator', (req, res) => {
  try {
    const { email, password } = req.body;
    const operator = db.prepare('SELECT * FROM operators WHERE email = ? AND status = ?').get(email, 'approved');
    
    if (!operator || !bcrypt.compareSync(password, operator.password)) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect, ou compte non approuvé' });
    }
    
    res.json({ 
      success: true, 
      user: { 
        id: operator.id, 
        operatorNumber: operator.operator_number,
        email: operator.email, 
        nom: operator.nom, 
        prenom: operator.prenom,
        role: 'operator' 
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login Restaurant
app.post('/api/auth/restaurant', (req, res) => {
  try {
    const { email, password } = req.body;
    const restaurant = db.prepare('SELECT * FROM restaurants WHERE email = ? AND status = ?').get(email, 'approved');
    
    if (!restaurant || !bcrypt.compareSync(password, restaurant.password)) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect, ou compte non approuvé' });
    }
    
    res.json({ 
      success: true, 
      user: { 
        id: restaurant.id, 
        restaurantId: restaurant.restaurant_id,
        enseigne: restaurant.enseigne,
        email: restaurant.email,
        role: 'restaurant' 
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================
// COLLECTORS ROUTES
// =============================================

// Register collector (demande)
app.post('/api/collectors/register', (req, res) => {
  try {
    const { email, password, nom, prenom, tel, permis } = req.body;
    
    const existing = db.prepare('SELECT * FROM collectors WHERE email = ?').get(email);
    if (existing) {
      return res.status(400).json({ error: 'Un compte avec cet email existe déjà' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    
    const result = db.prepare(`
      INSERT INTO collectors (email, password, nom, prenom, tel, permis_numero, permis_date_obtention, permis_lieu_obtention, permis_categories, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    `).run(
      email, 
      hashedPassword, 
      nom, 
      prenom, 
      tel ? JSON.stringify(tel) : null,
      permis?.numero,
      permis?.dateObtention,
      permis?.lieuObtention,
      permis?.categories ? JSON.stringify(permis.categories) : null
    );
    
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get pending collectors
app.get('/api/collectors/pending', (req, res) => {
  try {
    const collectors = db.prepare('SELECT * FROM collectors WHERE status = ?').all('pending');
    res.json(collectors.map(c => ({
      id: c.id,
      email: c.email,
      nom: c.nom,
      prenom: c.prenom,
      tel: c.tel ? JSON.parse(c.tel) : null,
      permis: c.permis_numero ? {
        numero: c.permis_numero,
        dateObtention: c.permis_date_obtention,
        lieuObtention: c.permis_lieu_obtention,
        categories: c.permis_categories ? JSON.parse(c.permis_categories) : []
      } : null,
      dateRequest: c.date_request
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get approved collectors
app.get('/api/collectors/approved', (req, res) => {
  try {
    const collectors = db.prepare('SELECT * FROM collectors WHERE status = ?').all('approved');
    res.json(collectors.map(c => ({
      id: c.id,
      collectorNumber: c.collector_number,
      email: c.email,
      nom: c.nom,
      prenom: c.prenom,
      tel: c.tel ? JSON.parse(c.tel) : null,
      permis: c.permis_numero ? {
        numero: c.permis_numero,
        dateObtention: c.permis_date_obtention,
        lieuObtention: c.permis_lieu_obtention,
        categories: c.permis_categories ? JSON.parse(c.permis_categories) : []
      } : null,
      dateApproved: c.date_approved
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Approve collector
app.post('/api/collectors/:id/approve', (req, res) => {
  try {
    const { id } = req.params;
    const collectorNumber = generateCollectorNumber();
    
    db.prepare(`
      UPDATE collectors 
      SET status = 'approved', collector_number = ?, date_approved = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(collectorNumber, id);
    
    const collector = db.prepare('SELECT * FROM collectors WHERE id = ?').get(id);
    
    res.json({ 
      success: true, 
      collectorNumber,
      collector: {
        id: collector.id,
        collectorNumber: collector.collector_number,
        email: collector.email,
        nom: collector.nom,
        prenom: collector.prenom
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reject collector
app.post('/api/collectors/:id/reject', (req, res) => {
  try {
    const { id } = req.params;
    db.prepare('DELETE FROM collectors WHERE id = ? AND status = ?').run(id, 'pending');
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete collector
app.delete('/api/collectors/:id', (req, res) => {
  try {
    const { id } = req.params;
    db.prepare('DELETE FROM collectors WHERE id = ?').run(id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================
// OPERATORS ROUTES
// =============================================

// Register operator
app.post('/api/operators/register', (req, res) => {
  try {
    const { email, password, nom, prenom, tel } = req.body;
    
    const existing = db.prepare('SELECT * FROM operators WHERE email = ?').get(email);
    if (existing) {
      return res.status(400).json({ error: 'Un compte avec cet email existe déjà' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    
    const result = db.prepare(`
      INSERT INTO operators (email, password, nom, prenom, tel, status)
      VALUES (?, ?, ?, ?, ?, 'pending')
    `).run(email, hashedPassword, nom, prenom, tel ? JSON.stringify(tel) : null);
    
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get pending operators
app.get('/api/operators/pending', (req, res) => {
  try {
    const operators = db.prepare('SELECT * FROM operators WHERE status = ?').all('pending');
    res.json(operators.map(o => ({
      id: o.id,
      email: o.email,
      nom: o.nom,
      prenom: o.prenom,
      tel: o.tel ? JSON.parse(o.tel) : null,
      dateRequest: o.date_request
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get approved operators
app.get('/api/operators/approved', (req, res) => {
  try {
    const operators = db.prepare('SELECT * FROM operators WHERE status = ?').all('approved');
    res.json(operators.map(o => ({
      id: o.id,
      operatorNumber: o.operator_number,
      email: o.email,
      nom: o.nom,
      prenom: o.prenom,
      tel: o.tel ? JSON.parse(o.tel) : null,
      dateApproved: o.date_approved
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Approve operator
app.post('/api/operators/:id/approve', (req, res) => {
  try {
    const { id } = req.params;
    const operatorNumber = generateOperatorNumber();
    
    db.prepare(`
      UPDATE operators 
      SET status = 'approved', operator_number = ?, date_approved = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(operatorNumber, id);
    
    const operator = db.prepare('SELECT * FROM operators WHERE id = ?').get(id);
    
    res.json({ 
      success: true, 
      operatorNumber,
      operator: {
        id: operator.id,
        operatorNumber: operator.operator_number,
        email: operator.email,
        nom: operator.nom,
        prenom: operator.prenom
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reject operator
app.post('/api/operators/:id/reject', (req, res) => {
  try {
    const { id } = req.params;
    db.prepare('DELETE FROM operators WHERE id = ? AND status = ?').run(id, 'pending');
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete operator
app.delete('/api/operators/:id', (req, res) => {
  try {
    const { id } = req.params;
    db.prepare('DELETE FROM operators WHERE id = ?').run(id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================
// RESTAURANTS ROUTES
// =============================================

// Register restaurant (demande)
app.post('/api/restaurants/register', (req, res) => {
  try {
    const { enseigne, societe, siret, typeProducteur, adresse, gerant, tel, email, password, gps, rib } = req.body;
    
    const existing = db.prepare('SELECT * FROM restaurants WHERE email = ?').get(email);
    if (existing) {
      return res.status(400).json({ error: 'Un compte avec cet email existe déjà' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    
    const result = db.prepare(`
      INSERT INTO restaurants (enseigne, societe, siret, type_producteur, adresse, gerant, tel, email, password, gps, rib, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    `).run(
      enseigne,
      societe,
      siret,
      typeProducteur,
      adresse ? JSON.stringify(adresse) : null,
      gerant ? JSON.stringify(gerant) : null,
      tel ? JSON.stringify(tel) : null,
      email,
      hashedPassword,
      gps ? JSON.stringify(gps) : null,
      rib ? JSON.stringify(rib) : null
    );
    
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get pending restaurants
app.get('/api/restaurants/pending', (req, res) => {
  try {
    const restaurants = db.prepare('SELECT * FROM restaurants WHERE status = ?').all('pending');
    res.json(restaurants.map(r => ({
      id: r.id,
      enseigne: r.enseigne,
      societe: r.societe,
      siret: r.siret,
      typeProducteur: r.type_producteur,
      adresse: r.adresse ? JSON.parse(r.adresse) : null,
      gerant: r.gerant ? JSON.parse(r.gerant) : null,
      tel: r.tel ? JSON.parse(r.tel) : null,
      email: r.email,
      gps: r.gps ? JSON.parse(r.gps) : null,
      rib: r.rib ? JSON.parse(r.rib) : null,
      dateRequest: r.date_request
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all approved restaurants
app.get('/api/restaurants', (req, res) => {
  try {
    const restaurants = db.prepare('SELECT * FROM restaurants WHERE status = ?').all('approved');
    res.json(restaurants.map(r => ({
      id: r.id,
      restaurantId: r.restaurant_id,
      enseigne: r.enseigne,
      societe: r.societe,
      siret: r.siret,
      typeProducteur: r.type_producteur,
      adresse: r.adresse ? JSON.parse(r.adresse) : null,
      gerant: r.gerant ? JSON.parse(r.gerant) : null,
      tel: r.tel ? JSON.parse(r.tel) : null,
      email: r.email,
      frequence: r.frequence,
      qrCode: r.qr_code,
      prixLitre: r.prix_litre,
      gps: r.gps ? JSON.parse(r.gps) : null,
      rib: r.rib ? JSON.parse(r.rib) : null,
      certificateId: r.certificate_id,
      individualCertification: r.individual_certification,
      legalType: r.legal_type,
      scopeSourcingContact: r.scope_sourcing_contact,
      outgoingMaterial: r.outgoing_material,
      maxCapacityPerYear: r.max_capacity_per_year,
      renewableCapacityPerYear: r.renewable_capacity_per_year,
      measuringUnit: r.measuring_unit,
      dateApproved: r.date_approved
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get restaurant by QR code
app.get('/api/restaurants/qr/:qrCode', (req, res) => {
  try {
    const { qrCode } = req.params;
    const restaurant = db.prepare('SELECT * FROM restaurants WHERE qr_code = ? AND status = ?').get(qrCode, 'approved');
    
    if (!restaurant) {
      return res.status(404).json({ error: 'Restaurant non trouvé' });
    }
    
    res.json({
      id: restaurant.id,
      restaurantId: restaurant.restaurant_id,
      enseigne: restaurant.enseigne,
      societe: restaurant.societe,
      siret: restaurant.siret,
      typeProducteur: restaurant.type_producteur,
      adresse: restaurant.adresse ? JSON.parse(restaurant.adresse) : null,
      gerant: restaurant.gerant ? JSON.parse(restaurant.gerant) : null,
      tel: restaurant.tel ? JSON.parse(restaurant.tel) : null,
      email: restaurant.email,
      frequence: restaurant.frequence,
      qrCode: restaurant.qr_code,
      prixLitre: restaurant.prix_litre,
      gps: restaurant.gps ? JSON.parse(restaurant.gps) : null
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Approve restaurant
app.post('/api/restaurants/:id/approve', (req, res) => {
  try {
    const { id } = req.params;
    const { frequence, qrCode, prixLitre, restaurantId, certificateId, individualCertification, legalType, scopeSourcingContact, maxCapacityPerYear, renewableCapacityPerYear } = req.body;
    
    const activationCode = generateActivationCode();
    const activationExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    
    db.prepare(`
      UPDATE restaurants 
      SET status = 'approved', 
          frequence = ?, 
          qr_code = ?, 
          prix_litre = ?,
          restaurant_id = ?,
          certificate_id = ?,
          individual_certification = ?,
          legal_type = ?,
          scope_sourcing_contact = ?,
          max_capacity_per_year = ?,
          renewable_capacity_per_year = ?,
          activation_code = ?,
          activation_expires = ?,
          date_approved = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(
      frequence, qrCode, prixLitre, restaurantId, certificateId, individualCertification,
      legalType, scopeSourcingContact, maxCapacityPerYear, renewableCapacityPerYear,
      activationCode, activationExpires, id
    );
    
    const restaurant = db.prepare('SELECT * FROM restaurants WHERE id = ?').get(id);
    
    res.json({ 
      success: true, 
      activationCode,
      restaurant: {
        id: restaurant.id,
        enseigne: restaurant.enseigne,
        email: restaurant.email
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reject restaurant
app.post('/api/restaurants/:id/reject', (req, res) => {
  try {
    const { id } = req.params;
    db.prepare('DELETE FROM restaurants WHERE id = ? AND status = ?').run(id, 'pending');
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add restaurant (admin direct)
app.post('/api/restaurants', (req, res) => {
  try {
    const data = req.body;
    
    const result = db.prepare(`
      INSERT INTO restaurants (
        enseigne, societe, siret, type_producteur, adresse, gerant, tel, email, 
        frequence, qr_code, prix_litre, gps, rib, restaurant_id, certificate_id,
        individual_certification, legal_type, scope_sourcing_contact, outgoing_material,
        max_capacity_per_year, renewable_capacity_per_year, measuring_unit, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved')
    `).run(
      data.enseigne,
      data.societe,
      data.siret,
      data.typeProducteur,
      data.adresse ? JSON.stringify(data.adresse) : null,
      data.gerant ? JSON.stringify(data.gerant) : null,
      data.tel ? JSON.stringify(data.tel) : null,
      data.email,
      data.frequence,
      data.qrCode,
      data.prixLitre,
      data.gps ? JSON.stringify(data.gps) : null,
      data.rib ? JSON.stringify(data.rib) : null,
      data.restaurantId,
      data.certificateId,
      data.individualCertification,
      data.legalType,
      data.scopeSourcingContact,
      data.outgoingMaterial,
      data.maxCapacityPerYear,
      data.renewableCapacityPerYear,
      data.measuringUnit
    );
    
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update restaurant
app.put('/api/restaurants/:id', (req, res) => {
  try {
    const { id } = req.params;
    const data = req.body;
    
    db.prepare(`
      UPDATE restaurants SET
        enseigne = ?, societe = ?, siret = ?, type_producteur = ?, adresse = ?, gerant = ?, 
        tel = ?, email = ?, frequence = ?, qr_code = ?, prix_litre = ?, gps = ?, rib = ?,
        restaurant_id = ?, certificate_id = ?, individual_certification = ?, legal_type = ?,
        scope_sourcing_contact = ?, outgoing_material = ?, max_capacity_per_year = ?,
        renewable_capacity_per_year = ?, measuring_unit = ?
      WHERE id = ?
    `).run(
      data.enseigne,
      data.societe,
      data.siret,
      data.typeProducteur,
      data.adresse ? JSON.stringify(data.adresse) : null,
      data.gerant ? JSON.stringify(data.gerant) : null,
      data.tel ? JSON.stringify(data.tel) : null,
      data.email,
      data.frequence,
      data.qrCode,
      data.prixLitre,
      data.gps ? JSON.stringify(data.gps) : null,
      data.rib ? JSON.stringify(data.rib) : null,
      data.restaurantId,
      data.certificateId,
      data.individualCertification,
      data.legalType,
      data.scopeSourcingContact,
      data.outgoingMaterial,
      data.maxCapacityPerYear,
      data.renewableCapacityPerYear,
      data.measuringUnit,
      id
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete restaurant
app.delete('/api/restaurants/:id', (req, res) => {
  try {
    const { id } = req.params;
    db.prepare('DELETE FROM restaurants WHERE id = ?').run(id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================
// COLLECTIONS ROUTES
// =============================================

// Create collection
app.post('/api/collections', (req, res) => {
  try {
    const { 
      restaurantId, collectorId, collectorNumber, collectorName,
      volume, conditionnement, price, paymentModes, paymentAmounts,
      colSignature, restoSignature
    } = req.body;
    
    const collectionId = 'col:' + Date.now();
    const date = new Date().toISOString();
    const numeroOrdre = generateNumeroOrdre(collectorNumber, date);
    
    const result = db.prepare(`
      INSERT INTO collections (
        collection_id, numero_ordre, date, restaurant_id, collector_id, collector_number,
        collector_name, volume, conditionnement_type, conditionnement_nombre_futs,
        conditionnement_volume_fut, price, payment_modes, payment_amounts,
        col_signature, resto_signature
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      collectionId,
      numeroOrdre,
      date,
      restaurantId,
      collectorId,
      collectorNumber,
      collectorName,
      volume,
      conditionnement?.type,
      conditionnement?.nombreFuts,
      conditionnement?.volumeFut,
      price,
      paymentModes ? JSON.stringify(paymentModes) : null,
      paymentAmounts ? JSON.stringify(paymentAmounts) : null,
      colSignature,
      restoSignature
    );
    
    // Get restaurant info
    const restaurant = db.prepare('SELECT * FROM restaurants WHERE id = ?').get(restaurantId);
    
    res.json({ 
      success: true, 
      id: result.lastInsertRowid,
      collectionId,
      numeroOrdre,
      date,
      restaurant: restaurant ? {
        id: restaurant.id,
        enseigne: restaurant.enseigne,
        societe: restaurant.societe,
        siret: restaurant.siret,
        typeProducteur: restaurant.type_producteur,
        adresse: restaurant.adresse ? JSON.parse(restaurant.adresse) : null,
        gerant: restaurant.gerant ? JSON.parse(restaurant.gerant) : null,
        tel: restaurant.tel ? JSON.parse(restaurant.tel) : null,
        email: restaurant.email,
        prixLitre: restaurant.prix_litre
      } : null
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all collections
app.get('/api/collections', (req, res) => {
  try {
    const collections = db.prepare(`
      SELECT c.*, r.enseigne, r.societe, r.siret, r.type_producteur, r.adresse, r.gerant, r.tel as resto_tel, r.email as resto_email, r.prix_litre
      FROM collections c
      LEFT JOIN restaurants r ON c.restaurant_id = r.id
      ORDER BY c.date DESC
    `).all();
    
    res.json(collections.map(c => ({
      id: c.collection_id,
      numeroOrdre: c.numero_ordre,
      date: c.date,
      restaurant: {
        id: c.restaurant_id,
        enseigne: c.enseigne,
        societe: c.societe,
        siret: c.siret,
        typeProducteur: c.type_producteur,
        adresse: c.adresse ? JSON.parse(c.adresse) : null,
        gerant: c.gerant ? JSON.parse(c.gerant) : null,
        tel: c.resto_tel ? JSON.parse(c.resto_tel) : null,
        email: c.resto_email,
        prixLitre: c.prix_litre
      },
      collectorNumber: c.collector_number,
      collectorName: c.collector_name,
      volume: c.volume,
      conditionnement: c.conditionnement_type ? {
        type: c.conditionnement_type,
        nombreFuts: c.conditionnement_nombre_futs,
        volumeFut: c.conditionnement_volume_fut
      } : null,
      price: c.price,
      paymentModes: c.payment_modes ? JSON.parse(c.payment_modes) : null,
      paymentAmounts: c.payment_amounts ? JSON.parse(c.payment_amounts) : null,
      colSig: c.col_signature,
      restoSig: c.resto_signature
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get collections by collector
app.get('/api/collections/collector/:collectorId', (req, res) => {
  try {
    const { collectorId } = req.params;
    const collections = db.prepare(`
      SELECT c.*, r.enseigne, r.societe, r.siret, r.type_producteur, r.adresse, r.gerant, r.tel as resto_tel, r.email as resto_email, r.prix_litre
      FROM collections c
      LEFT JOIN restaurants r ON c.restaurant_id = r.id
      WHERE c.collector_id = ?
      ORDER BY c.date DESC
    `).all(collectorId);
    
    res.json(collections.map(c => ({
      id: c.collection_id,
      numeroOrdre: c.numero_ordre,
      date: c.date,
      restaurant: {
        id: c.restaurant_id,
        enseigne: c.enseigne,
        societe: c.societe,
        siret: c.siret,
        typeProducteur: c.type_producteur,
        adresse: c.adresse ? JSON.parse(c.adresse) : null,
        gerant: c.gerant ? JSON.parse(c.gerant) : null,
        tel: c.resto_tel ? JSON.parse(c.resto_tel) : null,
        email: c.resto_email,
        prixLitre: c.prix_litre
      },
      collectorNumber: c.collector_number,
      collectorName: c.collector_name,
      volume: c.volume,
      conditionnement: c.conditionnement_type ? {
        type: c.conditionnement_type,
        nombreFuts: c.conditionnement_nombre_futs,
        volumeFut: c.conditionnement_volume_fut
      } : null,
      price: c.price,
      paymentModes: c.payment_modes ? JSON.parse(c.payment_modes) : null,
      paymentAmounts: c.payment_amounts ? JSON.parse(c.payment_amounts) : null,
      colSig: c.col_signature,
      restoSig: c.resto_signature
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get collection by ID
app.get('/api/collections/:id', (req, res) => {
  try {
    const { id } = req.params;
    const collection = db.prepare(`
      SELECT c.*, r.enseigne, r.societe, r.siret, r.type_producteur, r.adresse, r.gerant, r.tel as resto_tel, r.email as resto_email, r.prix_litre
      FROM collections c
      LEFT JOIN restaurants r ON c.restaurant_id = r.id
      WHERE c.collection_id = ?
    `).get(id);
    
    if (!collection) {
      return res.status(404).json({ error: 'Collection non trouvée' });
    }
    
    res.json({
      id: collection.collection_id,
      numeroOrdre: collection.numero_ordre,
      date: collection.date,
      restaurant: {
        id: collection.restaurant_id,
        enseigne: collection.enseigne,
        societe: collection.societe,
        siret: collection.siret,
        typeProducteur: collection.type_producteur,
        adresse: collection.adresse ? JSON.parse(collection.adresse) : null,
        gerant: collection.gerant ? JSON.parse(collection.gerant) : null,
        tel: collection.resto_tel ? JSON.parse(collection.resto_tel) : null,
        email: collection.resto_email,
        prixLitre: collection.prix_litre
      },
      collectorNumber: collection.collector_number,
      collectorName: collection.collector_name,
      volume: collection.volume,
      conditionnement: collection.conditionnement_type ? {
        type: collection.conditionnement_type,
        nombreFuts: collection.conditionnement_nombre_futs,
        volumeFut: collection.conditionnement_volume_fut
      } : null,
      price: collection.price,
      paymentModes: collection.payment_modes ? JSON.parse(collection.payment_modes) : null,
      paymentAmounts: collection.payment_amounts ? JSON.parse(collection.payment_amounts) : null,
      colSig: collection.col_signature,
      restoSig: collection.resto_signature
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================
// TOURNEES ROUTES
// =============================================

// Create tournee
app.post('/api/tournees', (req, res) => {
  try {
    const { collectorId, date, etapes } = req.body;
    const tourneeId = `tournee:${collectorId}:${date}`;
    
    // Check if tournee exists
    const existing = db.prepare('SELECT * FROM tournees WHERE tournee_id = ?').get(tourneeId);
    if (existing) {
      return res.json({ success: true, id: existing.id, tourneeId, exists: true });
    }
    
    const result = db.prepare(`
      INSERT INTO tournees (tournee_id, collector_id, date, etapes, status)
      VALUES (?, ?, ?, ?, 'en_cours')
    `).run(tourneeId, collectorId, date, JSON.stringify(etapes));
    
    res.json({ success: true, id: result.lastInsertRowid, tourneeId });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get tournee by collector and date
app.get('/api/tournees/:collectorId/:date', (req, res) => {
  try {
    const { collectorId, date } = req.params;
    const tourneeId = `tournee:${collectorId}:${date}`;
    const tournee = db.prepare('SELECT * FROM tournees WHERE tournee_id = ?').get(tourneeId);
    
    if (!tournee) {
      return res.status(404).json({ error: 'Tournée non trouvée' });
    }
    
    res.json({
      id: tournee.tournee_id,
      collectorId: tournee.collector_id,
      date: tournee.date,
      etapes: JSON.parse(tournee.etapes),
      status: tournee.status
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update tournee
app.put('/api/tournees/:tourneeId', (req, res) => {
  try {
    const { tourneeId } = req.params;
    const { etapes, status } = req.body;
    
    db.prepare(`
      UPDATE tournees SET etapes = ?, status = ? WHERE tournee_id = ?
    `).run(JSON.stringify(etapes), status, tourneeId);
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================
// ADMIN SETTINGS ROUTES
// =============================================

// Get settings
app.get('/api/settings', (req, res) => {
  try {
    const settings = db.prepare('SELECT * FROM admin_settings').all();
    const result = {};
    settings.forEach(s => {
      result[s.key] = s.value;
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update settings
app.post('/api/settings', (req, res) => {
  try {
    const settings = req.body;
    
    for (const [key, value] of Object.entries(settings)) {
      db.prepare(`
        INSERT INTO admin_settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = ?
      `).run(key, value, value);
    }
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================
// STATISTICS ROUTES
// =============================================

// Get statistics
app.get('/api/statistics', (req, res) => {
  try {
    const totalCollections = db.prepare('SELECT COUNT(*) as count FROM collections').get().count;
    const totalVolume = db.prepare('SELECT SUM(volume) as total FROM collections').get().total || 0;
    const totalRevenue = db.prepare('SELECT SUM(price) as total FROM collections').get().total || 0;
    const totalRestaurants = db.prepare('SELECT COUNT(*) as count FROM restaurants WHERE status = ?').get('approved').count;
    const totalCollectors = db.prepare('SELECT COUNT(*) as count FROM collectors WHERE status = ?').get('approved').count;
    
    // Collections today
    const today = new Date().toISOString().split('T')[0];
    const todayCollections = db.prepare('SELECT COUNT(*) as count FROM collections WHERE DATE(date) = DATE(?)').get(today).count;
    const todayVolume = db.prepare('SELECT SUM(volume) as total FROM collections WHERE DATE(date) = DATE(?)').get(today).total || 0;
    
    res.json({
      totalCollections,
      totalVolume,
      totalRevenue,
      totalRestaurants,
      totalCollectors,
      todayCollections,
      todayVolume
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║           UCO AND CO - Backend Server                      ║
╠═══════════════════════════════════════════════════════════╣
║  Server running on port ${PORT}                              ║
║  API URL: http://localhost:${PORT}/api                       ║
║  Health check: http://localhost:${PORT}/api/health           ║
╚═══════════════════════════════════════════════════════════╝
  `);
});

module.exports = app;
