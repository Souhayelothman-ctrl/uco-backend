# UCO AND CO - Backend Server

## Description
Serveur backend Node.js avec base de données SQLite pour l'application de collecte d'huiles usagées UCO AND CO.

## Fonctionnalités
- Authentification (Admin, Collecteurs, Opérateurs, Restaurants)
- Gestion des collecteurs avec numéro unique (COL-001, COL-002, etc.)
- Gestion des opérateurs avec numéro unique (OP-001, OP-002, etc.)
- Gestion des restaurants
- Gestion des collectes avec numéro d'ordre automatique
- Gestion des tournées
- Génération automatique du bordereau Word

## Format du Numéro d'Ordre
Le numéro d'ordre suit le format: `AAMMJJ-XXX-YY`
- `AA`: Année sur 2 chiffres (2026 → 26)
- `MM`: Mois sur 2 chiffres (01-12)
- `JJ`: Jour sur 2 chiffres (01-31)
- `XXX`: Numéro du collecteur sur 3 chiffres (001, 002, etc.)
- `YY`: Numéro d'ordre de passage du jour sur 2 chiffres (01, 02, 03, etc.)

**Exemple:** `260122-001-03` = 22 janvier 2026, Collecteur 001, 3ème collecte du jour

---

## 🚀 DÉPLOIEMENT SUR RENDER (Gratuit)

### Étape 1: Créer un compte Render
1. Aller sur **https://render.com**
2. Cliquer sur "Get Started for Free"
3. Se connecter avec GitHub (recommandé)

### Étape 2: Créer un repository GitHub
1. Créer un nouveau repository sur GitHub
2. Uploader les fichiers du backend:
   - `server.js`
   - `package.json`
   - `render.yaml`
   - `.gitignore`

### Étape 3: Déployer sur Render
1. Sur Render, cliquer sur **"New +"** → **"Web Service"**
2. Connecter votre repository GitHub
3. Render détecte automatiquement le `render.yaml`
4. Cliquer sur **"Create Web Service"**
5. Attendre le déploiement (2-3 minutes)

### Étape 4: Récupérer l'URL du backend
Une fois déployé, vous obtiendrez une URL comme:
```
https://uco-backend.onrender.com
```

### Étape 5: Configurer le Frontend
Dans votre fichier `src/App.jsx`, modifier la ligne:
```javascript
const API_BASE_URL = 'https://uco-backend.onrender.com/api';
```

---

## Installation Locale (Développement)

### Prérequis
- Node.js 18 ou supérieur
- npm

### Étapes

1. **Cloner/Copier les fichiers**
```bash
mkdir uco-backend
cd uco-backend
# Copier server.js, package.json, etc.
```

2. **Installer les dépendances**
```bash
npm install
```

3. **Démarrer le serveur**
```bash
npm start
```

Le serveur démarre sur `http://localhost:3001`

---

## API Endpoints

### Authentification
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | `/api/auth/admin` | Login admin |
| POST | `/api/auth/collector` | Login collecteur |
| POST | `/api/auth/operator` | Login opérateur |
| POST | `/api/auth/restaurant` | Login restaurant |

### Collecteurs
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | `/api/collectors/register` | Inscription |
| GET | `/api/collectors/pending` | Liste en attente |
| GET | `/api/collectors/approved` | Liste approuvés |
| POST | `/api/collectors/:id/approve` | Approuver |
| POST | `/api/collectors/:id/reject` | Refuser |
| DELETE | `/api/collectors/:id` | Supprimer |

### Restaurants
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | `/api/restaurants/register` | Inscription |
| GET | `/api/restaurants/pending` | Liste en attente |
| GET | `/api/restaurants` | Liste approuvés |
| GET | `/api/restaurants/qr/:qrCode` | Par QR code |
| POST | `/api/restaurants/:id/approve` | Approuver |
| POST | `/api/restaurants` | Ajouter (admin) |
| PUT | `/api/restaurants/:id` | Modifier |
| DELETE | `/api/restaurants/:id` | Supprimer |

### Collectes
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | `/api/collections` | Créer une collecte |
| GET | `/api/collections` | Liste des collectes |
| GET | `/api/collections/collector/:id` | Par collecteur |
| GET | `/api/collections/:id` | Détail |

### Autres
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/statistics` | Statistiques |
| GET | `/api/health` | Vérification santé |

---

## Identifiants par défaut

| Rôle | Email | Mot de passe |
|------|-------|--------------|
| Admin | contact@uco-and-co.com | 30Septembre2006A$ |

---

## Support

En cas de problème:
1. Vérifier les logs sur Render (Dashboard → Logs)
2. Tester l'endpoint `/api/health`
3. Vérifier que Node.js >= 18 est installé
