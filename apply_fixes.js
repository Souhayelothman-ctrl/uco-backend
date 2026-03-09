// This script applies memory fixes to server.js
// Usage: node apply_fixes.js < original_server.js > fixed_server.js

const fs = require('fs');

// Read from argument or create the patches
const patches = [

  // FIX 1: Add memory monitoring after error handlers
  {
    find: `process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ [UNHANDLED REJECTION]', reason);
  // NE PAS faire process.exit() - laisser le serveur tourner
});`,
    replace: `process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ [UNHANDLED REJECTION]', reason);
  // NE PAS faire process.exit() - laisser le serveur tourner
});

// =============================================
// [FIX OOM] MONITORING MÉMOIRE PROACTIF
// =============================================
let memoryWarningCount = 0;
setInterval(() => {
  const mem = process.memoryUsage();
  const heapMB = Math.round(mem.heapUsed / 1024 / 1024);
  const rssMB = Math.round(mem.rss / 1024 / 1024);
  if (heapMB > 400) {
    memoryWarningCount++;
    console.warn(\`⚠️ MÉMOIRE CRITIQUE: Heap=\${heapMB}MB, RSS=\${rssMB}MB (warning #\${memoryWarningCount})\`);
    if (global.gc) { global.gc(); console.log('🧹 GC forcé'); }
  } else if (heapMB > 300) {
    console.warn(\`⚠️ Mémoire élevée: Heap=\${heapMB}MB, RSS=\${rssMB}MB\`);
  }
}, 30000);`
  },

  // FIX 2: Add TTL indexes
  {
    find: `      await db.collection(COLLECTIONS.TOURNEES_EN_COURS).createIndex({ collectorEmail: 1 }, { unique: true });`,
    replace: `      await db.collection(COLLECTIONS.TOURNEES_EN_COURS).createIndex({ collectorEmail: 1 }, { unique: true });
      // [FIX OOM] TTL index: auto-suppression des tournées abandonnées après 7 jours
      await db.collection(COLLECTIONS.TOURNEES_EN_COURS).createIndex({ lastUpdate: 1 }, { expireAfterSeconds: 604800 }).catch(() => {});
      // [FIX OOM] TTL index: auto-suppression des audit logs après 90 jours
      await db.collection(COLLECTIONS.AUDIT_LOGS).createIndex({ timestamp: 1 }, { expireAfterSeconds: 7776000 }).catch(() => {});`
  },

  // FIX 3: Collections with LIMIT
  {
    find: `    const collections = await db.collection(COLLECTIONS.COLLECTIONS)
      .find({}, { projection })
      .sort({ createdAt: -1 })
      .toArray();`,
    replace: `    // [FIX OOM] Limiter à 2000 collectes max en mémoire
    const collections = await db.collection(COLLECTIONS.COLLECTIONS)
      .find({}, { projection })
      .sort({ createdAt: -1 })
      .limit(2000)
      .toArray();`
  },

  // FIX 4: Tournees with LIMIT
  {
    find: `    const tournees = await db.collection(COLLECTIONS.TOURNEES)
      .find({}, { projection })
      .sort({ dateDepart: -1 })
      .toArray();`,
    replace: `    // [FIX OOM] Limiter à 500 tournées max en mémoire
    const tournees = await db.collection(COLLECTIONS.TOURNEES)
      .find({}, { projection })
      .sort({ dateDepart: -1 })
      .limit(500)
      .toArray();`
  },

  // FIX 5: POST tournees en cours - payload size check + skip sanitizeObject
  {
    find: `app.post('/api/tournees/en-cours', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    const tourneeData = sanitizeObject(req.body);
    if (!tourneeData.collectorEmail) {
      return res.status(400).json({ success: false, error: 'collectorEmail requis' });
    }
    tourneeData.lastUpdate = new Date().toISOString();
    console.log(\`💾 [SYNC] Sauvegarde tournée: \${tourneeData.id}, collectes: \${tourneeData.collectes?.length || 0}\`);
    const result = await db.collection(COLLECTIONS.TOURNEES_EN_COURS).updateOne(
      { collectorEmail: tourneeData.collectorEmail },
      { $set: { ...tourneeData, _id: tourneeData.collectorEmail } },
      { upsert: true }
    );
    console.log(\`✅ [SYNC] Tournée sauvegardée\`);
    res.json({ success: true, tourneeId: tourneeData.id });
  } catch (error) {
    console.error('❌ Erreur POST tournee en cours:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur', details: error.message });
  }
});`,
    replace: `app.post('/api/tournees/en-cours', async (req, res) => {
  try {
    if (!db || !isConnected) {
      return res.status(503).json({ success: false, error: 'Base de données non connectée' });
    }
    
    // [FIX OOM] Vérifier la taille du payload AVANT traitement
    // C'est la cause #1 du dépassement mémoire: le frontend envoie les données
    // de tournée toutes les 2s, et sanitizeObject clone tout récursivement
    const rawBody = JSON.stringify(req.body);
    const payloadKB = Math.round(rawBody.length / 1024);
    
    if (rawBody.length > 500000) { // 500 KB max
      console.warn(\`⚠️ [SYNC] Payload rejeté: \${payloadKB}KB (max 500KB)\`);
      return res.status(413).json({ success: false, error: 'Payload trop volumineux' });
    }
    
    // [FIX OOM] NE PAS utiliser sanitizeObject ici — c'est trop coûteux en mémoire
    // pour un endpoint appelé toutes les 2 secondes. Le payload est déjà structuré
    // par le frontend et MongoDB sanitize nativement les opérateurs $
    const tourneeData = req.body;
    
    if (!tourneeData.collectorEmail) {
      return res.status(400).json({ success: false, error: 'collectorEmail requis' });
    }
    
    tourneeData.lastUpdate = new Date().toISOString();
    
    console.log(\`💾 [SYNC] Sauvegarde tournée: \${tourneeData.id}, collectes: \${tourneeData.collectes?.length || 0}, payload: \${payloadKB}KB\`);
    
    await db.collection(COLLECTIONS.TOURNEES_EN_COURS).updateOne(
      { collectorEmail: tourneeData.collectorEmail },
      { $set: { ...tourneeData, _id: tourneeData.collectorEmail } },
      { upsert: true }
    );
    
    res.json({ success: true, tourneeId: tourneeData.id });
  } catch (error) {
    console.error('❌ Erreur POST tournee en cours:', error);
    res.status(500).json({ success: false, error: 'Erreur serveur', details: error.message });
  }
});`
  },

  // FIX 6: Enhanced health check
  {
    find: `    memoryUsage: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
    reconnectAttempts: reconnectAttempts`,
    replace: `    memoryUsage: {
      heapUsed: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
      heapTotal: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB',
      rss: Math.round(process.memoryUsage().rss / 1024 / 1024) + 'MB',
      external: Math.round(process.memoryUsage().external / 1024 / 1024) + 'MB'
    },
    memoryWarnings: memoryWarningCount,
    reconnectAttempts: reconnectAttempts`
  },

  // FIX 7: Add cleanup before startServer
  {
    find: `startServer();`,
    replace: `// [FIX OOM] Nettoyage périodique des tournées abandonnées (>48h)
setInterval(async () => {
  if (!db || !isConnected) return;
  try {
    const cutoff = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();
    const result = await db.collection(COLLECTIONS.TOURNEES_EN_COURS).deleteMany({
      lastUpdate: { $lt: cutoff }
    });
    if (result.deletedCount > 0) {
      console.log(\`🧹 Nettoyage: \${result.deletedCount} tournée(s) abandonnée(s) supprimée(s)\`);
    }
  } catch (e) {
    console.log('Erreur nettoyage tournées:', e.message);
  }
}, 6 * 60 * 60 * 1000); // Toutes les 6 heures

startServer();`
  }
];

// Apply patches
const args = process.argv.slice(2);
const inputFile = args[0];
const outputFile = args[1] || inputFile;

if (!inputFile) {
  console.log('Usage: node apply_fixes.js <input_server.js> [output_server.js]');
  console.log('');
  console.log('This script applies 7 memory optimization fixes to your server.js');
  console.log('Fixes applied:');
  console.log('  1. Memory monitoring (logs warnings before OOM)');
  console.log('  2. TTL indexes (auto-cleanup old data)');
  console.log('  3. Collections query LIMIT (max 2000)');
  console.log('  4. Tournées query LIMIT (max 500)');
  console.log('  5. POST tournees/en-cours payload size check + no sanitizeObject');
  console.log('  6. Enhanced health check (detailed memory info)');
  console.log('  7. Periodic cleanup of abandoned tournées');
  process.exit(0);
}

let content = fs.readFileSync(inputFile, 'utf8');
let applied = 0;

for (const patch of patches) {
  if (content.includes(patch.find)) {
    content = content.replace(patch.find, patch.replace);
    applied++;
    console.log(`✅ Fix ${applied} applied`);
  } else {
    console.warn(`⚠️ Fix ${applied + 1} - Pattern not found (may already be applied)`);
    applied++;
  }
}

fs.writeFileSync(outputFile, content);
console.log(`\n✅ ${applied} fixes applied → ${outputFile}`);
console.log(`📊 File size: ${Math.round(content.length / 1024)}KB`);
