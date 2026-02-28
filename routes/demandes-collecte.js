const express = require('express');
const router = express.Router();

// Stockage en mémoire (sera remplacé par MongoDB si configuré)
let demandesCollecte = [];

// GET - Récupérer toutes les demandes
router.get('/', (req, res) => {
  try {
    const urgenceOrder = { tres_urgente: 0, urgente: 1, normale: 2 };
    const sorted = [...demandesCollecte].sort((a, b) => {
      if (urgenceOrder[a.urgence] !== urgenceOrder[b.urgence]) {
        return urgenceOrder[a.urgence] - urgenceOrder[b.urgence];
      }
      return new Date(a.dateCreation) - new Date(b.dateCreation);
    });
    res.json(sorted);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST - Créer une demande
router.post('/', (req, res) => {
  try {
    const nouvelleDemande = {
      id: req.body.id || `demande_${Date.now()}`,
      ...req.body,
      dateCreation: req.body.dateCreation || new Date().toISOString(),
      status: req.body.status || 'en_attente'
    };
    
    // Vérifier si demande existe déjà pour ce restaurant
    const existe = demandesCollecte.find(d => 
      d.restaurantId === nouvelleDemande.restaurantId && d.status === 'en_attente'
    );
    
    if (existe) {
      const index = demandesCollecte.findIndex(d => d.id === existe.id);
      demandesCollecte[index] = { ...existe, ...nouvelleDemande, id: existe.id };
      return res.json({ success: true, demande: demandesCollecte[index], updated: true });
    }
    
    demandesCollecte.push(nouvelleDemande);
    console.log('🆕 Nouvelle demande:', nouvelleDemande.id, '- Urgence:', nouvelleDemande.urgence);
    res.status(201).json({ success: true, demande: nouvelleDemande });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT - Mettre à jour une demande
router.put('/:id', (req, res) => {
  try {
    const index = demandesCollecte.findIndex(d => d.id === req.params.id);
    if (index === -1) {
      return res.status(404).json({ error: 'Demande non trouvée' });
    }
    
    demandesCollecte[index] = {
      ...demandesCollecte[index],
      ...req.body,
      dateModification: new Date().toISOString()
    };
    
    console.log('✏️ Demande mise à jour:', req.params.id, '- Status:', demandesCollecte[index].status);
    res.json({ success: true, demande: demandesCollecte[index] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE - Supprimer une demande
router.delete('/:id', (req, res) => {
  try {
    const index = demandesCollecte.findIndex(d => d.id === req.params.id);
    if (index === -1) {
      return res.status(404).json({ error: 'Demande non trouvée' });
    }
    
    const deleted = demandesCollecte.splice(index, 1)[0];
    console.log('🗑️ Demande supprimée:', req.params.id);
    res.json({ success: true, deleted });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
