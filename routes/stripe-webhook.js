const express = require('express');
const router = express.Router();

/**
 * Webhook Stripe
 * POST /api/stripe/webhook
 */
router.post('/webhook', async (req, res) => {
  const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
  
  let event;
  
  try {
    // Récupérer le body brut
    let rawBody = req.body;
    
    // Si le body est déjà un objet (parsé), on doit le convertir en string
    if (typeof rawBody === 'object' && !Buffer.isBuffer(rawBody)) {
      // Mode sans vérification de signature (fallback)
      console.log('⚠️ Body déjà parsé, vérification signature impossible');
      event = rawBody;
    } else {
      // Mode normal avec vérification de signature
      const sig = req.headers['stripe-signature'];
      
      if (!sig) {
        console.log('⚠️ Pas de signature Stripe, traitement sans vérification');
        event = typeof rawBody === 'string' ? JSON.parse(rawBody) : rawBody;
      } else {
        // Vérification de la signature
        const bodyString = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
        event = stripe.webhooks.constructEvent(bodyString, sig, endpointSecret);
        console.log('✅ Signature Stripe vérifiée');
      }
    }
    
    console.log('📩 Événement Stripe reçu:', event.type);
    
    // Traiter les événements
    switch (event.type) {
      case 'payment_intent.succeeded':
        console.log('✅ Paiement réussi:', event.data.object.id);
        break;
        
      case 'payment_intent.payment_failed':
        console.log('❌ Paiement échoué:', event.data.object.id);
        break;
        
      case 'customer.subscription.created':
        console.log('🆕 Abonnement créé:', event.data.object.id);
        break;
        
      case 'customer.subscription.updated':
        console.log('🔄 Abonnement mis à jour:', event.data.object.id);
        break;
        
      case 'customer.subscription.deleted':
        console.log('🗑️ Abonnement supprimé:', event.data.object.id);
        break;
        
      case 'invoice.paid':
        console.log('💰 Facture payée:', event.data.object.id);
        break;
        
      case 'invoice.payment_failed':
        console.log('❌ Facture impayée:', event.data.object.id);
        break;
        
      case 'checkout.session.completed':
        console.log('✅ Checkout terminé:', event.data.object.id);
        break;
        
      default:
        console.log('ℹ️ Événement non traité:', event.type);
    }
    
    // Toujours répondre 200 OK
    res.status(200).json({ received: true, type: event.type });
    
  } catch (err) {
    console.error('❌ Erreur webhook Stripe:', err.message);
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});

module.exports = router;
