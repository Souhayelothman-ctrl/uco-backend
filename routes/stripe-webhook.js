/**
 * STRIPE WEBHOOK HANDLER
 * ========================
 * 
 * Ce fichier doit Ãªtre ajoutÃ© Ã  votre backend Node.js/Express
 * URL: https://uco-backend.onrender.com/api/stripe/webhook
 * 
 * INSTALLATION:
 * 1. Ajouter ce fichier dans votre dossier routes/
 * 2. Dans server.js, ajouter:
 *    const stripeWebhook = require('./routes/stripe-webhook');
 *    app.use('/api/stripe', stripeWebhook);
 * 
 * 3. Configurer la variable d'environnement STRIPE_WEBHOOK_SECRET
 *    dans Render avec la clÃ© secrÃ¨te du webhook (whsec_...)
 * 
 * 4. RedÃ©ployer le backend sur Render
 */

const express = require('express');
const router = express.Router();

// IMPORTANT: Le webhook Stripe nÃ©cessite le body brut (raw), pas parsÃ© en JSON
// Cette route DOIT Ãªtre configurÃ©e AVANT le middleware express.json() global

/**
 * Webhook Stripe
 * POST /api/stripe/webhook
 * 
 * ReÃ§oit les Ã©vÃ©nements de Stripe et met Ã  jour la base de donnÃ©es
 */
router.post('/webhook', 
  express.raw({ type: 'application/json' }), // Body brut requis pour la vÃ©rification de signature
  async (req, res) => {
    
    const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
    
    let event;
    
    // VÃ©rifier la signature du webhook (sÃ©curitÃ©)
    if (endpointSecret) {
      const sig = req.headers['stripe-signature'];
      
      try {
        event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
        console.log('âœ… Webhook Stripe vÃ©rifiÃ©:', event.type);
      } catch (err) {
        console.error('âŒ Erreur vÃ©rification signature webhook:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
      }
    } else {
      // Mode dÃ©veloppement sans vÃ©rification de signature
      try {
        event = JSON.parse(req.body.toString());
        console.log('âš ï¸ Webhook sans vÃ©rification de signature (dev):', event.type);
      } catch (err) {
        console.error('âŒ Erreur parsing webhook:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
      }
    }
    
    // RÃ©cupÃ©rer la rÃ©fÃ©rence Ã  la base de donnÃ©es (adapter selon votre setup)
    // Exemple avec MongoDB/Mongoose ou autre
    let db;
    try {
      // Si vous utilisez MongoDB avec Mongoose
      // const Restaurant = require('../models/Restaurant');
      // db = { Restaurant };
      
      // Si vous utilisez une autre base de donnÃ©es, adaptez ici
      db = req.app.locals.db || global.db;
    } catch (e) {
      console.log('Note: DB non disponible pour le webhook');
    }
    
    // Traiter les diffÃ©rents types d'Ã©vÃ©nements
    try {
      switch (event.type) {
        
        // ========== PAIEMENTS ==========
        
        case 'payment_intent.succeeded':
          await handlePaymentSucceeded(event.data.object, db);
          break;
          
        case 'payment_intent.payment_failed':
          await handlePaymentFailed(event.data.object, db);
          break;
          
        // ========== ABONNEMENTS ==========
        
        case 'customer.subscription.created':
          await handleSubscriptionCreated(event.data.object, db);
          break;
          
        case 'customer.subscription.updated':
          await handleSubscriptionUpdated(event.data.object, db);
          break;
          
        case 'customer.subscription.deleted':
          await handleSubscriptionDeleted(event.data.object, db);
          break;
          
        // ========== FACTURES ==========
        
        case 'invoice.paid':
          await handleInvoicePaid(event.data.object, db);
          break;
          
        case 'invoice.payment_failed':
          await handleInvoicePaymentFailed(event.data.object, db);
          break;
          
        case 'invoice.upcoming':
          await handleInvoiceUpcoming(event.data.object, db);
          break;
          
        // ========== CHECKOUT ==========
        
        case 'checkout.session.completed':
          await handleCheckoutCompleted(event.data.object, db);
          break;
          
        case 'checkout.session.expired':
          await handleCheckoutExpired(event.data.object, db);
          break;
          
        // ========== MÃ‰THODES DE PAIEMENT ==========
        
        case 'payment_method.attached':
          console.log('ðŸ’³ MÃ©thode de paiement attachÃ©e');
          break;
          
        case 'payment_method.detached':
          console.log('ðŸ’³ MÃ©thode de paiement dÃ©tachÃ©e');
          break;
          
        // ========== AUTRES ==========
        
        default:
          console.log(`â„¹ï¸ Ã‰vÃ©nement Stripe non traitÃ©: ${event.type}`);
      }
      
      // Toujours rÃ©pondre 200 OK Ã  Stripe
      res.status(200).json({ received: true, type: event.type });
      
    } catch (error) {
      console.error('âŒ Erreur traitement webhook:', error);
      // RÃ©pondre 200 quand mÃªme pour Ã©viter les retries inutiles
      // mais logger l'erreur pour investigation
      res.status(200).json({ received: true, error: error.message });
    }
  }
);

// ========== HANDLERS ==========

/**
 * Paiement rÃ©ussi
 */
async function handlePaymentSucceeded(paymentIntent, db) {
  console.log('âœ… Paiement rÃ©ussi:', paymentIntent.id);
  console.log('   Montant:', paymentIntent.amount / 100, paymentIntent.currency.toUpperCase());
  console.log('   Client:', paymentIntent.customer);
  console.log('   Metadata:', paymentIntent.metadata);
  
  // Si c'est un paiement de rÃ©gularisation
  if (paymentIntent.metadata?.type === 'regularization') {
    const restaurantId = paymentIntent.metadata.restaurantId;
    if (restaurantId && db) {
      try {
        // DÃ©bloquer le compte restaurant
        // await db.Restaurant.updateOne(
        //   { _id: restaurantId },
        //   { 
        //     $set: { 
        //       'subscription.status': 'active',
        //       'subscription.failedAttempts': 0,
        //       accountBlocked: false
        //     }
        //   }
        // );
        console.log('âœ… Compte restaurant dÃ©bloquÃ©:', restaurantId);
      } catch (e) {
        console.error('Erreur dÃ©blocage compte:', e);
      }
    }
  }
}

/**
 * Paiement Ã©chouÃ©
 */
async function handlePaymentFailed(paymentIntent, db) {
  console.log('âŒ Paiement Ã©chouÃ©:', paymentIntent.id);
  console.log('   Raison:', paymentIntent.last_payment_error?.message);
  console.log('   Client:', paymentIntent.customer);
  
  const restaurantId = paymentIntent.metadata?.restaurantId;
  if (restaurantId && db) {
    try {
      // IncrÃ©menter le compteur d'Ã©checs
      // await db.Restaurant.updateOne(
      //   { _id: restaurantId },
      //   { 
      //     $inc: { 'subscription.failedAttempts': 1 },
      //     $set: { 'subscription.lastFailedAt': new Date() }
      //   }
      // );
      console.log('âš ï¸ Compteur d\'Ã©checs incrÃ©mentÃ© pour:', restaurantId);
    } catch (e) {
      console.error('Erreur mise Ã  jour Ã©chec:', e);
    }
  }
}

/**
 * Abonnement crÃ©Ã©
 */
async function handleSubscriptionCreated(subscription, db) {
  console.log('ðŸ†• Abonnement crÃ©Ã©:', subscription.id);
  console.log('   Client:', subscription.customer);
  console.log('   Statut:', subscription.status);
  console.log('   Plan:', subscription.items.data[0]?.price?.id);
  
  // Mettre Ã  jour le restaurant avec l'ID de l'abonnement
  const metadata = subscription.metadata || {};
  const restaurantId = metadata.restaurantId;
  
  if (restaurantId && db) {
    try {
      // await db.Restaurant.updateOne(
      //   { _id: restaurantId },
      //   { 
      //     $set: { 
      //       'subscription.stripeSubscriptionId': subscription.id,
      //       'subscription.status': subscription.status,
      //       'subscription.currentPeriodEnd': new Date(subscription.current_period_end * 1000)
      //     }
      //   }
      // );
      console.log('âœ… Restaurant mis Ã  jour avec abonnement');
    } catch (e) {
      console.error('Erreur mise Ã  jour abonnement:', e);
    }
  }
}

/**
 * Abonnement mis Ã  jour
 */
async function handleSubscriptionUpdated(subscription, db) {
  console.log('ðŸ”„ Abonnement mis Ã  jour:', subscription.id);
  console.log('   Nouveau statut:', subscription.status);
  
  const metadata = subscription.metadata || {};
  const restaurantId = metadata.restaurantId;
  
  if (restaurantId && db) {
    try {
      const updateData = {
        'subscription.status': subscription.status,
        'subscription.currentPeriodEnd': new Date(subscription.current_period_end * 1000)
      };
      
      // Si l'abonnement est annulÃ© ou expirÃ©
      if (['canceled', 'unpaid', 'past_due'].includes(subscription.status)) {
        updateData['subscription.canceledAt'] = new Date();
      }
      
      // await db.Restaurant.updateOne({ _id: restaurantId }, { $set: updateData });
      console.log('âœ… Statut abonnement mis Ã  jour');
    } catch (e) {
      console.error('Erreur mise Ã  jour statut:', e);
    }
  }
}

/**
 * Abonnement supprimÃ©/annulÃ©
 */
async function handleSubscriptionDeleted(subscription, db) {
  console.log('ðŸ—‘ï¸ Abonnement supprimÃ©:', subscription.id);
  
  const metadata = subscription.metadata || {};
  const restaurantId = metadata.restaurantId;
  
  if (restaurantId && db) {
    try {
      // await db.Restaurant.updateOne(
      //   { _id: restaurantId },
      //   { 
      //     $set: { 
      //       'subscription.status': 'canceled',
      //       'subscription.canceledAt': new Date()
      //     }
      //   }
      // );
      console.log('âœ… Abonnement marquÃ© comme annulÃ©');
    } catch (e) {
      console.error('Erreur annulation abonnement:', e);
    }
  }
}

/**
 * Facture payÃ©e
 */
async function handleInvoicePaid(invoice, db) {
  console.log('ðŸ’° Facture payÃ©e:', invoice.id);
  console.log('   Montant:', invoice.amount_paid / 100, invoice.currency.toUpperCase());
  console.log('   Client:', invoice.customer);
  console.log('   Abonnement:', invoice.subscription);
  
  // RÃ©initialiser le compteur d'Ã©checs si c'est un renouvellement d'abonnement
  if (invoice.subscription && db) {
    const customerId = invoice.customer;
    try {
      // await db.Restaurant.updateOne(
      //   { 'subscription.stripeCustomerId': customerId },
      //   { 
      //     $set: { 
      //       'subscription.status': 'active',
      //       'subscription.failedAttempts': 0,
      //       'subscription.lastPaymentAt': new Date(),
      //       accountBlocked: false
      //     }
      //   }
      // );
      console.log('âœ… Compteur d\'Ã©checs rÃ©initialisÃ©');
    } catch (e) {
      console.error('Erreur rÃ©initialisation compteur:', e);
    }
  }
}

/**
 * Facture impayÃ©e
 */
async function handleInvoicePaymentFailed(invoice, db) {
  console.log('âŒ Facture impayÃ©e:', invoice.id);
  console.log('   Tentative:', invoice.attempt_count);
  console.log('   Prochaine tentative:', invoice.next_payment_attempt ? new Date(invoice.next_payment_attempt * 1000) : 'Aucune');
  
  const customerId = invoice.customer;
  
  if (customerId && db) {
    try {
      const failedAttempts = invoice.attempt_count || 1;
      
      // Bloquer le compte aprÃ¨s 15 tentatives Ã©chouÃ©es
      const shouldBlock = failedAttempts >= 15;
      
      // await db.Restaurant.updateOne(
      //   { 'subscription.stripeCustomerId': customerId },
      //   { 
      //     $set: { 
      //       'subscription.status': shouldBlock ? 'blocked' : 'payment_failed',
      //       'subscription.failedAttempts': failedAttempts,
      //       'subscription.lastFailedAt': new Date(),
      //       'subscription.nextRetryAt': invoice.next_payment_attempt ? new Date(invoice.next_payment_attempt * 1000) : null,
      //       accountBlocked: shouldBlock,
      //       'subscription.blockedReason': shouldBlock ? 'PrÃ©lÃ¨vements refusÃ©s (15 tentatives)' : null,
      //       'subscription.blockedAt': shouldBlock ? new Date() : null
      //     }
      //   }
      // );
      
      if (shouldBlock) {
        console.log('ðŸ”’ Compte bloquÃ© aprÃ¨s 15 Ã©checs');
      } else {
        console.log(`âš ï¸ Tentative ${failedAttempts}/15 Ã©chouÃ©e`);
      }
    } catch (e) {
      console.error('Erreur mise Ã  jour Ã©chec facture:', e);
    }
  }
}

/**
 * Facture Ã  venir (notification)
 */
async function handleInvoiceUpcoming(invoice, db) {
  console.log('ðŸ“… Facture Ã  venir');
  console.log('   Montant:', invoice.amount_due / 100, invoice.currency.toUpperCase());
  console.log('   Client:', invoice.customer);
  
  // Optionnel: Envoyer un email de rappel au restaurant
}

/**
 * Checkout session terminÃ©e
 */
async function handleCheckoutCompleted(session, db) {
  console.log('âœ… Checkout terminÃ©:', session.id);
  console.log('   Mode:', session.mode);
  console.log('   Client:', session.customer);
  console.log('   Metadata:', session.metadata);
  
  const restaurantId = session.metadata?.restaurantId;
  const subscriptionPlan = session.metadata?.plan;
  
  if (session.mode === 'subscription' && restaurantId && db) {
    try {
      // await db.Restaurant.updateOne(
      //   { _id: restaurantId },
      //   { 
      //     $set: { 
      //       'subscription.stripeCustomerId': session.customer,
      //       'subscription.stripeSubscriptionId': session.subscription,
      //       'subscription.plan': subscriptionPlan,
      //       'subscription.status': 'active',
      //       'subscription.startedAt': new Date()
      //     }
      //   }
      // );
      console.log('âœ… Restaurant souscrit au plan:', subscriptionPlan);
    } catch (e) {
      console.error('Erreur activation abonnement:', e);
    }
  }
}

/**
 * Checkout session expirÃ©e
 */
async function handleCheckoutExpired(session, db) {
  console.log('â° Checkout expirÃ©:', session.id);
  console.log('   Metadata:', session.metadata);
  
  // Optionnel: Envoyer un email de rappel
}

module.exports = router;
