// =============================================
// utils/bordereau-pdf.js — Génération SERVEUR du bordereau d'enlèvement
// Reproduit la mise en page du bordereau html2pdf (App.jsx generateBordereauPDF)
// en pdfkit : page 1 = bordereau d'enlèvement, page 2 = autodéclaration ISCC
// (texte officiel verbatim, © ISCC System GmbH, Version 2.0).
//
// Usage :
//   const { generateBordereauPDF } = require('./utils/bordereau-pdf');
//   const { buffer, filename, numeroOrdre } = await generateBordereauPDF(col, resto, { logoPng: Buffer|null });
// =============================================
const PDFDocument = require('pdfkit');

// ---------- Couleurs (identiques au HTML) ----------
const C = {
  vert: '#4a7c59', vertFonce: '#1b5e20', vertClair: '#e8f5e9', vertTexte: '#2e7d32',
  orange: '#e65100', orangeClair: '#fff8e1', gris: '#666', grisClair: '#f5f5f5',
  grisLigne: '#e0e0e0', grisTexte: '#999', grisFond: '#fafafa', noir: '#000', blanc: '#fff'
};

// ---------- Helpers de formatage (portés depuis App.jsx) ----------
const formatAdresse = (adr) => {
  if (typeof adr === 'string') return adr;
  if (!adr) return '';
  return `${adr.numero || ''} ${adr.nature || ''} ${adr.nom || ''}, ${adr.cp || ''} ${adr.ville || ''}, ${adr.pays || ''}`
    .replace(/\s+/g, ' ').replace(/,\s*,/g, ',').replace(/,\s*$/, '').trim();
};
const formatGerant = (g) => {
  if (typeof g === 'string') return g;
  if (!g) return '';
  return [g.civilite, g.prenom, g.nom].filter(Boolean).join(' ').trim();
};
const DIAL = { FR: '+33', BE: '+32', CH: '+41', LU: '+352', ES: '+34', IT: '+39', DE: '+49', PT: '+351', NL: '+31' };
const formatPhone = (tel) => {
  if (!tel) return '';
  if (typeof tel === 'string') return tel;
  if (typeof tel === 'object') {
    if (tel.countryCode && tel.number) return `${DIAL[tel.countryCode] || ''} ${tel.number}`.trim();
    if (tel.number) return String(tel.number);
    return '';
  }
  return String(tel);
};
const parseDate = (s) => { if (!s) return new Date(); const d = new Date(s); return isNaN(d.getTime()) ? new Date() : d; };
const pad2 = (n) => String(n).padStart(2, '0');
const fmtDate = (d) => `${pad2(d.getDate())}/${pad2(d.getMonth() + 1)}/${d.getFullYear()}`;
const fmtTime = (d) => `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;

// data URI base64 → Buffer (PNG/JPEG), null si absent/invalide
const dataUriToBuffer = (uri) => {
  if (!uri || typeof uri !== 'string') return null;
  const m = uri.match(/^data:(image\/(?:png|jpeg|jpg));base64,(.+)$/);
  if (!m) return null;
  try { return Buffer.from(m[2], 'base64'); } catch (e) { return null; }
};

// Numéro d'ordre AAMMJJ-COLXXX-XX (même logique que le frontend)
const computeNumeroOrdre = (col) => {
  let n = col.numeroOrdre;
  if (!n || (n.includes('-') && n.length > 20)) {
    const d = parseDate(col.date);
    const colNum = parseInt(col.collectorNumber) || 0;
    const colId = colNum > 0 ? `COL${String(colNum).padStart(3, '0')}` : 'COL001';
    n = `${String(d.getFullYear()).slice(-2)}${pad2(d.getMonth() + 1)}${pad2(d.getDate())}-${colId}-${pad2(Math.floor(Math.random() * 99) + 1)}`;
  }
  return n;
};

// =============================================
// GÉNÉRATION
// =============================================
async function generateBordereauPDF(col, restaurant, opts = {}) {
  const resto = restaurant || col.restaurant || {};
  const logoPng = opts.logoPng || null; // Buffer PNG du logo (optionnel)

  const numeroOrdre = computeNumeroOrdre(col);
  const colDate = parseDate(col.date);
  const dateFormatted = fmtDate(colDate);
  const timeFormatted = fmtTime(colDate);
  const adr = formatAdresse(resto.adresse);
  const siretFormatted = resto.siret
    ? (typeof resto.siret === 'string' ? resto.siret.replace(/(\d{3})(\d{3})(\d{3})(\d{5})/, '$1 $2 $3 $4') : String(resto.siret))
    : '-';
  const gpsInfo = resto.gps?.latitude && resto.gps?.longitude ? `${resto.gps.latitude}, ${resto.gps.longitude}` : '-';
  const colNum = parseInt(col.collectorNumber) || 0;
  const collecteurId = colNum > 0 ? `COL-${String(colNum).padStart(3, '0')}` : '-';
  const collecteurNom = col.collectorName || '-';

  let paymentInfo;
  if (col.paymentModes?.nonPaye) paymentInfo = 'NON PAYÉ (Report)';
  else {
    const modes = [];
    if (col.paymentModes?.cb) modes.push(`CB: ${col.paymentAmounts?.cb || col.price}€`);
    if (col.paymentModes?.especes) modes.push(`Espèces: ${col.paymentAmounts?.especes || col.price}€`);
    if (col.paymentModes?.virement) modes.push(`Virement: ${col.paymentAmounts?.virement || col.price}€`);
    paymentInfo = modes.length ? modes.join(' | ') : `${col.price || 0}€`;
  }
  let condInfo = col.conditionnement?.type || '-';
  if (col.conditionnement?.type === 'Fûts') condInfo = `Fûts (${col.conditionnement.nombreFuts || 0} × ${col.conditionnement.volumeFut || 0}L)`;

  const sigCol = dataUriToBuffer(col.colSig || col.colSignature);
  const sigResto = dataUriToBuffer(col.restoSig || col.restoSignature);

  const filename = `Bordereau-${numeroOrdre}-${(resto.enseigne || 'Restaurant').replace(/[^a-zA-Z0-9]/g, '_')}.pdf`;

  // ---- Document A4, marges 8mm haut/bas, 10mm gauche/droite (comme le HTML) ----
  const mm = 72 / 25.4;
  const doc = new PDFDocument({ size: 'A4', margins: { top: 8 * mm, bottom: 8 * mm, left: 10 * mm, right: 10 * mm }, info: { Title: `Bordereau ${numeroOrdre}`, Author: 'UCO AND CO' } });
  const chunks = [];
  doc.on('data', (c) => chunks.push(c));
  const done = new Promise((resolve, reject) => { doc.on('end', () => resolve(Buffer.concat(chunks))); doc.on('error', reject); });

  const L = doc.page.margins.left, R = doc.page.width - doc.page.margins.right, W = R - L;
  const year = new Date().getFullYear();

  // ---------- primitives ----------
  const text = (str, x, y, o = {}) => {
    doc.font(o.bold ? 'Helvetica-Bold' : (o.mono ? 'Courier-Bold' : 'Helvetica')).fontSize(o.size || 9).fillColor(o.color || '#333');
    doc.text(String(str ?? ''), x, y, { width: o.width, align: o.align || 'left', lineGap: o.lineGap || 0 });
    return doc.y;
  };
  const rect = (x, y, w, h, fill, stroke, lw = 0.5) => {
    if (fill && stroke) doc.rect(x, y, w, h).lineWidth(lw).fillAndStroke(fill, stroke);
    else if (fill) doc.rect(x, y, w, h).fill(fill);
    else if (stroke) doc.rect(x, y, w, h).lineWidth(lw).stroke(stroke);
  };
  const hline = (x1, x2, y, color = C.grisLigne, lw = 0.5) => doc.moveTo(x1, y).lineTo(x2, y).lineWidth(lw).stroke(color);

  // En-tête commun (logo + n° d'ordre)
  const header = (y, sub, lineColor) => {
    let hy = y;
    if (logoPng) { try { doc.image(logoPng, L, hy, { height: 26 }); hy += 28; } catch (e) { hy = text('UCO AND CO', L, hy, { bold: true, size: 16, color: '#6bb44a' }) + 2; } }
    else hy = text('UCO AND CO', L, hy, { bold: true, size: 16, color: '#6bb44a' }) + 2;
    sub.forEach(s => { hy = text(s, L, hy, { size: 7, color: C.gris }); });
    // bloc n° d'ordre à droite
    const bw = 130, bh = 34;
    rect(R - bw, y, bw, bh, C.vertClair);
    text("N° D'ORDRE", R - bw + 8, y + 5, { size: 7, color: C.gris });
    text(numeroOrdre, R - bw + 8, y + 15, { mono: true, size: 12, color: C.vertTexte });
    const bottom = Math.max(hy, y + bh) + 6;
    hline(L, R, bottom, lineColor, 2);
    return bottom + 8;
  };

  // Section encadrée avec titre vert et tableau clé/valeur (page 1)
  const section = (y, title, rows, labelW = W * 0.25) => {
    const th = 15;
    let ry = y + th;
    const heights = rows.map(r => r.h || 13);
    const total = th + heights.reduce((a, b) => a + b, 0);
    rect(L, y, W, total, null, C.vert, 0.8);
    rect(L, y, W, th, C.vert);
    text(title, L + 8, y + 4, { bold: true, size: 8, color: C.blanc });
    rows.forEach((r, i) => {
      const h = heights[i];
      rect(L + 0.4, ry, labelW, h, r.labelBg || C.grisClair);
      if (r.valueBg) rect(L + labelW, ry, W - labelW - 0.4, h, r.valueBg);
      if (i > 0) hline(L, R, ry);
      text(r.label, L + 8, ry + (h - (r.labelSize || 8)) / 2 - 1, { size: r.labelSize || 8, bold: !!r.labelBold, color: r.labelColor || '#333' });
      text(r.value, L + labelW + 8, ry + (h - (r.valueSize || 8)) / 2 - 1, { size: r.valueSize || 8, bold: !!r.valueBold, mono: !!r.mono, color: r.valueColor || '#333', width: W - labelW - 16 });
      ry += h;
    });
    return y + total + 7;
  };

  const footer = (pageNo) => {
    const fy = doc.page.height - doc.page.margins.bottom - 12;
    hline(L, R, fy, '#ddd');
    text(`UCO AND CO © ${year} | Bordereau N° ${numeroOrdre} | Page ${pageNo}/2`, L, fy + 4, { size: 6.5, color: C.grisTexte, width: W, align: 'center' });
  };

  // =====================================================
  // PAGE 1 — BORDEREAU D'ENLÈVEMENT
  // =====================================================
  let y = header(doc.page.margins.top, ['119 Route de La Varenne, 28270 Rueil La Gadelière', 'Tél: 06 10 25 10 63 | SIRET: 953 315 041 00012'], C.vert);

  // Titre
  rect(L, y, W, 32, C.vert);
  text("BORDEREAU D'ENLÈVEMENT DE DÉCHETS", L, y + 6, { bold: true, size: 13, color: C.blanc, width: W, align: 'center' });
  text("Bon d'achat - Exemplaire Collecteur", L, y + 21, { size: 8, color: '#c8e6c9', width: W, align: 'center' });
  y += 40;

  y = section(y, 'DÉSIGNATION DU DÉCHET', [
    { label: 'Dénomination', value: 'H.A.U. (Huile Alimentaire Usagée)' },
    { label: 'Code déchet', value: '20 01 25 (non dangereux)' },
    { label: 'Valeur GES des HAU', value: '0 g éq CO²/kg' }
  ], W * 0.30);

  y = section(y, 'PRODUCTEUR / POINT DE COLLECTE', [
    { label: 'Enseigne', value: resto.enseigne || 'Non renseigné', valueBold: true, valueSize: 10, h: 15 },
    { label: 'Société', value: resto.societe || '-' },
    { label: 'SIRET', value: siretFormatted, mono: true },
    { label: 'Type', value: resto.typeProducteur || '-' },
    { label: 'Adresse', value: adr || 'Non renseignée' },
    { label: 'GPS', value: gpsInfo, valueSize: 7 }
  ]);

  y = section(y, 'DÉTAILS DE LA COLLECTE', [
    { label: 'Date / Heure', value: `${dateFormatted} à ${timeFormatted}`, valueBold: true },
    { label: 'Conditionnement', value: condInfo },
    { label: 'Volume collecté', value: `${col.volume || 0} Litres`, labelBg: C.vertClair, labelBold: true, labelColor: C.vertFonce, valueBold: true, valueSize: 13, valueColor: C.vertFonce, h: 19 },
    { label: 'Prix unitaire', value: `${resto.prixLitre || '-'} €/L` },
    { label: 'Montant total', value: `${col.price || 0} €`, labelBg: C.orangeClair, labelBold: true, labelColor: C.orange, valueBold: true, valueSize: 13, valueColor: C.orange, h: 19 },
    { label: 'Mode paiement', value: paymentInfo }
  ]);

  y = section(y, 'COLLECTEUR', [
    { label: 'Identifiant', value: `${collecteurId} - ${collecteurNom}`, valueBold: true },
    { label: 'Véhicule', value: col.vehiculeImmat || '-' }
  ]);

  // Signatures — deux cadres côte à côte
  const sgap = 10, sw = (W - sgap) / 2, sh = 15 + 60 + 14;
  const sigBox = (x, titre, color, img, sousTitre) => {
    rect(x, y, sw, sh, null, color, 1.5);
    rect(x, y, sw, 15, color);
    text(titre, x, y + 4, { bold: true, size: 8, color: C.blanc, width: sw, align: 'center' });
    rect(x + 0.75, y + 15, sw - 1.5, 60, C.grisFond);
    if (img) { try { doc.image(img, x + (sw - 140) / 2, y + 17.5, { fit: [140, 55], align: 'center', valign: 'center' }); } catch (e) { text('Signature', x, y + 40, { size: 8, color: C.grisTexte, width: sw, align: 'center' }); } }
    else text('Signature', x, y + 40, { size: 8, color: C.grisTexte, width: sw, align: 'center' });
    hline(x, x + sw, y + 75);
    text(sousTitre || '-', x, y + 79, { size: 7, width: sw, align: 'center' });
  };
  sigBox(L, 'SIGNATURE COLLECTEUR', C.vert, sigCol, collecteurNom);
  sigBox(L + sw + sgap, 'SIGNATURE PRODUCTEUR', C.vertFonce, sigResto, formatGerant(resto.gerant) || '-');
  y += sh + 8;

  // Mentions légales
  const mentions = "DÉCLARATION GÉNÉRALE DE L'ÉMETTEUR DU BORDEREAU — Nous nous engageons à ne transporter les déchets ci-dessus désignés que vers des installations de traitement conformes à la loi du 19/07/1976 modifiée relative aux installations classées pour la protection de l'environnement. L'émetteur de ce bordereau est le destinataire des déchets ci-dessus décrits. Nous certifions que les renseignements portés ci-dessus sont exacts et établis de bonne foi. Achat sans TVA selon la directive 2006/112/CE (article 199-I-D) et l'article 283-2 sexies du Code général des impôts — le producteur déclare être soumis à la TVA. Toute reproduction ou remise de ce bordereau sans autorisation de UCO AND CO est strictement interdite.";
  doc.font('Helvetica').fontSize(6.5);
  const mh = doc.heightOfString(mentions, { width: W - 10 }) + 10;
  rect(L, y, W, mh, C.grisClair);
  text(mentions, L + 5, y + 5, { size: 6.5, color: C.gris, width: W - 10 });
  footer(1);

  // =====================================================
  // PAGE 2 — AUTODÉCLARATION ISCC (texte verbatim)
  // =====================================================
  doc.addPage();
  y = header(doc.page.margins.top, ['Document de conformité ISCC'], C.vertFonce);

  y = text("Autodéclaration d'ISCC relative aux points d'origine produisant les huiles de cuisson usagées (UCO)", L, y + 2, { bold: true, size: 11, color: C.noir, width: W, align: 'center' }) + 10;

  // Tableau "Informations relatives aux points d'origine"
  const cell = (x, yy, w, h, str, o = {}) => {
    rect(x, yy, w, h, o.fill || null, C.noir, 0.6);
    if (o.checkbox) { doc.rect(x + w / 2 - 4, yy + h / 2 - 4, 8, 8).lineWidth(0.8).stroke(C.noir); return; }
    doc.font(o.bold ? 'Helvetica-Bold' : 'Helvetica').fontSize(o.size || 8).fillColor(C.noir);
    doc.text(String(str ?? ''), x + 5, yy + 3.5, { width: w - 10, align: o.align || 'left' });
  };
  const rowH = (str, w, size = 8) => { doc.font('Helvetica').fontSize(size); return Math.max(14, doc.heightOfString(String(str ?? ''), { width: w - 10 }) + 7); };

  const lw = W * 0.32, cw = W * 0.06, vw = W - lw;
  const iscRows = [
    ['Nom', `${resto.enseigne || ''}${resto.societe ? ' — ' + resto.societe : ''}`],
    ['Adresse', (typeof resto.adresse === 'string' ? resto.adresse : `${resto.adresse?.numero || ''} ${resto.adresse?.nature || ''} ${resto.adresse?.nom || ''}`.trim()) || '-'],
    ['Code postal, ville', `${resto.adresse?.cp || resto.codePostal || ''} ${resto.adresse?.ville || resto.ville || ''}`.trim()],
    ['Pays', 'France'],
    ['Numéro de téléphone', formatPhone(resto.tel) || '-']
  ];
  let h = rowH("Informations relatives aux points d'origine (p. ex., restaurant, service de restauration, etc.) :", W);
  cell(L, y, W, h, "Informations relatives aux points d'origine (p. ex., restaurant, service de restauration, etc.) :", { bold: true });
  y += h;
  iscRows.forEach(([k, v]) => { h = Math.max(rowH(k, lw), rowH(v, vw)); cell(L, y, lw, h, k); cell(L + lw, y, vw, h, v); y += h; });
  const q1 = "La quantité d'UCO produites par le point d'origine est égale ou supérieure à dix (10) tonnes métriques par mois ¹";
  const q2 = "Les UCO produites par le point d'origine est d'origine animale en tout ou en partie ²";
  h = rowH(q1, W - cw); cell(L, y, W - cw, h, q1); cell(L + W - cw, y, cw, h, '', { checkbox: true }); y += h;
  h = rowH(q2, W - cw); cell(L, y, W - cw, h, q2); cell(L + W - cw, y, cw, h, '', { checkbox: true }); y += h;
  const dest = 'UCO AND CO — 119 Route de La Varenne, 28270 Rueil-la-Gadelière — SIRET 953 315 041 00012';
  h = Math.max(rowH('Destinataire des UCO (point de collecte)', lw), rowH(dest, vw));
  cell(L, y, lw, h, 'Destinataire des UCO (point de collecte)'); cell(L + lw, y, vw, h, dest); y += h + 8;

  // Confirmations du signataire (verbatim)
  const confTitle = 'En signant la présente autodéclaration, le signataire confirme ce qui suit :';
  h = rowH(confTitle, W); cell(L, y, W, h, confTitle, { bold: true }); y += h;
  const confs = [
    "1. UCO désigne les huiles et les graisses d'origine végétale ou animale ayant été utilisées pour cuire des aliments destinés à la consommation humaine. Les livraisons d'UCO couvertes par la présente autodéclaration contiennent uniquement des UCO et ne sont mélangées avec aucune autre huile ou graisse qui ne correspond pas à la définition d'UCO.",
    "2. Les UCO couvertes par la présente autodéclaration correspondent à la définition de déchet. Cela signifie que les UCO sont un matériau que le point d'origine jette ou envisage ou est tenu de jeter et que les UCO n'ont pas été modifiées ni contaminées intentionnellement pour correspondre à cette définition.",
    "3. La documentation des quantités d'UCO livrées est disponible.",
    "4. La législation nationale applicable en matière de prévention et de gestion des déchets (p. ex., pour le transport, la surveillance, etc.) est respectée.",
    "5. Les vérificateurs des organismes de certification ou d'ISCC (peuvent être accompagnés par un représentant du point de collecte) peuvent examiner sur place ou en contactant le signataire (p. ex., par téléphone) si les renseignements contenus dans la présente autodéclaration sont corrects.",
    "6. Les informations contenues dans la présente autodéclaration peuvent être transmises à l'organisme de certification du point de collecte ou à ISCC et vérifiés par eux. Note : l'organisme de certification et ISCC assurent la confidentialité des données fournies dans la présente autodéclaration."
  ];
  doc.font('Helvetica').fontSize(7.5);
  const confH = confs.reduce((a, s) => a + doc.heightOfString(s, { width: W - 16, lineGap: 1 }) + 4, 0) + 8;
  rect(L, y, W, confH, null, C.noir, 0.6);
  let cy = y + 5;
  confs.forEach(s => { doc.font('Helvetica').fontSize(7.5).fillColor(C.noir).text(s, L + 8, cy, { width: W - 16, lineGap: 1 }); cy = doc.y + 4; });
  y += confH;

  // Lieu/date + signature
  const half = W / 2, sigH = 52;
  cell(L, y, half, sigH, `${resto.adresse?.ville || resto.ville || ''}, ${dateFormatted}`, { align: 'center' });
  // recentrer verticalement le texte lieu/date : on l'écrase avec un fond blanc puis on réécrit centré
  rect(L + 1, y + 1, half - 2, sigH - 2, C.blanc);
  text(`${resto.adresse?.ville || resto.ville || ''}, ${dateFormatted}`, L, y + sigH / 2 - 5, { size: 8, color: C.noir, width: half, align: 'center' });
  rect(L + half, y, half, sigH, null, C.noir, 0.6);
  if (sigResto) { try { doc.image(sigResto, L + half + (half - 170) / 2, y + 3, { fit: [170, 46], align: 'center', valign: 'center' }); } catch (e) {} }
  y += sigH;
  cell(L, y, half, 14, 'Lieu, date', { align: 'center' }); cell(L + half, y, half, 14, 'Signature', { align: 'center' }); y += 14 + 10;

  // Notes de bas de page ISCC (verbatim)
  hline(L, R, y, C.noir, 0.6); y += 5;
  const notes = [
    ["¹ 10 (dix) tonnes métriques d'UCO égalent à env. 11,1 (onze virgule un) mètres cubes / 11 100 (onze mille cent) litres / 2 932 (deux mille neuf cent trente-deux) gallons", 6.3, '#333'],
    ["² Si cette case est cochée, il est supposé que les UCO produits par le point d'origine sont (au moins en partie) d'origine animale (p. ex., provenant du lard, du beurre, du suif, etc.) et que le point de collecte ne peut pas vendre les UCO venant de ce point d'origine comme étant « entièrement d'origine végétale ». Si cette case n'est pas cochée, cela signifie que le point d'origine utilise exclusivement des huiles végétales (p. ex, huile de colza ou de tournesol) et pas des huiles ou graisses d'origine animale pour la cuisson ou la friture.", 6.3, '#333'],
    ["Note : L'huile végétale ayant été utilisée pour la cuisson ou la friture de la viande et qui contient par conséquent une partie inévitable d'origine animale peut toujours être considérée comme « UCO entièrement d'origine végétale ».", 6.3, '#333'],
    ["En cas de conflit entre version en langue anglaise et version traduite de ce document, la version en langue anglaise s'appliquera et sera contraignante pour les parties impliquées dans la présente auto-déclaration.", 6, '#555'],
    ["In the event of any conflict between the English language version and the translated version of this document, the English language version shall apply and be binding upon the parties involved in this self-declaration.", 6, '#555']
  ];
  notes.forEach(([s, size, color]) => { y = text(s, L, y, { size, color, width: W, lineGap: 0.5 }) + 3; });
  y += 2;
  text('© ISCC System GmbH', L, y, { size: 6.5, color: C.noir });
  text('Version 2.0 (au 1er avril 2020)', L, y, { size: 6.5, color: C.noir, width: W, align: 'right' });
  footer(2);

  doc.end();
  const buffer = await done;
  return { buffer, filename, numeroOrdre };
}

module.exports = { generateBordereauPDF, formatAdresse, formatGerant, formatPhone, computeNumeroOrdre };
