#!/usr/bin/env node
// Minimal x402 v2 "exact" (SVM) paid endpoint — the smallest server that
// wires x402.js correctly. Every POST is a paid resource; every other
// request gets the 402 + PAYMENT-REQUIRED header that tells a client how
// to pay. No framework, no facilitator, no database.
//
//   X402_PAYTO=<your receiving address> \
//   X402_FEEPAYER=<path to fee-payer keypair.json> \
//   node example-server.js
//
// The advertised destination is the PAYTO's associated token account for
// the configured asset (USDC by default). That ATA must EXIST on mainnet
// before a single payment can settle — create it first, or every correct
// payment dies in simulation ("rail-cannot-receive", the most common
// defect class on Cairn's scoreboard). test-battery.js checks this.
//
// NOTE what is deliberately missing here, and what production needs:
//   - rate limiting (with a Retry-After header on the 429 — clients
//     don't parse 429 bodies, they back off blind without the header)
//   - your actual resource: this server settles the payment and returns
//     a receipt; yours should return the thing the payment bought.
'use strict';
const http = require('http');
const x402 = require('./x402');

const PORT = process.env.PORT || 8402;
const BASE = process.env.BASE || `http://127.0.0.1:${PORT}`;

function json(res, code, body, extra = {}) {
  res.writeHead(code, { 'Content-Type': 'application/json', ...extra });
  res.end(JSON.stringify(body, null, 2));
}

// The 402 everyone gets until they pay: requirements in the JSON body for
// humans and pay-then-claim clients, and the same thing base64d in the
// PAYMENT-REQUIRED header for x402 v2 clients.
function demand(res, err) {
  json(res, 402, { error: err || 'payment_required', accepts: [x402.requirements()] },
    { 'PAYMENT-REQUIRED': x402.paymentRequiredHeader(BASE + '/', err) });
}

http.createServer((req, res) => {
  if (req.method !== 'POST') return demand(res);
  let body = '';
  req.on('data', c => { body += c; if (body.length > 4096) req.destroy(); });
  req.on('end', async () => {
    let parsed = {};
    try { parsed = JSON.parse(body || '{}'); } catch { return json(res, 400, { error: 'invalid_json' }); }
    const payHeader = req.headers['payment-signature'] || req.headers['x-payment'];
    if (!payHeader) return demand(res);
    // settle() does everything: header parse, full layout validation, local
    // ed25519 signature verification, fee-payer signing, broadcast, confirm.
    // It never throws; on failure it hands back the right status + JSON body.
    // The second argument binds a buyer message (falls back to the tx memo);
    // pass null if your resource doesn't need one — but then drop the
    // question_required branch in x402.js, which refuses memoless payments.
    const q = typeof parsed.question === 'string' ? parsed.question.trim() : '';
    const r = await x402.settle(payHeader, q || null);
    if (!r.ok) return json(res, r.code, r.body,
      { 'PAYMENT-REQUIRED': x402.paymentRequiredHeader(BASE + '/', r.body && r.body.error) });
    // Paid. r.signature is the settled tx; serve the resource here.
    json(res, 200, {
      status: 'settled', transaction: r.signature, payer: r.payer,
      amount_atomic: r.amount, memo: r.memo,
      resource: 'replace this object with what the payment actually bought',
    }, { 'PAYMENT-RESPONSE': r.settlementHeader, 'X-PAYMENT-RESPONSE': r.settlementHeader });
  });
}).listen(PORT, () => console.log(`x402 example endpoint on :${PORT} — POST to pay, anything else to see terms`));
