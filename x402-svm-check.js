#!/usr/bin/env node
// x402-svm-check — a self-serve conformance checker for x402 v2 "exact"
// scheme endpoints on Solana. Point it at any endpoint URL; it reads that
// endpoint's OWN advertised requirements (the 402 body's `accepts` array),
// builds a battery of hostile payloads from them, and reports whether each
// is correctly rejected. Nothing is ever broadcast on-chain: the hostile
// transactions are signed by a throwaway keypair against a fake blockhash
// and only sent to your HTTP endpoint, never to an RPC.
//
//   node x402-svm-check.js https://your-endpoint.example/api/pay
//
// What it can and cannot tell you:
//   - It tests the REJECTION path (does a malformed / hostile / underpaying
//     payload get correctly refused?) and the RECEIVE RAIL (does the
//     advertised payTo's token account actually exist on-chain?). Those two
//     cover the most common defect classes seen in the wild:
//     "hostile-payload-accepted" and "rail-cannot-receive".
//   - It does NOT perform a live valid payment (that needs real funds and a
//     real settlement) — so a clean run here is necessary but not sufficient.
//     For a scored, signed, end-to-end run including a real settlement, see
//     Cairn (https://cairnwake.com).
//
// What it deliberately does NOT flag (and why): every FAIL this tool reports
// traces to a normative requirement of the x402 v2 "exact" scheme — a signed
// payment to the advertised asset, amount, and destination, refused when any
// of those is wrong or the envelope is malformed. It does NOT flag two things
// that are easy to mistake for defects but that the spec does not require of
// the server: (1) replaying an already-settled payment — v2 §10.1 places
// replay defence at the authorization nonce and the token contract, not the
// resource server, and re-serving a retried request is also how a client that
// lost its response recovers what it paid for; (2) omitting the token EIP-712
// domain from `extra` (EVM only; §5.1.2 marks `extra` optional). A conformance
// checker that scores those is grading a convention, not the specification.
//
// Only dependency: @solana/web3.js.  MIT — Coppice (https://coppice-ai.com).
'use strict';
const { Keypair, PublicKey, TransactionMessage, VersionedTransaction,
  TransactionInstruction, ComputeBudgetProgram } = require('@solana/web3.js');

const TOKEN = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const ATA_PROGRAM = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
const WSOL = 'So11111111111111111111111111111111111111112';

const url = process.argv[2];
const HEADER = process.env.X402_HEADER || 'X-PAYMENT'; // some servers use PAYMENT-SIGNATURE
const RPC = process.env.X402_RPC || 'https://api.mainnet-beta.solana.com';
if (!url) {
  console.error('usage: node x402-svm-check.js <endpoint-url>   (POST endpoint that answers 402)');
  console.error('  env: X402_HEADER (default X-PAYMENT), X402_RPC, X402_METHOD (default POST)');
  process.exit(2);
}
const METHOD = process.env.X402_METHOD || 'POST';

// GET/HEAD requests cannot carry a body (Node's fetch throws). For those,
// the payment travels in the header alone; for POST etc. we send a probe body.
function reqInit(method, extraHeaders, jsonBody) {
  const bodyless = method === 'GET' || method === 'HEAD';
  return {
    method,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
    ...(bodyless ? {} : { body: JSON.stringify(jsonBody) }),
  };
}

const ata = (owner, mint) => PublicKey.findProgramAddressSync(
  [owner.toBuffer(), TOKEN.toBuffer(), mint.toBuffer()], ATA_PROGRAM)[0];

function transferChecked(source, mint, dest, authority, amount, decimals) {
  const data = Buffer.alloc(10);
  data[0] = 12; data.writeBigUInt64LE(BigInt(amount), 1); data[9] = decimals;
  return new TransactionInstruction({ programId: TOKEN, data, keys: [
    { pubkey: source, isSigner: false, isWritable: true },
    { pubkey: mint, isSigner: false, isWritable: false },
    { pubkey: dest, isSigner: false, isWritable: true },
    { pubkey: authority, isSigner: true, isWritable: false },
  ]});
}

// Build a base64 VersionedTransaction from the endpoint's own requirements.
function buildTx(cfg, { mint, amount, decimals, dest, authority, sign = true,
  forge = false, extraIx = null } = {}) {
  const m = new PublicKey(mint || cfg.asset);
  const auth = authority || cfg._payer;
  const d = dest || ata(new PublicKey(cfg.payTo), m);
  const ixs = [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 6000 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1000 }),
    transferChecked(ata(auth.publicKey, m), m, d, auth.publicKey,
      amount == null ? cfg.amount : amount, decimals == null ? cfg.decimals : decimals),
  ];
  if (extraIx) ixs.push(extraIx);
  const msg = new TransactionMessage({ payerKey: new PublicKey(cfg.feePayer),
    recentBlockhash: Keypair.generate().publicKey.toBase58(), // fake; never broadcast
    instructions: ixs }).compileToV0Message();
  const tx = new VersionedTransaction(msg);
  if (sign) tx.sign([auth]);
  if (forge) tx.signatures[1] = Buffer.from(Array(64).fill(7));
  return Buffer.from(tx.serialize()).toString('base64');
}

const envelope = (cfg, txB64) => Buffer.from(JSON.stringify({
  x402Version: 2, scheme: 'exact', network: cfg.network,
  accepted: { scheme: 'exact', network: cfg.network },
  payload: { transaction: txB64 } })).toString('base64');

async function fire(cfg, name, buildHeader) {
  let header;
  try { header = buildHeader(); } catch (e) {
    return { name, verdict: 'ERROR', detail: 'could not build payload: ' + e.message };
  }
  let r, text;
  try {
    r = await fetch(url, reqInit(METHOD,
      { ...(header ? { [HEADER]: header } : {}) },
      { question: 'x402-svm-check probe' }));
    text = await r.text();
  } catch (e) {
    return { name, verdict: 'ERROR', detail: 'request failed: ' + e.message };
  }
  let body = null; try { body = JSON.parse(text); } catch {}
  const err = body && (body.error || (body.accepts && 'payment_required'));
  // A hostile payload is correctly handled iff the endpoint did NOT accept it.
  // Acceptance = a 2xx status. Anything 4xx (ideally 402 with a JSON error) is
  // a correct rejection. A 5xx means the endpoint mishandled it (leaked an
  // infra error instead of validating) — flag as WEAK, not a hard fail.
  let verdict;
  if (r.status >= 200 && r.status < 300) verdict = 'FAIL';
  else if (r.status >= 500) verdict = 'WEAK';
  else if (r.status >= 400) verdict = 'PASS';
  else verdict = 'WEAK';
  return { name, verdict, detail: `${r.status}${err ? ' ' + err : ''}${verdict === 'FAIL' ? ' — ACCEPTED a hostile payload' : ''}` +
    (verdict === 'WEAK' && r.status >= 500 ? ' (5xx: validate before hitting infra)' : '') };
}

// Some servers put the x402 envelope in the response BODY, others carry it
// base64-encoded in a PAYMENT-REQUIRED header beside an empty body (both are
// live in the wild — agent402.tools does the latter). Read both.
function termsOf(body, headers) {
  if (body && (body.accepts || body.accepted))
    return body.accepts || [body.accepted];
  const h = headers && headers.get && headers.get('payment-required');
  if (h) { try { const j = JSON.parse(Buffer.from(h, 'base64').toString('utf8'));
    if (j && (j.accepts || j.accepted)) return j.accepts || [j.accepted]; } catch {} }
  return [];
}

async function rpcAccountExists(pubkey) {
  const r = await fetch(RPC, { method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getAccountInfo',
      params: [pubkey, { encoding: 'base64' }] }) });
  const j = await r.json();
  return !!(j.result && j.result.value);
}

(async () => {
  // 1. Read the endpoint's own 402.
  let disc;
  try {
    const r = await fetch(url, reqInit(METHOD, {}, {}));
    disc = { status: r.status, body: await r.json().catch(() => null), headers: r.headers };
  } catch (e) { console.error('could not reach endpoint:', e.message); process.exit(2); }

  if (disc.status < 400) {
    console.error(`endpoint did not answer a 402/4xx to an unpaid ${METHOD} (got ${disc.status}). ` +
      'Is this the paid endpoint URL?');
    process.exit(2);
  }
  const accepts = termsOf(disc.body, disc.headers);
  const isSvm = a => a.scheme === 'exact' && typeof a.network === 'string' && /solana/i.test(a.network);
  const exact = accepts.find(isSvm);
  // Second unpaid request: does the advertised payTo rotate per request (a
  // per-payment custody/deposit address)? If so, its token account cannot
  // have been created by anyone yet, and "create the ATA" is not the fix —
  // the operator must pre-create it when issuing the offer, or accept a
  // Create-ATA instruction. Detected, not assumed; reported in the rail check.
  let payToDynamic = false;
  if (exact) {
    try {
      const r2 = await fetch(url, reqInit(METHOD, {}, {}));
      const b2 = await r2.json().catch(() => null);
      const a2 = termsOf(b2, r2.headers).find(isSvm);
      if (a2 && a2.payTo && a2.payTo !== exact.payTo) payToDynamic = true;
    } catch {}
  }
  if (!exact) {
    const evmExact = accepts.find(a => a.scheme === 'exact');
    if (evmExact) {
      console.error(`this endpoint's "exact" scheme is on network "${evmExact.network}", not Solana. ` +
        'x402-svm-check only covers the Solana (SVM) exact scheme.');
    } else {
      console.error('no x402 "exact" scheme found in the endpoint\'s `accepts`. ' +
        'Advertised schemes: ' + (accepts.map(a => `${a.scheme}/${a.network}`).join(', ') || '(none)'));
      if (!accepts.length && METHOD === 'POST')
        console.error('note: this probe used POST (the default). GET-shaped routes may ' +
          'only advertise terms on GET — retry with X402_METHOD=GET.');
    }
    process.exit(2);
  }
  const _payer = Keypair.generate();
  const cfg = {
    network: exact.network,
    asset: exact.asset,
    amount: exact.amount || exact.minUnits || exact.maxAmountRequired,
    payTo: exact.payTo,
    decimals: (exact.extra && exact.extra.decimals) != null ? exact.extra.decimals : (exact.decimals != null ? exact.decimals : 6),
    // If the server co-signs as fee payer it advertises extra.feePayer; if the
    // client pays its own fees (no facilitator), the payer is its own fee payer.
    feePayer: (exact.extra && exact.extra.feePayer) || _payer.publicKey.toBase58(),
    selfFeePayer: !(exact.extra && exact.extra.feePayer),
    _payer,
  };
  try { new PublicKey(cfg.asset); new PublicKey(cfg.payTo); } catch {
    console.error(`the exact scheme's asset/payTo are not valid base58 Solana addresses ` +
      `(asset=${cfg.asset}, payTo=${cfg.payTo}). Is the advertised network really Solana?`);
    process.exit(2);
  }
  console.log(`Target:   ${url}`);
  console.log(`Scheme:   exact  network=${cfg.network}`);
  console.log(`Pay:      ${cfg.amount} atomic units of ${cfg.asset} -> ${cfg.payTo}`);
  console.log(`FeePayer: ${cfg.selfFeePayer ? '(client pays own fees — no facilitator)' : cfg.feePayer}\n`);

  const results = [];
  const check = async (name, buildHeader) => results.push(await fire(cfg, name, buildHeader));

  await check('no_payment', () => null);
  await check('garbage_transaction', () => envelope(cfg, 'aGVsbG8gd29ybGQ='));
  await check('header_not_base64_json', () => '!!!not-base64!!!');
  await check('unsigned_transaction', () => envelope(cfg, buildTx(cfg, { sign: false })));
  await check('forged_signature', () => envelope(cfg, buildTx(cfg, { forge: true })));
  await check('wrong_asset', () => envelope(cfg, buildTx(cfg, {
    mint: cfg.asset === WSOL ? 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v' : WSOL, decimals: 9 })));
  await check('wrong_amount_underpay', () => envelope(cfg, buildTx(cfg, { amount: 1 })));
  await check('wrong_destination', () => envelope(cfg, buildTx(cfg, {
    dest: ata(cfg._payer.publicKey, new PublicKey(cfg.asset)) })));
  await check('extra_instruction', () => envelope(cfg, buildTx(cfg, {
    extraIx: new TransactionInstruction({ programId: Keypair.generate().publicKey,
      data: Buffer.from([1]), keys: [] }) })));
  // fee-payer's own ATA as the transfer source: passes every layout check,
  // would drain the fee payer — must be refused at validation, not in sim.
  // Only meaningful when the server co-signs as a distinct fee payer.
  if (!cfg.selfFeePayer) await check('fee_payer_ata_as_source', () => {
    const mint = new PublicKey(cfg.asset);
    const msg = new TransactionMessage({ payerKey: new PublicKey(cfg.feePayer),
      recentBlockhash: Keypair.generate().publicKey.toBase58(),
      instructions: [
        ComputeBudgetProgram.setComputeUnitLimit({ units: 6000 }),
        ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1000 }),
        transferChecked(ata(new PublicKey(cfg.feePayer), mint), mint,
          ata(new PublicKey(cfg.payTo), mint), cfg._payer.publicKey, cfg.amount, cfg.decimals),
      ] }).compileToV0Message();
    const tx = new VersionedTransaction(msg);
    tx.sign([cfg._payer]);
    return envelope(cfg, Buffer.from(tx.serialize()).toString('base64'));
  });

  // Rail preflight: can the advertised payTo actually receive this asset?
  let railLine;
  {
    const dest = ata(new PublicKey(cfg.payTo), new PublicKey(cfg.asset)).toBase58();
    let exists = false, rpcErr = null;
    try { exists = await rpcAccountExists(dest); } catch (e) { rpcErr = e.message; }
    const verdict = rpcErr ? 'ERROR' : (exists ? 'PASS' : 'FAIL');
    results.push({ name: 'receive_rail_exists', verdict,
      detail: rpcErr ? 'RPC error: ' + rpcErr
        : (exists ? `destination token account ${dest.slice(0, 8)}… exists${payToDynamic ? ' (payTo rotates per request; this one existed at issue time)' : ''}`
          : payToDynamic
            ? `payTo rotates per request (per-payment custody address) and the destination token account ${dest} does NOT exist at issue time — a spec-layout payment fails in simulation; fix is on the operator's side at offer time (pre-create the ATA when issuing the offer, or accept a Create-ATA instruction), not a one-off account creation (rail-cannot-receive: dynamic-payto)`
            : `destination token account ${dest} does NOT exist — every correct payment will fail in simulation (rail-cannot-receive)`) });
  }

  // Report.
  console.log('CHECK                         VERDICT  DETAIL');
  console.log('─'.repeat(78));
  for (const x of results) {
    console.log(`${x.name.padEnd(28)}  ${x.verdict.padEnd(7)}  ${x.detail}`);
  }
  const fails = results.filter(r => r.verdict === 'FAIL');
  const weak = results.filter(r => r.verdict === 'WEAK');
  const errs = results.filter(r => r.verdict === 'ERROR');
  console.log('─'.repeat(78));
  console.log(`${results.filter(r => r.verdict === 'PASS').length}/${results.length} PASS` +
    (weak.length ? `, ${weak.length} WEAK` : '') +
    (fails.length ? `, ${fails.length} FAIL` : '') +
    (errs.length ? `, ${errs.length} ERROR` : ''));
  if (fails.length) console.log('\nFAIL = the endpoint accepted a payload it should have refused, or its receive rail is missing. Fix before taking payments.');
  if (weak.length) console.log('WEAK = handled with a 5xx (leaked an infra error) or an unexpected 3xx. Validate the payload and answer a clean 4xx JSON instead.');
  console.log('\nNote: this checker verifies rejection behavior and the receive rail only.');
  console.log('It does not send a real payment. For a scored end-to-end run with a live');
  console.log('settlement, see Cairn: https://cairnwake.com');
  process.exit(fails.length ? 1 : 0);
})();
