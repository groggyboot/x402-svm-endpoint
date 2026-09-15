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
// Wake 160: classification for plaintext_envelope_refused, kept pure so the
// decision table is testable without a public https fixture (see
// site/test-check.js). `obs` is what the http:// twin of the target said.
function plaintextVerdict(obs) {
  const { targetProtocol, loopback, reachable, status, hasTerms, location, claimedUrl,
          host, pathname, method, errCode, httpsStatus } = obs;
  if (loopback) return null;                       // no public path, nothing to attack
  const probed = `${method || 'POST'} http://${host}${pathname}`;
  // Wake 161: every clean verdict names the exact request it covers. I told a
  // peer their site served no terms in the clear on the strength of a probe of
  // paths that were never their payment door; their /api/ask was answering the
  // full envelope over http at that moment. A per-request observation reported
  // as a per-operator verdict is how a true reading becomes a false statement.
  const scope = ` (covers ${probed} only — another path on this host can still leak)`;
  if (targetProtocol !== 'https:') return { verdict: 'FAIL',
    detail: `target is ${targetProtocol}// — the payment terms for this endpoint are only ever served in the clear` };
  if (!reachable)
    // An outright refused connection is evidence: nothing is listening in the
    // clear. A timeout, a DNS failure or a reset is NOT — it is "I could not
    // look", and a checker that scores those as PASS launders its own blindness
    // into someone else's clean bill.
    return /ECONNREFUSED|EHOSTUNREACH|ENETUNREACH/i.test(String(errCode || ''))
      ? { verdict: 'PASS', detail: `no plaintext listener on http://${host} (${errCode})` }
      : { verdict: 'ERROR', detail: `could not reach http://${host} in the clear` +
          `${errCode ? ` (${errCode})` : ''} — this is "I could not look", not "no terms are served"` };
  if (hasTerms) return { verdict: 'FAIL',
    detail: `${probed} answers ${status} with a full payment envelope in the clear` +
      (claimedUrl && String(claimedUrl).startsWith('https:')
        ? ` — and its own resource.url claims ${claimedUrl}, a security property the channel it arrived on does not have` : '') +
      `. payTo is rewritable in transit by anything on the path.` };
  if (status >= 300 && status < 400 && /^https:/i.test(location || '')) {
    if (status === 308 || status === 307)
      return { verdict: 'PASS', detail: `plaintext redirects ${status} to ${location} before any terms are served` };
    // 1.7.1 (2026-09-15): what a 301/302 loses is the BODY, and a GET/HEAD
    // route has none to lose. The POST-shaped WEAK below was landing on
    // fourteen GET doors on my own board; a redirect before any terms are
    // served is the property this check is for, and on a bodiless route it
    // holds.
    if (/^(GET|HEAD)$/i.test(method || 'POST'))
      return { verdict: 'PASS', detail: `plaintext redirects ${status} to ${location} before any terms are served (a ${String(method).toUpperCase()} route carries no body for a ${status} to drop)` };
    return { verdict: 'WEAK', detail: `plaintext redirects ${status} to ${location}, but ${status} lets a client drop the body and re-issue a paying POST as GET — 308 preserves the method` };
  }
  // A door that refuses MY client has not shown me what it serves a client it
  // accepts. Cloudflare's Browser Integrity Check answers exactly this way
  // (403, error code 1010) and it blocks by User-Agent, not by protocol — so
  // an edge that hides a plaintext envelope from one client family still hands
  // it to every other. Refusals are unobserved, not clean.
  if ([401, 403, 405, 407, 429, 451].includes(status) || status >= 500)
    return { verdict: 'ERROR',
      detail: `${probed} answers ${status} — my request was refused before any terms could be served, ` +
        `so this run says nothing about what the door hands a client it accepts (an edge UA block reads exactly like this)` };
  // Wake 161: the plaintext twin has to answer THE SAME REQUEST the https twin
  // answers, or the run is not a comparison. My wake-160 sweep asked 39
  // endpoints with one verb; the GET-only doors answered 404/405 to a POST and
  // the old table read that silence as innocence. Six endpoints serving live
  // payment terms in the clear scored clean because I knocked with the wrong
  // verb and then published the total as a fact about the ecosystem.
  if (httpsStatus && [400, 404, 405, 410].includes(status) && status !== httpsStatus)
    return { verdict: 'ERROR',
      detail: `${probed} answers ${status} where the https twin answers ${httpsStatus} — ` +
        `the plaintext side never answered the same request, so nothing here is evidence either way` };
  return { verdict: 'PASS', detail: `plaintext answers ${status} and serves no payment terms` + scope };
}
if (typeof module !== 'undefined') module.exports = { ...(module.exports || {}), plaintextVerdict };

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
  else if ([404, 405, 429].includes(r.status)) verdict = 'ERROR'; // not observed (1.6.0): the route, method or rate limit answered before any validator did
  else if (r.status >= 400) verdict = 'PASS';
  else verdict = 'WEAK';
  return { name, verdict, detail: `${r.status}${err ? ' ' + err : ''}${verdict === 'FAIL' ? ' — ACCEPTED a hostile payload' : ''}` +
    (verdict === 'WEAK' && r.status >= 500 ? ' (5xx: validate before hitting infra)' : '') +
    (verdict === 'ERROR' ? ' — not observed: a 404/405/429 answers before any validator does, so this row proves nothing either way' : '') };
}

// Some servers put the x402 envelope in the response BODY, others carry it
// base64-encoded in a PAYMENT-REQUIRED header beside an empty body (both are
// live in the wild — agent402.tools does the latter). Read both.
// 1.7.0 (2026-09-14): the header may be spelled PAYMENT-REQUIRED (v2) or
// X-Payment-Required, and carry base64 JSON or plain JSON — all four are live
// (a swarmboard reviewer found a plain-JSON X-Payment-Required door that this
// decoder read as "no header"). Decode every case; report which was used.
function decodeEnvelopeHeader(headers) {
  if (!headers || !headers.get) return null;
  for (const name of ['payment-required', 'x-payment-required']) {
    const raw = headers.get(name); if (!raw) continue;
    try { const j = JSON.parse(Buffer.from(raw, 'base64').toString('utf8')); if (j && typeof j === 'object') return { env: j, name, encoding: 'base64' }; } catch {}
    try { const j = JSON.parse(raw); if (j && typeof j === 'object') return { env: j, name, encoding: 'json' }; } catch {}
  }
  return null;
}
function termsOf(body, headers) {
  if (body && (body.accepts || body.accepted))
    return body.accepts || [body.accepted];
  const d = decodeEnvelopeHeader(headers);
  if (d && (d.env.accepts || d.env.accepted)) return d.env.accepts || [d.env.accepted];
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

  // --- Client-fingerprint parity (wake 159) --------------------------------
  // Found on my OWN doors, by accident, an hour after an independent party
  // verified their envelopes as clean: the envelope can be perfect and the
  // door can still be shut. A CDN/WAF in front of the endpoint may refuse
  // whole client families by User-Agent before the origin ever answers. My
  // origin served a correct 402; Cloudflare's Browser Integrity Check served
  // `403 error code: 1010` to Python's stdlib urllib and to libwww-perl —
  // two of the likeliest ways a small agent script fetches a URL.
  //
  // No conformance battery I know of tests this, because every battery
  // probes with exactly one client. One seat, one fingerprint, one answer.
  // Measured from a single vantage point: a difference is evidence, and a
  // match is not proof of universal reachability.
  const STDLIB_UAS = ['Python-urllib/3.12', 'libwww-perl/6.68', 'Java/17.0.1', 'Go-http-client/1.1'];
  {
    const seen = [];
    for (const ua of STDLIB_UAS) {
      try {
        const r = await fetch(url, reqInit(METHOD, { 'User-Agent': ua }, { question: 'x402 client-fingerprint probe' }));
        seen.push({ ua, status: r.status });
      } catch (e) { seen.push({ ua, status: 'ERROR: ' + e.message }); }
    }
    const odd = seen.filter(s => s.status !== disc.status);
    const blocked = odd.filter(s => s.status === 403 || s.status === 406 || s.status === 401);
    results.push({
      name: 'client_fingerprint_parity',
      verdict: blocked.length ? 'FAIL' : (odd.length ? 'WEAK' : 'PASS'),
      detail: blocked.length
        ? `the edge refuses ${blocked.length} common client(s) before the envelope is served: ` +
          blocked.map(s => `${s.ua} -> ${s.status}`).join(', ') +
          ` (unpaid baseline was ${disc.status}). A CDN bot rule is shadowing a payable door: those clients never see the 402 at all.`
        : odd.length
          ? `unpaid baseline ${disc.status}, but ${odd.map(s => `${s.ua} -> ${s.status}`).join(', ')} — differs by client, cause unknown (rate limit? routing?)`
          : `all ${seen.length} probed stdlib clients get the same ${disc.status} as the baseline` });
  }

  // --- Plaintext envelope (wake 160) ---------------------------------------
  // Found on my own door the same way the fingerprint check was: by probing
  // in a way I never normally probe. A 402 envelope is not a status message,
  // it is MONEY INSTRUCTIONS — it names payTo, asset and amount. Served over
  // http:// those instructions cross the wire in the clear, and the copy of
  // `resource.url` inside them usually still says https, so the document
  // asserts a security property the channel it arrived on does not have.
  // Any on-path router rewrites payTo, the client pays a stranger, and the
  // real endpoint answers its retry with a 402 it cannot explain.
  //
  // Honest bound: an active attacker who controls the plaintext channel can
  // strip a redirect too. Nothing served over http:// is safe. What this
  // check measures is whether the endpoint ever hands out payment terms in
  // the clear at all, which is the part its operator controls.
  {
    const u = new URL(url);
    const loopback = /^(localhost|127\.|::1$|\[::1\]$|0\.0\.0\.0$|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/.test(u.hostname);
    let obs = { targetProtocol: u.protocol, loopback, host: u.host, pathname: u.pathname,
      method: METHOD, reachable: false, errCode: '', httpsStatus: disc.status };
    if (!loopback && u.protocol === 'https:') {
      const plain = new URL(url); plain.protocol = 'http:';
      try {
        const r = await fetch(plain.toString(), { ...reqInit(METHOD, {}, { question: 'x402 plaintext-envelope probe' }), redirect: 'manual' });
        const hdr = r.headers.get('payment-required') || r.headers.get('x-payment-required') || '';
        let body = null; try { body = await r.clone().json(); } catch {}
        obs = { ...obs, reachable: true, status: r.status, location: r.headers.get('location') || '',
          hasTerms: !!hdr || !!(body && (body.accepts || body.accepted)),
          claimedUrl: body && body.resource && body.resource.url };
      } catch (e) {
        // Keep WHY it failed: a refused connection and a timeout are different
        // facts and only one of them is evidence (see plaintextVerdict).
        obs.errCode = e && (e.cause && (e.cause.code || e.cause.name) || e.code || e.name) || '';
      }
    }
    const v = plaintextVerdict(obs);
    if (v) results.push({ name: 'plaintext_envelope_refused', ...v });
  }

  const check = async (name, buildHeader) => results.push(await fire(cfg, name, buildHeader));

  // ── Envelope projection checks (wake 158) ────────────────────────────────
  // Read-only, computed from the discovery 402 already in hand. These exist
  // because this instrument gave MY OWN endpoints a clean bill for a week
  // while an outside grader called them D/"avoid": it looked for an entry it
  // could use anywhere in `accepts`, and never asked what a naive client
  // reading the JSON body would find FIRST — or whether every option in the
  // list was executable at all. A checker that reads the strict surface
  // certifies a door the loose readers cannot open.
  //
  // Two projections carry the same claim: the base64 PAYMENT-REQUIRED header
  // and the JSON body. Divergence between them is the defect.
  {
    const bodyTerms = disc.body && (disc.body.accepts || (disc.body.accepted ? [disc.body.accepted] : null));
    const hdrDec = decodeEnvelopeHeader(disc.headers);
    const hdrEnv = hdrDec ? hdrDec.env : null;
    const hdrHow = hdrDec ? `${hdrDec.name.toUpperCase()} (${hdrDec.encoding})` : 'PAYMENT-REQUIRED';

    // CAIP-2: <namespace>:<reference>. "solana-mainnet" is NOT CAIP-2 and no
    // standard client will resolve it; "solana:5eykt4Us…" is.
    const isCaip2 = n => typeof n === 'string' && /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/.test(n);
    // 1.7.0 (2026-09-14): version-aware names. On an x402Version:1 body the
    // spec's own network names ("base", "solana", …) are the conformant form;
    // calling them non-CAIP-2 produced a false FAIL on six v1 doors in a week
    // (browserbase, Solana Index, timzinin, …). A v2 body still owes CAIP-2.
    const V1_NAMES = { base: 'eip155:8453', 'base-sepolia': 'eip155:84532', avalanche: 'eip155:43114',
      'avalanche-fuji': 'eip155:43113', polygon: 'eip155:137', 'polygon-amoy': 'eip155:80002',
      sei: 'eip155:1329', 'sei-testnet': 'eip155:1328', iotex: 'eip155:4689',
      solana: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', 'solana-devnet': 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1' };
    const bodyVer = disc.body && Number(disc.body.x402Version) || null;
    const normNet = n => (typeof n === 'string' && V1_NAMES[n]) || n;
    const netOk = n => isCaip2(n) || (bodyVer === 1 && !!V1_NAMES[n]);
    const executable = a => !!a && a.scheme === 'exact' && netOk(a.network) &&
      !!a.payTo && !!a.asset && !!(a.amount || a.maxAmountRequired);
    const why = a => !a ? 'missing'
      : a.scheme !== 'exact' ? `scheme "${a.scheme}" is not an x402 scheme`
      : !netOk(a.network) ? (bodyVer === 1 ? `network "${a.network}" is neither a v1 network name nor a CAIP-2 id` : `network "${a.network}" is not a CAIP-2 id (a v2 body owes CAIP-2)`)
      : !a.payTo ? 'no payTo' : !a.asset ? 'no asset'
      : !(a.amount || a.maxAmountRequired) ? 'no amount' : 'ok';

    if (!bodyTerms) {
      // 1.6.0 (2026-09-12): header-only is PASS, not WEAK. The x402 v2 HTTP
      // transport puts every protocol field in headers and calls the body a
      // server implementation concern; its own example body is {}. Grading
      // that as a finding would flag every seller that follows the spec
      // (raised by an operator on MikeyPetrillo/Agent402#1321, checked against
      // specs/transports-v2/http.md). The v1 body-reading fact is printed in
      // the detail, where it belongs, not in the verdict.
      const hdrTerms = hdrEnv && (hdrEnv.accepts || (hdrEnv.accepted ? [hdrEnv.accepted] : null));
      results.push({ name: 'body_envelope_present', verdict: hdrTerms ? 'PASS' : 'FAIL',
        detail: hdrTerms
          ? 'terms are in the PAYMENT-REQUIRED header; the JSON body carries no `accepts` — conformant to the x402 v2 HTTP transport (the body is a server implementation concern); a v1 body-reading client sees no terms here (compatibility note, not a defect)'
          : hdrEnv ? 'a PAYMENT-REQUIRED header is present but decodes to no `accepts`'
          : 'no payment terms in either the JSON body or a PAYMENT-REQUIRED header' });
    } else {
      // 1.7.0: a v1 body carries `resource` inside each accepts entry, not at
      // the top level — "omits resource" failed to reproduce by hand six times
      // on v1 doors before this line learned to look where v1 puts it.
      const perOptionResource = bodyVer === 1 && bodyTerms.every(a => a && a.resource != null);
      const missing = ['x402Version', 'resource'].filter(k => disc.body[k] == null && !(k === 'resource' && perOptionResource));
      results.push({ name: 'body_envelope_complete', verdict: missing.length ? 'FAIL' : 'PASS',
        detail: missing.length
          ? `body advertises \`accepts\` but omits ${missing.join(' and ')} — a body-reading client sees a malformed envelope`
          : (perOptionResource ? 'v1 body carries x402Version, and resource inside every accepts entry (where v1 puts it)' : 'body carries x402Version + resource beside `accepts`') });

      // The check that would have caught my own D: accepts[0], not "some entry".
      const first = bodyTerms[0];
      results.push({ name: 'accepts0_payable', verdict: executable(first) ? 'PASS' : 'FAIL',
        detail: executable(first)
          ? `accepts[0] is exact/${first.network} — payable by a client that takes the first option`
          : `accepts[0] is NOT payable by a naive client: ${why(first)}` });

      const bad = bodyTerms.filter(a => !executable(a));
      results.push({ name: 'accepts_all_executable', verdict: bad.length ? 'WEAK' : 'PASS',
        detail: bad.length
          ? `${bad.length}/${bodyTerms.length} advertised option(s) cannot be executed by a standard x402 client (${bad.map(a => `${a.scheme}/${a.network}: ${why(a)}`).join('; ')}) — accepts[] is the machine-executable list, not a menu of routes the operator will honour; move non-x402 routes to another key`
          : `all ${bodyTerms.length} advertised option(s) are executable` });

      // Same claim, two projections: do they agree?
      if (hdrEnv && (hdrEnv.accepts || hdrEnv.accepted)) {
        const h0 = (hdrEnv.accepts || [hdrEnv.accepted])[0];
        // 1.7.0: compare the OPTION, not the dialect — a v2 header saying
        // eip155:8453 and a v1 body saying "base" name one chain; a door that
        // serves both versions is dual-serving, which is agreement.
        const same = h0 && first && h0.scheme === first.scheme && normNet(h0.network) === normNet(first.network) &&
          String(h0.payTo) === String(first.payTo) &&
          String(h0.amount || h0.maxAmountRequired) === String(first.amount || first.maxAmountRequired);
        const dual = same && h0.network !== first.network;
        results.push({ name: 'header_body_agree', verdict: same ? 'PASS' : 'FAIL',
          detail: same ? (dual ? `header (${hdrHow}, ${h0.network}) and body (v${bodyVer || '?'}, ${first.network}) name the same option in two dialects — dual-serving, not a disagreement` : 'header and body advertise the same first payment option')
            : `header accepts[0] (${h0 ? h0.scheme + '/' + h0.network : 'none'}) and body accepts[0] ` +
              `(${first ? first.scheme + '/' + first.network : 'none'}) disagree — the two projections of one claim do not match` });
      }
    }
  }

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
  if (fails.length) console.log('\nFAIL = the endpoint accepted a payload it should have refused, its receive rail is missing, or its edge refuses clients before the envelope is served. Fix before taking payments.');
  if (weak.length) console.log('WEAK = handled with a 5xx (leaked an infra error) or an unexpected 3xx. Validate the payload and answer a clean 4xx JSON instead.');
  console.log('\nNote: this checker verifies rejection behavior and the receive rail only.');
  console.log('It does not send a real payment. For a scored end-to-end run with a live');
  console.log('settlement, see Cairn: https://cairnwake.com');
  process.exit(fails.length ? 1 : 0);
})();
