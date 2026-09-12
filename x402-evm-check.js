#!/usr/bin/env node
// x402-evm-check — a self-serve conformance checker for x402 v2 "exact"
// scheme endpoints on EVM chains (Base mainnet first). Point it at any
// endpoint URL; it reads that endpoint's OWN advertised requirements (the
// 402 body's `accepts` array), builds a battery of hostile EIP-3009
// payloads from them, and reports whether each is correctly rejected.
// Nothing is ever broadcast on-chain: every payload is signed by a
// THROWAWAY secp256k1 key holding zero balance and is sent only to your
// HTTP endpoint — even a server that tried to settle one would revert.
//
//   node x402-evm-check.js https://your-endpoint.example/api/pay
//
// This is NOT a port of x402-svm-check: the SVM defect class "receive rail
// missing" (absent ATA) has no EVM equivalent — any address can receive
// ERC-20. The EVM rail risks are different species, all read-only
// checkable: a USDC-blacklisted payTo (every transfer reverts), a
// zero-address payTo, an asset contract that does not exist or does not
// implement EIP-3009 (exact-scheme settlement impossible), and a
// lookalike token at a non-canonical address.
//
// What it deliberately does NOT flag, same policy as the SVM checker:
// (1) replaying an already-settled authorization — v2 §10.1 places replay
// defence at the token contract's nonce, not the resource server;
// (2) omitting the EIP-712 domain hints from `extra` — §5.1.2 marks
// `extra` optional. We grade the specification, not conventions.
//
// Deps: @noble/curves + @noble/hashes only.  MIT — Coppice (https://coppice-ai.com).
'use strict';
const { secp256k1 } = require('@noble/curves/secp256k1');
const { keccak_256 } = require('@noble/hashes/sha3');

const CHAINS = {
  8453: { label: 'base', rpc: process.env.X402_EVM_RPC || 'https://mainnet.base.org',
    rpcAlt: 'https://base-rpc.publicnode.com',
    usdc: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
};

const url = process.argv[2];
const HEADER = process.env.X402_HEADER || 'X-PAYMENT';
const METHOD = process.env.X402_METHOD || 'POST';
if (!url) {
  console.error('usage: node x402-evm-check.js <endpoint-url>   (POST endpoint that answers 402)');
  console.error('  env: X402_HEADER (default X-PAYMENT), X402_EVM_RPC, X402_METHOD (default POST)');
  process.exit(2);
}

// ---- tiny hex/abi/eip712 toolkit (no ethers, no web3) ----
const strip0x = s => s.replace(/^0x/i, '');
const hex = b => '0x' + Buffer.from(b).toString('hex');
const isAddr = s => /^0x[0-9a-fA-F]{40}$/.test(s || '');
const kec = b => keccak_256(b);
const utf8 = s => Buffer.from(s, 'utf8');
const word = bi => { const b = Buffer.alloc(32); let v = BigInt(bi);
  for (let i = 31; i >= 0 && v > 0n; i--) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
const addrWord = a => Buffer.concat([Buffer.alloc(12), Buffer.from(strip0x(a), 'hex')]);
const cat = (...bs) => Buffer.concat(bs.map(Buffer.from));

const DOMAIN_TYPEHASH = kec(utf8('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'));
const XFER_TYPEHASH = kec(utf8('TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)'));

function digest712(domain, auth) {
  const dom = kec(cat(DOMAIN_TYPEHASH, kec(utf8(domain.name)), kec(utf8(domain.version)),
    word(domain.chainId), addrWord(domain.verifyingContract)));
  const struct = kec(cat(XFER_TYPEHASH, addrWord(auth.from), addrWord(auth.to),
    word(auth.value), word(auth.validAfter), word(auth.validBefore),
    Buffer.from(strip0x(auth.nonce), 'hex')));
  return kec(cat(Buffer.from([0x19, 0x01]), dom, struct));
}
function evmAddress(priv) {
  return '0x' + Buffer.from(kec(secp256k1.getPublicKey(priv, false).slice(1)).slice(12)).toString('hex');
}
function sign712(priv, domain, auth) {
  const sig = secp256k1.sign(digest712(domain, auth), priv);
  return hex(cat(sig.toCompactRawBytes(), Buffer.from([27 + sig.recovery])));
}
const randNonce = () => hex(crypto.getRandomValues(new Uint8Array(32)));

// ---- RPC (read-only; the only chain access this tool ever makes) ----
async function rpc(chain, method, params) {
  const call = async url => {
    const r = await fetch(url, { method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
    const j = await r.json();
    if (j.error) { const e = new Error(j.error.message || 'rpc error'); e.rpcError = true; e.rpcCode = j.error.code; throw e; }
    return j.result;
  };
  try { return await call(chain.rpc); }
  catch (e) { if (isRevert(e) || !chain.rpcAlt) throw e; return call(chain.rpcAlt); }
}
const ethCall = (chain, to, data) => rpc(chain, 'eth_call', [{ to, data }, 'latest']);
// A JSON-RPC error on eth_call conflates "the contract reverted" with node-side
// failures (rate limits, timeouts). Only a revert says anything about the token.
const isRevert = e => !!e.rpcError && (e.rpcCode === 3 ||
  /revert|invalid opcode|execution error/i.test(e.message || ''));
const SEL = { isBlacklisted: '0xfe575a87', authorizationState: '0xe94a0102',
  name: '0x06fdde03', decimals: '0x313ce567' };
function decodeString(ret) {
  try { const b = Buffer.from(strip0x(ret), 'hex');
    const len = Number(BigInt(hex(b.slice(32, 64))));
    return b.slice(64, 64 + len).toString('utf8'); } catch { return null; }
}

// ---- HTTP probe plumbing (same shape/verdict rules as the SVM checker) ----
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
  if (status >= 300 && status < 400 && /^https:/i.test(location || ''))
    return (status === 308 || status === 307)
      ? { verdict: 'PASS', detail: `plaintext redirects ${status} to ${location} before any terms are served` }
      : { verdict: 'WEAK', detail: `plaintext redirects ${status} to ${location}, but ${status} lets a client drop the body and re-issue a paying POST as GET — 308 preserves the method` };
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
  return { method, headers: { 'Content-Type': 'application/json', ...extraHeaders },
    ...(bodyless ? {} : { body: JSON.stringify(jsonBody) }) };
}
const envelope = (cfg, payload) => Buffer.from(JSON.stringify({
  x402Version: 2, scheme: 'exact', network: cfg.network,
  accepted: { scheme: 'exact', network: cfg.network }, payload })).toString('base64');

async function fire(name, buildHeader) {
  let header;
  try { header = buildHeader(); } catch (e) {
    return { name, verdict: 'ERROR', detail: 'could not build payload: ' + e.message };
  }
  let r; let text;
  try {
    r = await fetch(url, reqInit(METHOD, { ...(header ? { [HEADER]: header } : {}) },
      { question: 'x402-evm-check probe' }));
    text = await r.text();
  } catch (e) { return { name, verdict: 'ERROR', detail: 'request failed: ' + e.message }; }
  let body = null; try { body = JSON.parse(text); } catch {}
  const err = body && (body.error || (body.accepts && 'payment_required'));
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
function termsOf(body, headers) {
  if (body && (body.accepts || body.accepted))
    return body.accepts || [body.accepted];
  const h = headers && headers.get && headers.get('payment-required');
  if (h) { try { const j = JSON.parse(Buffer.from(h, 'base64').toString('utf8'));
    if (j && (j.accepts || j.accepted)) return j.accepts || [j.accepted]; } catch {} }
  return [];
}

(async () => {
  // 1. Read the endpoint's own 402 — twice, to detect a rotating payTo.
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
  const parseChain = n => { if (!n) return null;
    const m = /^eip155:(\d+)$/i.exec(n); if (m) return Number(m[1]);
    if (/^base$/i.test(n)) return 8453;
    if (/^base-sepolia$/i.test(n)) return 84532;
    return null; };
  const isEvm = a => a && a.scheme === 'exact' && parseChain(a.network) != null;
  const exact = accepts.find(isEvm);
  if (!exact) {
    if (accepts.some(a => a && a.scheme === 'exact' && /solana/i.test(String(a.network || '')))) {
      console.error('this endpoint\'s "exact" scheme is on Solana — use x402-svm-check for SVM endpoints.');
    } else {
      console.error('no EVM x402 "exact" scheme found in the endpoint\'s `accepts`. ' +
        'Advertised schemes: ' + (accepts.map(a => `${a.scheme}/${a.network}`).join(', ') || '(none)'));
    }
    process.exit(2);
  }
  const chainId = parseChain(exact.network);
  const chain = CHAINS[chainId];
  if (!chain) {
    console.error(`network "${exact.network}" (chainId ${chainId}) is not supported — mainnet only ` +
      `(supported: ${Object.entries(CHAINS).map(([id, c]) => `${c.label}/eip155:${id}`).join(', ')}).`);
    process.exit(2);
  }
  let payToDynamic = false;
  try {
    const r2 = await fetch(url, reqInit(METHOD, {}, {}));
    const b2 = await r2.json().catch(() => null);
    const a2 = termsOf(b2, r2.headers).find(isEvm);
    if (a2 && a2.payTo && exact.payTo && a2.payTo.toLowerCase() !== exact.payTo.toLowerCase()) payToDynamic = true;
  } catch {}

  const cfg = {
    network: exact.network, chainId, asset: exact.asset, payTo: exact.payTo,
    amount: exact.amount || exact.minUnits || exact.maxAmountRequired,
  };
  if (!isAddr(cfg.asset) || !isAddr(cfg.payTo)) {
    console.error(`the exact scheme's asset/payTo are not valid 0x EVM addresses ` +
      `(asset=${cfg.asset}, payTo=${cfg.payTo}). Is the advertised network really EVM?`);
    process.exit(2);
  }
  // EIP-712 domain: prefer the endpoint's own `extra` hints; fall back to the
  // token's on-chain name() and USDC's version "2" (extra is optional, §5.1.2).
  let domName = exact.extra && exact.extra.name, domVersion = exact.extra && exact.extra.version;
  if (!domName) { try { domName = decodeString(await ethCall(chain, cfg.asset, SEL.name)) || 'USD Coin'; } catch { domName = 'USD Coin'; } }
  if (!domVersion) domVersion = '2';
  const domain = { name: domName, version: domVersion, chainId, verifyingContract: cfg.asset };
  const priv = secp256k1.utils.randomPrivateKey(); // throwaway; zero balance; never funded
  const payer = evmAddress(priv);

  console.log(`Target:   ${url}`);
  console.log(`Scheme:   exact  network=${cfg.network} (chainId ${chainId})`);
  console.log(`Pay:      ${cfg.amount} atomic units of ${cfg.asset} -> ${cfg.payTo}`);
  console.log(`Domain:   name="${domain.name}" version="${domain.version}"` +
    (exact.extra && exact.extra.name ? ' (from extra)' : ' (from chain/default)') + '\n');

  const now = () => Math.floor(Date.now() / 1000);
  // Respect the endpoint's advertised window so timing never masks the layer
  // each check is aimed at (a validBefore past maxTimeoutSeconds gets refused
  // for the wrong reason before the signature is even looked at).
  const window_ = Math.min(3600, Number(exact.maxTimeoutSeconds) > 0 ? Number(exact.maxTimeoutSeconds) : 3600);
  const makeAuth = (over = {}) => ({ from: payer, to: cfg.payTo, value: cfg.amount,
    validAfter: 0, validBefore: now() + window_, nonce: randNonce(), ...over });
  const payload = (auth, sig) => ({ signature: sig, authorization: {
    from: auth.from, to: auth.to, value: String(auth.value),
    validAfter: String(auth.validAfter), validBefore: String(auth.validBefore), nonce: auth.nonce } });
  const signed = (over = {}, opts = {}) => {
    const auth = makeAuth(over);
    const d = opts.chainId ? { ...domain, chainId: opts.chainId } : domain;
    return envelope(cfg, payload(auth, sign712(opts.priv || priv, d, auth)));
  };

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

  // --- Envelope projections (ported from x402-svm-check, wake 159) ---------
  // A door has two projections of one claim: the base64 PAYMENT-REQUIRED
  // header and the JSON body. The strict surface can be perfect while the
  // loose one is unopenable. My own endpoint was graded D for exactly this
  // and my checker passed it, because the checker read the header and the
  // clients read the body. Divergence between the two IS the defect.
  {
    const bodyTerms = disc.body && (disc.body.accepts || (disc.body.accepted ? [disc.body.accepted] : null));
    const hdrRaw = disc.headers && disc.headers.get && disc.headers.get('payment-required');
    let hdrEnv = null;
    if (hdrRaw) { try { hdrEnv = JSON.parse(Buffer.from(hdrRaw, 'base64').toString('utf8')); } catch {} }

    // CAIP-2: <namespace>:<reference>. "base" and "base-sepolia" are accepted
    // by this tool's own parseChain as a courtesy, but they are NOT CAIP-2 and
    // a standard client will not resolve them; "eip155:8453" is.
    const isCaip2 = n => typeof n === 'string' && /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/.test(n);
    const executable = a => !!a && a.scheme === 'exact' && isCaip2(a.network) &&
      !!a.payTo && !!a.asset && !!(a.amount || a.maxAmountRequired);
    const why = a => !a ? 'missing'
      : a.scheme !== 'exact' ? `scheme "${a.scheme}" is not an x402 scheme`
      : !isCaip2(a.network) ? `network "${a.network}" is not a CAIP-2 id`
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
      const missing = ['x402Version', 'resource'].filter(k => disc.body[k] == null);
      results.push({ name: 'body_envelope_complete', verdict: missing.length ? 'FAIL' : 'PASS',
        detail: missing.length
          ? `body advertises \`accepts\` but omits ${missing.join(' and ')} — a body-reading client sees a malformed envelope`
          : 'body carries x402Version + resource beside `accepts`' });

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

      if (hdrEnv && (hdrEnv.accepts || hdrEnv.accepted)) {
        const h0 = (hdrEnv.accepts || [hdrEnv.accepted])[0];
        const same = h0 && first && h0.scheme === first.scheme && h0.network === first.network &&
          String(h0.payTo) === String(first.payTo) &&
          String(h0.amount || h0.maxAmountRequired) === String(first.amount || first.maxAmountRequired);
        results.push({ name: 'header_body_agree', verdict: same ? 'PASS' : 'FAIL',
          detail: same ? 'header and body advertise the same first payment option'
            : `header accepts[0] (${h0 ? h0.scheme + '/' + h0.network : 'none'}) and body accepts[0] ` +
              `(${first ? first.scheme + '/' + first.network : 'none'}) disagree — the two projections of one claim do not match` });
      }
    }
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

  const check = async (name, buildHeader) => results.push(await fire(name, buildHeader));

  await check('no_payment', () => null);
  await check('header_not_base64_json', () => '!!!not-base64!!!');
  await check('garbage_payload', () => Buffer.from('{"hello":"world"}').toString('base64'));
  await check('bad_signature', () => {
    const auth = makeAuth();
    return envelope(cfg, payload(auth, hex(Buffer.alloc(65, 7))));
  });
  await check('wrong_signer', () => {
    // valid signature by key B over an authorization claiming from = payer(A):
    // ecrecover yields B ≠ from; the server must refuse.
    const other = secp256k1.utils.randomPrivateKey();
    const auth = makeAuth();
    return envelope(cfg, payload(auth, sign712(other, domain, auth)));
  });
  await check('wrong_amount_underpay', () => signed({ value: '1' }));
  await check('wrong_destination', () => signed({ to: payer }));
  await check('expired_authorization', () => signed({ validBefore: now() - 3600 }));
  await check('not_yet_valid', () => signed({ validAfter: now() + 3600, validBefore: now() + 7200 }));
  await check('wrong_chain_domain', () => signed({}, { chainId: 1 }));

  // Rail preflight: read-only RPC. The EVM analog of the SVM receive-rail
  // check — different defect species, see the header comment.
  const rail = (name, verdict, detail) => results.push({ name, verdict, detail });
  const ZERO = '0x' + '0'.repeat(40);
  rail('payTo_not_zero_address', cfg.payTo.toLowerCase() === ZERO ? 'FAIL' : 'PASS',
    cfg.payTo.toLowerCase() === ZERO
      ? 'payTo is the zero address — settlement burns or reverts (rail-cannot-receive)'
      : `payTo ${cfg.payTo.slice(0, 10)}…${payToDynamic ? ' (payTo rotates per unpaid request — per-payment custody address; pay only against a fresh offer)' : ''}`);
  let code = null;
  try { code = await rpc(chain, 'eth_getCode', [cfg.asset, 'latest']); } catch {}
  rail('asset_contract_exists', code == null ? 'ERROR' : (code && code !== '0x' ? 'PASS' : 'FAIL'),
    code == null ? 'RPC unreachable' : (code && code !== '0x' ? 'asset has contract code'
      : `no contract at asset address ${cfg.asset} — nothing can settle (rail-cannot-receive)`));
  if (code && code !== '0x') {
    {
      const probe3009 = () => ethCall(chain, cfg.asset,
        SEL.authorizationState + strip0x(addrWord(ZERO).toString('hex')) + '0'.repeat(64));
      let err = null;
      try { await probe3009(); } catch (e) {
        err = e;
        if (!isRevert(e)) { // transient node failure — retry once before judging
          await new Promise(r => setTimeout(r, 1500));
          try { await probe3009(); err = null; } catch (e2) { err = e2; }
        }
      }
      if (!err) rail('asset_supports_eip3009', 'PASS', 'authorizationState() answers — EIP-3009 present');
      else rail('asset_supports_eip3009', isRevert(err) ? 'FAIL' : 'ERROR', isRevert(err)
        ? 'authorizationState() reverts — token lacks EIP-3009; exact-scheme settlement impossible'
        : 'RPC error (no verdict on the token): ' + err.message);
    }
    try {
      const bl = await ethCall(chain, cfg.asset, SEL.isBlacklisted + strip0x(addrWord(cfg.payTo).toString('hex')));
      const black = BigInt(bl) === 1n;
      rail('payTo_not_blacklisted', black ? 'FAIL' : 'PASS', black
        ? 'USDC isBlacklisted(payTo) is TRUE — every transfer to it reverts (rail-cannot-receive)'
        : 'isBlacklisted(payTo) is false');
    } catch (e) {
      rail('payTo_not_blacklisted', 'PASS', isRevert(e)
        ? 'token exposes no isBlacklisted() — not applicable' : 'RPC error: ' + e.message);
    }
  }
  {
    const canonical = chain.usdc.toLowerCase();
    if (cfg.asset.toLowerCase() === canonical) {
      rail('asset_is_canonical', 'PASS', `asset is canonical USDC on ${chain.label}`);
    } else {
      let tokenName = null; let dec = null;
      try { tokenName = decodeString(await ethCall(chain, cfg.asset, SEL.name)); } catch {}
      try { dec = Number(BigInt(await ethCall(chain, cfg.asset, SEL.decimals))); } catch {}
      rail('asset_is_canonical', 'WEAK',
        `asset is NOT canonical USDC (${chain.usdc}) — it is "${tokenName || '?'}" (decimals ${dec == null ? '?' : dec}). ` +
        'A legitimate non-USDC token is allowed; a lookalike mint is the risk this surfaces — verify before paying.');
    }
  }
  {
    let pcode = null;
    try { pcode = await rpc(chain, 'eth_getCode', [cfg.payTo, 'latest']); } catch {}
    rail('payTo_account_type', pcode == null ? 'ERROR' : 'PASS', pcode == null ? 'RPC unreachable'
      : (pcode !== '0x'
        ? 'payTo is a contract — it receives ERC-20 fine, but whether funds are sweepable depends on its code (not verifiable read-only)'
        : 'payTo is an externally-owned account'));
  }

  // Report — identical table format to x402-svm-check (parsers share it).
  console.log('CHECK                         VERDICT  DETAIL');
  console.log('─'.repeat(78));
  for (const x of results) console.log(`${x.name.padEnd(28)}  ${x.verdict.padEnd(7)}  ${x.detail}`);
  const fails = results.filter(r => r.verdict === 'FAIL');
  const weak = results.filter(r => r.verdict === 'WEAK');
  const errs = results.filter(r => r.verdict === 'ERROR');
  console.log('─'.repeat(78));
  console.log(`${results.filter(r => r.verdict === 'PASS').length}/${results.length} PASS` +
    (weak.length ? `, ${weak.length} WEAK` : '') +
    (fails.length ? `, ${fails.length} FAIL` : '') +
    (errs.length ? `, ${errs.length} ERROR` : ''));
  if (fails.length) console.log('\nFAIL = the endpoint accepted a payload it should have refused, its receive rail is broken, or its edge refuses clients before the envelope is served. Fix before taking payments.');
  if (weak.length) console.log('WEAK = handled with a 5xx (leaked an infra error), an unexpected 3xx, or a non-canonical asset worth verifying.');
  console.log('\nNote: this checker verifies rejection behavior and rail preflight only.');
  console.log('It does not send a real payment; a clean run is necessary, not sufficient.');
  process.exit(fails.length ? 1 : 0);
})();
