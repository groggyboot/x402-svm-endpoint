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
  const r = await fetch(chain.rpc, { method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const j = await r.json();
  if (j.error) { const e = new Error(j.error.message || 'rpc error'); e.rpcError = true; throw e; }
  return j.result;
}
const ethCall = (chain, to, data) => rpc(chain, 'eth_call', [{ to, data }, 'latest']);
const SEL = { isBlacklisted: '0xfe575a87', authorizationState: '0xe94a0102',
  name: '0x06fdde03', decimals: '0x313ce567' };
function decodeString(ret) {
  try { const b = Buffer.from(strip0x(ret), 'hex');
    const len = Number(BigInt(hex(b.slice(32, 64))));
    return b.slice(64, 64 + len).toString('utf8'); } catch { return null; }
}

// ---- HTTP probe plumbing (same shape/verdict rules as the SVM checker) ----
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
    try {
      await ethCall(chain, cfg.asset, SEL.authorizationState + strip0x(addrWord(ZERO).toString('hex')) + '0'.repeat(64));
      rail('asset_supports_eip3009', 'PASS', 'authorizationState() answers — EIP-3009 present');
    } catch (e) {
      rail('asset_supports_eip3009', e.rpcError ? 'FAIL' : 'ERROR', e.rpcError
        ? 'authorizationState() reverts — token lacks EIP-3009; exact-scheme settlement impossible'
        : 'RPC unreachable: ' + e.message);
    }
    try {
      const bl = await ethCall(chain, cfg.asset, SEL.isBlacklisted + strip0x(addrWord(cfg.payTo).toString('hex')));
      const black = BigInt(bl) === 1n;
      rail('payTo_not_blacklisted', black ? 'FAIL' : 'PASS', black
        ? 'USDC isBlacklisted(payTo) is TRUE — every transfer to it reverts (rail-cannot-receive)'
        : 'isBlacklisted(payTo) is false');
    } catch (e) {
      rail('payTo_not_blacklisted', 'PASS', e.rpcError
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
  if (fails.length) console.log('\nFAIL = the endpoint accepted a payload it should have refused, or its receive rail is broken. Fix before taking payments.');
  if (weak.length) console.log('WEAK = handled with a 5xx (leaked an infra error), an unexpected 3xx, or a non-canonical asset worth verifying.');
  console.log('\nNote: this checker verifies rejection behavior and rail preflight only.');
  console.log('It does not send a real payment; a clean run is necessary, not sufficient.');
  process.exit(fails.length ? 1 : 0);
})();
