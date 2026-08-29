// x402 v2 "exact" scheme for SVM — self-hosted verify + settle, no facilitator.
// Spec: github.com/coinbase/x402 (specs/x402-specification-v2.md,
// schemes/exact/scheme_exact_svm.md, transports-v2/http.md).
//
// Flow: client builds a versioned tx (2 compute-budget ixs + TransferChecked
// to the ATA of payTo, optional memo), signs it as token authority but NOT as
// fee payer, base64s it inside a PaymentPayload, and sends it in a
// PAYMENT-SIGNATURE (v2) or X-PAYMENT (v1-compat) header. This module
// validates the exact layout, signs as fee payer with a dedicated
// minimally-funded keypair, broadcasts, waits for confirmation, and returns a
// SettlementResponse. The fee-payer key can pay fees and nothing else: it
// must not appear in any instruction, so a hostile payload can never move its
// funds — worst case is fee burn, bounded by MAX_FEE_LAMPORTS and the
// caller's rate limit.
'use strict';
const fs = require('fs');
const path = require('path');

// Lazy-load web3.js: keeps the always-on server light until first x402 use.
let w3 = null;
function web3() { return (w3 ||= require('@solana/web3.js')); }

const CAIP2 = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'; // mainnet genesis
const COMPUTE_BUDGET = 'ComputeBudget111111111111111111111111111111';
const TOKEN = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const TOKEN_2022 = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
const ATA_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const MEMO = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
const MEMO_V1 = 'Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo';
const LIGHTHOUSE = 'L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95';
const MAX_FEE_LAMPORTS = 20000; // base + priority the fee payer will accept

const cfg = {
  rpc: process.env.X402_RPC || 'https://api.mainnet-beta.solana.com',
  payTo: process.env.X402_PAYTO || 'HFZsCtVGHTxGzkjoE6cSnixwj5gpGvyiRycNtxrVRrn5', // CONFIGURE (Step 5): your vault PDA (or set X402_PAYTO)
  asset: process.env.X402_ASSET || 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', // USDC
  amount: process.env.X402_AMOUNT || '200000', // 0.2 USDC, atomic units, exact
  decimals: Number(process.env.X402_DECIMALS || 6),
  feePayerPath: process.env.X402_FEEPAYER || path.join(process.env.HOME || '/home/agent', 'keys', 'x402-feepayer.json'),
};

let feePayerKp = null;
function feePayer() {
  if (!feePayerKp) {
    const raw = JSON.parse(fs.readFileSync(cfg.feePayerPath, 'utf8'));
    feePayerKp = web3().Keypair.fromSecretKey(Uint8Array.from(raw));
  }
  return feePayerKp;
}
function feePayerAddress() {
  try { return feePayer().publicKey.toBase58(); } catch { return null; }
}

// The `accepts` entry advertised in the 402 (v2 PaymentRequirements).
function requirements() {
  return {
    scheme: 'exact',
    network: CAIP2,
    amount: cfg.amount,
    asset: cfg.asset,
    payTo: cfg.payTo,
    maxTimeoutSeconds: 60,
    extra: {
      feePayer: feePayerAddress(),
      decimals: cfg.decimals,
      question: 'put your question (<=800 chars) in the JSON body {"question":"..."} of the paying request, or in the transaction memo — it binds atomically with settlement',
      exampleBody: { question: 'What is Coppice and what does it sell?' },
    },
  };
}

// v2 PaymentRequired object, base64d into the PAYMENT-REQUIRED header.
function paymentRequiredHeader(resourceUrl, error) {
  const obj = {
    x402Version: 2,
    error: error || 'payment required',
    resource: {
      url: resourceUrl,
      description: 'A researched public answer and a permanent page in the record of an autonomous AI agent',
      mimeType: 'application/json',
    },
    accepts: [requirements()],
  };
  return Buffer.from(JSON.stringify(obj)).toString('base64');
}

function u32le(buf, o) { return buf[o] | (buf[o + 1] << 8) | (buf[o + 2] << 16) | (buf[o + 3] << 24); }
function u64le(buf, o) {
  let n = 0n;
  for (let i = 7; i >= 0; i--) n = (n << 8n) | BigInt(buf[o + i]);
  return n;
}

function deriveAta(owner, mint, tokenProgram) {
  const { PublicKey } = web3();
  return PublicKey.findProgramAddressSync(
    [new PublicKey(owner).toBuffer(), new PublicKey(tokenProgram).toBuffer(), new PublicKey(mint).toBuffer()],
    new PublicKey(ATA_PROGRAM))[0].toBase58();
}

// Validate the payload transaction against the spec's mandatory checks.
// Returns { ok:true, tx, payer, memo, feeLamports } or { ok:false, error }.
function validate(txB64) {
  const { VersionedTransaction, PublicKey } = web3();
  let tx;
  try { tx = VersionedTransaction.deserialize(Buffer.from(txB64, 'base64')); }
  catch { return { ok: false, error: 'undeserializable_transaction' }; }
  const msg = tx.message;
  if ((msg.addressTableLookups || []).length > 0)
    return { ok: false, error: 'address_table_lookups_not_allowed' };
  const keys = (msg.staticAccountKeys || msg.accountKeys).map(k => k.toBase58());
  const fp = feePayerAddress();
  if (keys[0] !== fp)
    return { ok: false, error: 'wrong_fee_payer', expected: fp };
  // Every required signer except the fee payer (slot 0, ours to fill) must
  // have already signed — verified locally, ed25519 over the message bytes,
  // so an unsigned or forged payload dies here instead of being broadcast.
  // Before this check an unsigned tx reached sendRawTransaction and the
  // caller got a 502 wrapping whatever the public RPC's error page said.
  const nSig = msg.header.numRequiredSignatures;
  if (tx.signatures.length !== nSig)
    return { ok: false, error: 'signature_count_mismatch', expected: nSig, received: tx.signatures.length };
  const msgBytes = msg.serialize();
  const { ed25519 } = require('@noble/curves/ed25519');
  for (let i = 1; i < nSig; i++) {
    const sig = tx.signatures[i];
    if (!sig || sig.every(b => b === 0))
      return { ok: false, error: 'payer_signature_missing', signer: keys[i],
        hint: 'sign the transaction as token authority before sending; only the fee-payer slot (index 0) may be left unsigned' };
    let good = false;
    try { good = ed25519.verify(sig, msgBytes, new PublicKey(keys[i]).toBytes()); } catch {}
    if (!good) return { ok: false, error: 'payer_signature_invalid', signer: keys[i] };
  }
  const cis = msg.compiledInstructions
    || msg.instructions.map(i => ({ programIdIndex: i.programIdIndex, accountKeyIndexes: i.accounts, data: Buffer.from(require('bs58').decode(i.data)) }));
  if (cis.length < 3 || cis.length > 6)
    return { ok: false, error: 'instruction_count_must_be_3_to_6' };
  const prog = (ci) => keys[ci.programIdIndex];
  const data = (ci) => Buffer.from(ci.data);

  // 1+2: compute budget — SetComputeUnitLimit (2) then SetComputeUnitPrice (3)
  if (prog(cis[0]) !== COMPUTE_BUDGET || data(cis[0])[0] !== 2)
    return { ok: false, error: 'instruction_0_must_be_set_compute_unit_limit' };
  if (prog(cis[1]) !== COMPUTE_BUDGET || data(cis[1])[0] !== 3)
    return { ok: false, error: 'instruction_1_must_be_set_compute_unit_price' };
  const cuLimit = u32le(data(cis[0]), 1);
  const cuPrice = u64le(data(cis[1]), 1); // micro-lamports per CU
  const priority = Number((BigInt(cuLimit) * cuPrice + 999999n) / 1000000n);
  const feeLamports = 5000 * msg.header.numRequiredSignatures + priority;
  if (feeLamports > MAX_FEE_LAMPORTS)
    return { ok: false, error: 'fee_too_high', max_total_fee_lamports: MAX_FEE_LAMPORTS, requested: feeLamports };

  // 3: TransferChecked on Token or Token-2022
  const tp = prog(cis[2]);
  if (tp !== TOKEN && tp !== TOKEN_2022)
    return { ok: false, error: 'instruction_2_must_be_token_transfer_checked' };
  const td = data(cis[2]);
  if (td[0] !== 12) // TransferChecked discriminator
    return { ok: false, error: 'instruction_2_must_be_transfer_checked' };
  const amount = u64le(td, 1);
  const decimals = td[9];
  const acc = cis[2].accountKeyIndexes.map(i => keys[i]);
  const [source, mint, dest, authority] = acc;
  if (mint !== cfg.asset)
    return { ok: false, error: 'wrong_asset', expected: cfg.asset };
  if (amount !== BigInt(cfg.amount))
    return { ok: false, error: 'wrong_amount', expected: cfg.amount, received: amount.toString() };
  if (decimals !== cfg.decimals)
    return { ok: false, error: 'wrong_decimals', expected: cfg.decimals };
  const expectedDest = deriveAta(cfg.payTo, cfg.asset, tp);
  if (dest !== expectedDest)
    return { ok: false, error: 'wrong_destination', expected_ata: expectedDest, for_owner: cfg.payTo };
  // The token authority must be one of the verified required signers, or the
  // transfer could never execute — catch it here rather than on-chain.
  const authIdx = cis[2].accountKeyIndexes[3];
  if (authIdx >= msg.header.numRequiredSignatures)
    return { ok: false, error: 'authority_not_a_signer', authority };

  // 4..6: only memo / lighthouse
  let memo = null;
  for (const ci of cis.slice(3)) {
    const p = prog(ci);
    if (p === MEMO || p === MEMO_V1) memo = data(ci).toString('utf8');
    else if (p !== LIGHTHOUSE)
      return { ok: false, error: 'unexpected_instruction_program', program: p };
  }

  // Fee-payer safety: never inside any instruction, never authority/source —
  // and never the source's owner. A transfer FROM the fee payer's own ATA
  // (source = deriveAta(fp)) passes every layout check above yet moves the
  // fee payer's funds, and used to sail on to simulation, where it died as an
  // opaque 502 (Cairn re-test note on report 0a5422f4, fee_payer_as_source).
  for (const ci of cis)
    if (ci.accountKeyIndexes.includes(0))
      return { ok: false, error: 'fee_payer_must_not_appear_in_instructions' };
  if (authority === fp || source === fp || source === deriveAta(fp, cfg.asset, tp))
    return { ok: false, error: 'fee_payer_must_not_move_funds' };

  return { ok: true, tx, payer: authority, memo, feeLamports, amount: amount.toString() };
}

// Parse a PAYMENT-SIGNATURE / X-PAYMENT header into the inner base64 tx.
function parseHeader(headerValue) {
  let payload;
  try { payload = JSON.parse(Buffer.from(String(headerValue), 'base64').toString('utf8')); }
  catch { return { ok: false, error: 'header_not_base64_json' }; }
  const txB64 = payload && payload.payload && payload.payload.transaction;
  if (typeof txB64 !== 'string' || txB64.length > 4096)
    return { ok: false, error: 'payload_missing_transaction' };
  const scheme = payload.accepted ? payload.accepted.scheme : payload.scheme;
  const network = payload.accepted ? payload.accepted.network : payload.network;
  if (scheme && scheme !== 'exact') return { ok: false, error: 'unsupported_scheme', supported: 'exact' };
  if (network && network !== CAIP2 && network !== 'solana')
    return { ok: false, error: 'unsupported_network', supported: CAIP2 };
  return { ok: true, txB64 };
}

// Sign as fee payer, broadcast, confirm. Returns a SettlementResponse-shaped
// object plus http status. Never throws. `question` is the body question (may
// be empty — then the tx memo must carry it); checked BEFORE broadcasting so
// a buyer is never charged for an ask that can't bind.
async function settle(headerValue, question) {
  let v;
  try {
    const strip = ({ ok, tx, ...rest }) => rest;
    const p = parseHeader(headerValue);
    if (!p.ok) return { ok: false, code: 400, body: strip(p) };
    v = validate(p.txB64);
    if (!v.ok) return { ok: false, code: 402, body: strip(v) };
    if (!question && !v.memo)
      return { ok: false, code: 400, body: { error: 'question_required',
        hint: 'include {"question":"..."} (<=800 chars) in the JSON body of this same request, or a memo instruction in the transaction. Settlement was NOT attempted — you have not been charged' } };
  } catch (e) { return { ok: false, code: 400, body: { ok: false, error: 'invalid_payment_payload' } }; }
  const { Connection } = web3();
  const conn = new Connection(cfg.rpc, 'confirmed');
  // Hard deadline on the whole RPC leg: web3.js fetches have no timeout, so a
  // hung public RPC would hold this request open past Cloudflare's ~100s
  // cutoff and the caller would get CF's HTML error page instead of JSON.
  const work = (async () => {
  try {
    // The tx id is the fee-payer signature, which is deterministic — compute
    // it up front so a replayed payload can be recognized even when the RPC's
    // "already processed" error is unhelpfully generic.
    v.tx.sign([feePayer()]);
    const txId = require('bs58').encode(v.tx.signatures[0]);
    // searchTransactionHistory:true — the recent-status cache only spans ~150
    // slots (~1 min), so a replay a few minutes after settlement would slip
    // past it and die as blockhash_expired instead of the honest 409.
    const prior = (await conn.getSignatureStatuses([txId], { searchTransactionHistory: true })).value[0];
    if (prior) return { ok: false, code: 409, body: { error: 'transaction_already_processed', transaction: txId,
      hint: 'this exact payment already settled; if it is yours and unbound, claim it via the pay-then-claim scheme: POST {"tx":"' + txId + '"} with your question' } };
    const sig = await conn.sendRawTransaction(v.tx.serialize(), { maxRetries: 3 });
    const deadline = Date.now() + 45000;
    let confirmed = false;
    while (Date.now() < deadline) {
      const st = (await conn.getSignatureStatuses([sig])).value[0];
      if (st && st.err) return { ok: false, code: 402, body: { error: 'transaction_failed_on_chain', transaction: sig } };
      if (st && (st.confirmationStatus === 'confirmed' || st.confirmationStatus === 'finalized')) { confirmed = true; break; }
      await new Promise(r => setTimeout(r, 2000));
    }
    if (!confirmed)
      return { ok: false, code: 402, body: { error: 'confirmation_timeout', transaction: sig,
        hint: 'the transaction was broadcast and may still land; once confirmed, claim it via the pay-then-claim scheme: POST {"tx":"' + sig + '"} with your question' } };
    const settlement = { success: true, transaction: sig, network: CAIP2, payer: v.payer };
    return { ok: true, code: 200, signature: sig, payer: v.payer, memo: v.memo, amount: v.amount,
      settlement, settlementHeader: Buffer.from(JSON.stringify(settlement)).toString('base64') };
  } catch (e) {
    const logs = Array.isArray(e && e.logs) ? e.logs : [];
    let m = String(e && e.message || e) + (e && e.transactionMessage ? ' :: ' + e.transactionMessage : '') + (logs.length ? ' :: ' + logs.join(' | ') : '');
    // A rate-limited public RPC answers with a full HTML error page; without
    // this the page ends up verbatim inside `detail` (Cairn report 0a5422f4).
    if (/<[a-z!/]/i.test(m)) m = m.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
    if (/already.*processed|AlreadyProcessed/i.test(m))
      return { ok: false, code: 409, body: { error: 'transaction_already_processed',
        hint: 'this signed transaction already landed; claim it via the pay-then-claim scheme: POST {"tx":"<signature>"} with your question' } };
    if (/Signature verification failure|invalid.*signature/i.test(m))
      return { ok: false, code: 402, body: { error: 'payer_signature_invalid',
        hint: 'sign the transaction as token authority before sending; leave the fee-payer slot unsigned' } };
    if (/Blockhash not found|block height exceeded/i.test(m))
      return { ok: false, code: 402, body: { error: 'blockhash_expired', hint: 'rebuild the transaction with a recent blockhash and retry' } };
    // A layout-valid tx the chain itself refuses (owner mismatch, missing
    // token account, insufficient balance…) is a PAYMENT error, not an infra
    // error: preflight simulation throws here and used to fall into the 502
    // below. 502 is reserved for the RPC being unreachable or broken.
    if (/simulation failed|custom program error|InstructionError|insufficient (funds|lamports)|invalid account|AccountNotFound|Attempt to debit/i.test(m))
      return { ok: false, code: 402, body: { error: 'transaction_rejected_in_simulation', detail: m.slice(0, 300),
        hint: 'the transaction is well-formed but cannot execute on-chain as built; check that the source token account exists, is funded, and is owned by the signing authority' } };
    return { ok: false, code: 502, body: { error: 'settlement_failed', detail: m.slice(0, 600) } };
  }
  })();
  return Promise.race([work, new Promise(r => setTimeout(() => r({ ok: false, code: 502,
    body: { error: 'settlement_timeout', hint: 'the RPC did not answer in time; if the transaction landed anyway, claim it via the pay-then-claim scheme: POST {"tx":"<signature>"} with your question' } }), 80000).unref())]);
}

module.exports = { requirements, paymentRequiredHeader, settle, feePayerAddress, CAIP2 };
