#!/usr/bin/env node
// Local mirror of Cairn's x402 conformance battery (report 0a5422f4) against
// a test instance on PORT. Builds real signed/unsigned VersionedTransactions
// so validate() sees exactly what a prober sends. Run:
//   PORT=8099 node serve.js &   then   node test-battery.js 8099
'use strict';
const { Keypair, PublicKey, TransactionMessage, VersionedTransaction,
  TransactionInstruction, ComputeBudgetProgram } = require('@solana/web3.js');
const x402 = require('./x402');

const PORT = process.argv[2] || 8099;
const URL = process.env.BATTERY_URL || `http://127.0.0.1:${PORT}/api/ask`;
const TOKEN = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const ATA_PROGRAM = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
const USDC = new PublicKey(x402.requirements().asset);
const PAYTO = new PublicKey(x402.requirements().payTo);
const FEEPAYER = new PublicKey(x402.feePayerAddress());

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

const AMOUNT = Number(x402.requirements().amount); // price in atomic units
const auth = Keypair.generate(); // stands in for the paying wallet
function buildTx({ mint = USDC, amount = AMOUNT, decimals = 6, dest = null,
  sign = true, forge = false, extraIx = null, cuPrice = 1000 } = {}) {
  const d = dest || ata(PAYTO, mint);
  const ixs = [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 6000 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: cuPrice }),
    transferChecked(ata(auth.publicKey, mint), mint, d, auth.publicKey, amount, decimals),
  ];
  if (extraIx) ixs.push(extraIx);
  const msg = new TransactionMessage({ payerKey: FEEPAYER,
    recentBlockhash: Keypair.generate().publicKey.toBase58(), // fake; never broadcast
    instructions: ixs }).compileToV0Message();
  const tx = new VersionedTransaction(msg);
  if (sign) tx.sign([auth]);
  if (forge) tx.signatures[1] = Buffer.from(Array(64).fill(7)); // wrong bytes
  return Buffer.from(tx.serialize()).toString('base64');
}

const header = (txB64, scheme = 'exact', network = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp') =>
  Buffer.from(JSON.stringify({ x402Version: 2, accepted: { scheme, network },
    payload: { transaction: txB64 } })).toString('base64');

async function post(name, expectStatus, expectError, payHeader) {
  const r = await fetch(URL, { method: 'POST',
    headers: { 'Content-Type': 'application/json',
      ...(payHeader ? { 'PAYMENT-SIGNATURE': payHeader } : {}) },
    body: JSON.stringify({ question: 'battery probe' }) });
  const text = await r.text();
  let body = {}; let jsonOk = true;
  try { body = JSON.parse(text); } catch { jsonOk = false; }
  const ok = r.status === expectStatus && jsonOk &&
    (!expectError || body.error === expectError);
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}: ${r.status} ${body.error || ''}` +
    (ok ? '' : ` (wanted ${expectStatus} ${expectError || ''}; json=${jsonOk}) ${text.slice(0, 200)}`));
  return ok;
}

(async () => {
  let pass = 0, total = 0;
  const t = async (...a) => { total++; if (await post(...a)) pass++; };

  await t('no_payment_402', 402, 'payment_required');
  await t('garbage_transaction', 402, 'undeserializable_transaction', header('aGVsbG8gd29ybGQ='));
  await t('header_not_b64_json', 400, 'header_not_base64_json', '!!!not-base64!!!');
  await t('unsigned_transaction', 402, 'payer_signature_missing', header(buildTx({ sign: false })));
  await t('forged_signature', 402, 'payer_signature_invalid', header(buildTx({ forge: true })));
  await t('wrong_scheme', 400, 'unsupported_scheme', header(buildTx(), 'evm-exact'));
  await t('wrong_network', 400, 'unsupported_network', header(buildTx(), 'exact', 'solana:devnet'));
  await t('wrong_asset', 402, 'wrong_asset',
    header(buildTx({ mint: new PublicKey('So11111111111111111111111111111111111111112') })));
  await t('wrong_amount', 402, 'wrong_amount', header(buildTx({ amount: 1 })));
  await t('self_destination', 402, 'wrong_destination',
    header(buildTx({ dest: ata(auth.publicKey, USDC) })));
  await t('extra_instruction', 402, 'unexpected_instruction_program',
    header(buildTx({ extraIx: new TransactionInstruction({
      programId: Keypair.generate().publicKey, data: Buffer.from([1]), keys: [] }) })));
  await t('high_priority_fee', 402, 'fee_too_high', header(buildTx({ cuPrice: 100000000 })));

  // fee_payer_as_source: feePayer as token authority — must be refused.
  {
    const msg = new TransactionMessage({ payerKey: FEEPAYER,
      recentBlockhash: Keypair.generate().publicKey.toBase58(),
      instructions: [
        ComputeBudgetProgram.setComputeUnitLimit({ units: 6000 }),
        ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1000 }),
        transferChecked(ata(FEEPAYER, USDC), USDC, ata(PAYTO, USDC), FEEPAYER, AMOUNT, 6),
      ] }).compileToV0Message();
    const tx = new VersionedTransaction(msg);
    total++;
    if (await post('fee_payer_as_authority', 402, 'fee_payer_must_not_appear_in_instructions',
      header(Buffer.from(tx.serialize()).toString('base64')))) pass++;
  }

  // fee_payer_as_source, Cairn's re-test variant: the transfer source is the
  // FEE PAYER'S ATA (a distinct address, so no index-0 overlap) with a third
  // party as authority. Passes every layout check, would die in simulation —
  // must be refused at validation, not as a 502.
  {
    const msg = new TransactionMessage({ payerKey: FEEPAYER,
      recentBlockhash: Keypair.generate().publicKey.toBase58(),
      instructions: [
        ComputeBudgetProgram.setComputeUnitLimit({ units: 6000 }),
        ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1000 }),
        transferChecked(ata(FEEPAYER, USDC), USDC, ata(PAYTO, USDC), auth.publicKey, AMOUNT, 6),
      ] }).compileToV0Message();
    const tx = new VersionedTransaction(msg);
    tx.sign([auth]);
    total++;
    if (await post('fee_payer_ata_as_source', 402, 'fee_payer_must_not_move_funds',
      header(Buffer.from(tx.serialize()).toString('base64')))) pass++;
  }

  // A fully valid, properly signed payload must clear validate() — checked
  // directly so nothing is broadcast from a test run.
  {
    total++;
    const path = require('path');
    const src = require('fs').readFileSync(path.join(__dirname, 'x402.js'), 'utf8');
    const m = new module.constructor();
    m.paths = require('module')._nodeModulePaths(__dirname);
    m._compile(src + '\nmodule.exports._validate = validate;', path.join(__dirname, 'x402.js'));
    const r = m.exports._validate(buildTx());
    if (r.ok) { pass++; console.log('PASS valid_payload_clears_validate'); }
    else console.log('FAIL valid_payload_clears_validate:', JSON.stringify(r));
  }

  // Burst: 35 rapid no-payment POSTs must all answer 402, never 429.
  {
    total++;
    let limited = 0;
    for (let i = 0; i < 35; i++) {
      const r = await fetch(URL, { method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': '203.0.113.9' },
        body: '{}' });
      if (r.status === 429) limited++;
    }
    if (!limited) { pass++; console.log('PASS burst_35_no_429'); }
    else console.log(`FAIL burst_35_no_429: ${limited} throttled`);
  }

  // Rail preflight (Cairn report 34cb30f7): the advertised payTo must be able
  // to RECEIVE — the vault's USDC ATA must exist on mainnet, or every correct
  // payment dies at TransferChecked in simulation and the endpoint is
  // rail-cannot-receive no matter how clean its rejections are.
  {
    total++;
    try {
      const r = await fetch('https://api.mainnet-beta.solana.com', { method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getAccountInfo',
          params: [ata(PAYTO, USDC).toBase58(), { encoding: 'base64' }] }) });
      const j = await r.json();
      if (j.result && j.result.value) { pass++; console.log('PASS destination_usdc_ata_exists'); }
      else console.log('FAIL destination_usdc_ata_exists: ATA missing on-chain — run tools/create-vault-usdc-ata.js');
    } catch (e) { console.log('FAIL destination_usdc_ata_exists (rpc error):', e.message); }
  }

  console.log(`\n${pass}/${total} passed`);
  process.exit(pass === total ? 0 : 1);
})();
