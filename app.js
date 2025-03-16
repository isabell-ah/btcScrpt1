const crypto = require('crypto');
const elliptic = require('elliptic');
const ec = new elliptic.ec('secp256k1');

//  Hashing Functions
const sha256 = (data) =>
  crypto.createHash('sha256').update(data, 'hex').digest();
const ripemd160 = (data) =>
  crypto.createHash('ripemd160').update(data).digest('hex');

// ============================================
// // ===== Exercise 1: P2PKH =====
// ============================================

// step1: Generate Keypair
const keyPair = ec.genKeyPair();
const privateKey = keyPair.getPrivate('hex');
const publicKey = keyPair.getPublic('hex');
const pubKeyHash = ripemd160(sha256(publicKey));

console.log(`Private Key: ${privateKey}`);
console.log(`Public Key: ${publicKey}`);
console.log(`Public Key Hash: ${pubKeyHash}`);

//  Step 2: Construct P2PKH Locking Script
const lockingScript = [
  'OP_DUP',
  'OP_HASH160',
  pubKeyHash,
  'OP_EQUALVERIFY',
  'OP_CHECKSIG',
];

console.log(`\nLocking Script: ${lockingScript.join(' ')}`);

//  Step 3: Simulate an Unlocking Script
const unlockingScript = (signature, pubKey) => [signature, pubKey];

//  Step 4: Execute P2PKH Script
const executeP2PKH = (signature, pubKey) => {
  let stack = unlockingScript(signature, pubKey);

  console.log(`\nExecuting P2PKH Script...`);
  console.log(`Stack before execution: ${JSON.stringify(stack, null, 2)}`);

  // OP_DUP: Duplicate the top item (public key)
  stack.push(stack[stack.length - 1]);
  console.log(`\nOP_DUP applied. Stack: ${JSON.stringify(stack)}`);

  // OP_HASH160: Hash the public key
  const hashedPubKey = ripemd160(sha256(stack.pop()));
  stack.push(hashedPubKey);
  console.log(`\nOP_HASH160 applied. Stack: ${JSON.stringify(stack)}`);

  // OP_EQUALVERIFY: Compare with pubKeyHash
  if (stack.pop() !== pubKeyHash) {
    console.log(' OP_EQUALVERIFY failed: Public key hash mismatch.');
    return false;
  }
  console.log('OP_EQUALVERIFY passed.');

  // OP_CHECKSIG: Verify signature (dummy logic)
  if (signature === 'dummy_signature') {
    console.log('\nOP_CHECKSIG: Signature is valid.');
    return true;
  } else {
    console.log('\nOP_CHECKSIG: Signature verification failed.');
    return false;
  }
};

//  Step 5: Test the Execution
const dummySignature = 'dummy_signature';
const p2pkhResult = executeP2PKH(dummySignature, publicKey);
console.log(`\nP2PKH Script Execution Result: ${p2pkhResult}`);

// ============================================
// // ===== Exercise 2: 2-of-3 Multisig  =====
// ============================================
console.log('\n      Exercise 2: 2-of-3 Multisig ');
//  Step 1: Generate 3 Keypairs
const keyPairs = Array.from({ length: 3 }, () => ec.genKeyPair());
const privateKeys = keyPairs.map((kp) => kp.getPrivate('hex'));
const pubKeys = keyPairs.map((kp) => kp.getPublic('hex'));

console.log(`Private Keys: ${JSON.stringify(privateKeys, null, 2)}`);
console.log(`Public Keys: ${JSON.stringify(pubKeys, null, 2)}`);

//  Step 2: Simulate Multisig Script
const multisigScript = (signatures, pubKeys, requiredSigs = 2) => {
  let validSigs = 0;
  let sigIndex = 0;
  let pubKeyIndex = 0;

  while (sigIndex < signatures.length && pubKeyIndex < pubKeys.length) {
    console.log(
      `\nChecking signature ${signatures[sigIndex]} with public key:  ${pubKeys[pubKeyIndex]}`
    );

    if (signatures[sigIndex].startsWith('sig')) {
      validSigs++;
      sigIndex++;
    }
    pubKeyIndex++;
  }

  if (validSigs >= requiredSigs) {
    console.log(`\n${validSigs} signatures verified.`);
    return true;
  } else {
    console.log('Not enough valid signatures.');
    return false;
  }
};

const multisigResult = multisigScript(['sig1', 'sig2'], pubKeys);
console.log(`\nMultisig Script Execution Result: ${multisigResult}`);

//  Simulating Spending
const simulateSpending = (signatures, pubKeys, requiredSigs = 2) => {
  console.log('\n  Simulating Spending...');
  const result = multisigScript(signatures, pubKeys, requiredSigs);

  if (result) {
    console.log('\nTransaction successfully spent with 2 valid signatures!!');
  } else {
    console.log('\nFailed to spend transaction: Not enough valid signatures.');
  }

  return result;
};

//  Simulate spending with 2 valid signatures
simulateSpending(['sig1', 'sig3'], pubKeys);
