const crypto = require('crypto');
const elliptic = require('elliptic');
const ec = new elliptic.ec('secp256k1');

// 🔹 Hashing Functions
const sha256 = (data) =>
  crypto.createHash('sha256').update(data, 'hex').digest();
const ripemd160 = (data) =>
  crypto.createHash('ripemd160').update(data).digest('hex');

// ============================================
// // ===== Exercise 2: 2-of-3 Multisig  =====
// ============================================

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
