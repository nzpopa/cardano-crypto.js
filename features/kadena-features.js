// const signing = require("./signing")
const derivation = require("./key-derivation")
const Module = require('../lib.js')

async function kadenaMnemonicToRootKeypair(mnemonic) {
  return derivation.mnemonicToRootKeypair(mnemonic, 3)
}

// root :: [UInt8]
function kadenaGenKeypair(root, index) {
  const derivationScheme = 2;
  const rootBuffer = Buffer.from(root)
  const xprv = derivation.derivePrivate(rootBuffer, index, derivationScheme);
  const xpub = xprv.slice(64, 96);
  return [xprv, xpub];
}

module.exports = {
  kadenaMnemonicToRootKeypair,
  kadenaGenKeypair,
}
