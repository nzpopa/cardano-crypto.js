const signing = require("./signing")
const derivation = require("./key-derivation")
const Module = require('../lib.js')

async function kadenaMnemonicToRootKeypair(mnemonic) {
  return derivation.mnemonicToRootKeypair(mnemonic, 3)
}

// root :: [Word8]
function kadenaGenKeypair(root, index) {
  const derivationScheme = 2;
  const rootBuffer = Buffer.from(root)
  const xprv = derivation.derivePrivate(rootBuffer, index, derivationScheme);
  const xpub = xprv.slice(64, 96);
  return [xprv, xpub];
}

function kadenaSign(msg, xprv) {
  const xprvBuf = Buffer.from(xprv);
  const msgBuf = Buffer.from(msg)
  return signing.sign(msgBuf, xprvBuf);
}

function kadenaVerify(msg, publicKey, sig) {
  const msgBuf = Buffer.from(msg);
  const pubKeyBuf = Buffer.from(publicKey);
  const sigBuf = Buffer.from(sig);
  return signing.verify(msgBuf, pubKeyBuf, sigBuf);
}

module.exports = {
  kadenaMnemonicToRootKeypair,
  kadenaGenKeypair,
  kadenaSign,
  kadenaVerify
}
