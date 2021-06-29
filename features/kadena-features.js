const bip39 = require('bip39')
const signing = require("./signing")
const derivation = require("./key-derivation")
const Module = require('../lib.js')

async function kadenaMnemonicToRootKeypair(mnemonic) {
  return derivation.mnemonicToRootKeypair(mnemonic, 3)
}

function kadenaGenMnemonic() {
  return bip39.generateMnemonic()
}

function kadenaGenKeypair(root, index) {
  const derivationScheme = 2;
  const rootBuffer = Buffer.from(root)
  const xprv = derivation.derivePrivate(rootBuffer, index, derivationScheme);
  const xpub = new Buffer(xprv.slice(64, 96))
  return [xprv.buffer, xpub.buffer];
}

function kadenaSign(msg, xprv) {
  const xprvBuf = Buffer.from(xprv);
  const msgBuf = Buffer.from(msg)
  return signing.sign(msgBuf, xprvBuf).buffer;
}

function kadenaVerify(msg, publicKey, sig) {
  const msgBuf = Buffer.from(msg);
  const pubKeyBuf = Buffer.from(publicKey);
  const sigBuf = Buffer.from(sig);
  return signing.verify(msgBuf, pubKeyBuf, sigBuf);
}

module.exports = {
  kadenaGenMnemonic,
  kadenaMnemonicToRootKeypair,
  kadenaGenKeypair,
  kadenaSign,
  kadenaVerify
}
