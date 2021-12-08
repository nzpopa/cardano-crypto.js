var { mnemonicToRootKeypair } = (lib = require("./index"));
var bip39 = require("bip39");

// console.log(lib);

var mnemonic = bip39.generateMnemonic();
var pwd = "123";

function validateMnemonic(input) {
  if (!bip39.validateMnemonic(input)) {
    const e = new Error("Invalid or unsupported mnemonic format:");
    e.name = "InvalidArgumentException";
    throw e;
  }
}

function mnemonicToRootKeypairV3(mnemonic, pwd) {
  validateMnemonic(mnemonic);
  const seed = Buffer.from(bip39.mnemonicToSeedSync(mnemonic), "hex");
  console.log(seed);
  return lib._seedToKeypairV1(pwd, seed);
}

function kadenaMnemonicToRootKeypair(pwd, mnemonic) {
  const pwdBuf = Buffer.from(pwd);
  return mnemonicToRootKeypairV3(mnemonic, pwdBuf);
}

var rootKeyPair = kadenaMnemonicToRootKeypair(pwd, mnemonic);
