#!/usr/bin/env sh

# Should be run in the nix-shell provided by shell.nix
# Make sure to run `npm install` on the first go

rm -f kadena-crypto.js
npm run build
browserify index.js --standalone lib > kadena-crypto.js
