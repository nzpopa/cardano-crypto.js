#!/usr/bin/env sh

rm -f kadena-crypto.js
npm run build
browserify index.js --standalone lib > kadena-crypto.js
