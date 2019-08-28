#/bin/bash

rm -rf dist/
npm run build
cp index.html dist/

rm -rf ../../priv/www/login
cp -R dist/ ../../priv/www/login

