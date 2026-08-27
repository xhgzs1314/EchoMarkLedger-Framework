@echo off
echo ========================================
echo Building EchoMarkLedger Version...
echo ========================================
call esbuild src/entry.js --bundle --outfile=dist/EchoMarkLedger.js --format=iife --global-name=EchoMarkSys --minify --keep-names

echo ========================================
echo Building EchoMarkLedger ALL Version...
echo ========================================
call esbuild src/entry-full.js --bundle --outfile=dist/EchoMarkLedger-secure.js --format=iife --global-name=EchoMarkSys --minify --keep-names

echo ========================================
echo Built Finished
echo   - dist/EchoMarkLedger.js       (core)
echo   - dist/EchoMarkLedger-secure.js (all)
echo ========================================