#!/bin/bash
# Tests for Bitcoin address support in hex2blf / blfchk
# Проверяет, что hex2blf принимает как hex hash160, так и биткоин-адреса,
# и что bloom-фильтр корректно работает с blfchk.

PASS=0
FAIL=0

BIN_DIR="$(cd "$(dirname "$0")/.." && pwd)"
HEX2BLF="$BIN_DIR/hex2blf"
BLFCHK="$BIN_DIR/blfchk"
TMPDIR_TEST="$(mktemp -d)"

fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
cleanup() { rm -rf "$TMPDIR_TEST"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Valid Bitcoin addresses derived from known hash160 values in example.hex
# Generated with standard Base58Check encoding.
#
# P2PKH (version=0x00, prefix '1'):
ADDR1="1Jc7yHzRK6cW5brDnq5GH2fRAWC7bUsN9k"
HASH1="c11e8406796ea352075234a0d50df5db7c46b3c2"

ADDR2="1GdmecymAMVCmpvKbUGA3Sapz7qi7VdQMY"
HASH2="ab7e21d65f521e163884d81aea511ec69ef98e46"

# P2SH (version=0x05, prefix '3'):
ADDR3="3KJ8tqUrrzvtAmYeuvjrhf2MK2Uq87WYy6"
HASH3="c11e8406796ea352075234a0d50df5db7c46b3c2"   # same hash160 as ADDR1

# A hex hash160 that is NOT in any address we load
ABSENT_HASH="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# TEST 1: hex2blf accepts hex hash160 input (regression test)
# ---------------------------------------------------------------------------
BLF1="$TMPDIR_TEST/test1.blf"
INPUT1="$TMPDIR_TEST/input1.txt"
echo "$HASH1" > "$INPUT1"
echo "$HASH2" >> "$INPUT1"

if "$HEX2BLF" "$INPUT1" "$BLF1" 2>&1 | grep -q "Loaded 2"; then
  pass "TEST 1: hex2blf loads 2 hex hash160 entries"
else
  fail "TEST 1: hex2blf should load 2 hex hash160 entries"
fi

# ---------------------------------------------------------------------------
# TEST 2: hex2blf accepts Bitcoin P2PKH address input
# ---------------------------------------------------------------------------
BLF2="$TMPDIR_TEST/test2.blf"
INPUT2="$TMPDIR_TEST/input2.txt"
echo "$ADDR1" > "$INPUT2"
echo "$ADDR2" >> "$INPUT2"

if "$HEX2BLF" "$INPUT2" "$BLF2" 2>&1 | grep -q "Loaded 2"; then
  pass "TEST 2: hex2blf loads 2 Bitcoin P2PKH addresses"
else
  fail "TEST 2: hex2blf should load 2 Bitcoin P2PKH addresses"
fi

# ---------------------------------------------------------------------------
# TEST 3: hex2blf accepts a mixed file (both addresses and hex hashes)
# ---------------------------------------------------------------------------
BLF3="$TMPDIR_TEST/test3.blf"
INPUT3="$TMPDIR_TEST/input3.txt"
printf '%s\n%s\n%s\n' "$ADDR1" "$HASH2" "$ADDR3" > "$INPUT3"

if "$HEX2BLF" "$INPUT3" "$BLF3" 2>&1 | grep -q "Loaded 3"; then
  pass "TEST 3: hex2blf loads 3 mixed entries (2 addresses + 1 hex)"
else
  fail "TEST 3: hex2blf should load 3 mixed entries"
fi

# ---------------------------------------------------------------------------
# TEST 4: blfchk finds hashes that were added via Bitcoin addresses
# Bloom filter built from addresses; query it with hex hash160 values.
# ---------------------------------------------------------------------------
FOUND=$(echo "$HASH1" | "$BLFCHK" "$BLF2" 2>/dev/null)
if [ "$FOUND" = "$HASH1" ]; then
  pass "TEST 4: blfchk finds hash160 of $ADDR1 in bloom filter built from addresses"
else
  fail "TEST 4: blfchk should find hash160 of $ADDR1 (got: '$FOUND')"
fi

FOUND2=$(echo "$HASH2" | "$BLFCHK" "$BLF2" 2>/dev/null)
if [ "$FOUND2" = "$HASH2" ]; then
  pass "TEST 4b: blfchk finds hash160 of $ADDR2 in bloom filter built from addresses"
else
  fail "TEST 4b: blfchk should find hash160 of $ADDR2 (got: '$FOUND2')"
fi

# ---------------------------------------------------------------------------
# TEST 5: blfchk does NOT return false positives for absent hashes
# ---------------------------------------------------------------------------
NOT_FOUND=$(echo "$ABSENT_HASH" | "$BLFCHK" "$BLF2" 2>/dev/null)
if [ -z "$NOT_FOUND" ]; then
  pass "TEST 5: blfchk correctly rejects absent hash"
else
  fail "TEST 5: blfchk should not find absent hash (got: '$NOT_FOUND')"
fi

# ---------------------------------------------------------------------------
# TEST 6: P2SH address (starts with '3') is handled correctly
# ---------------------------------------------------------------------------
BLF6="$TMPDIR_TEST/test6.blf"
INPUT6="$TMPDIR_TEST/input6.txt"
echo "$ADDR3" > "$INPUT6"
if "$HEX2BLF" "$INPUT6" "$BLF6" 2>&1 | grep -q "Loaded 1"; then
  pass "TEST 6a: hex2blf loads P2SH address"
else
  fail "TEST 6a: hex2blf should load P2SH address"
fi

FOUND6=$(echo "$HASH3" | "$BLFCHK" "$BLF6" 2>/dev/null)
if [ "$FOUND6" = "$HASH3" ]; then
  pass "TEST 6b: blfchk finds hash160 of P2SH address $ADDR3"
else
  fail "TEST 6b: blfchk should find hash160 of P2SH $ADDR3 (got: '$FOUND6')"
fi

# ---------------------------------------------------------------------------
# TEST 7: invalid/unrecognised lines are skipped silently
# ---------------------------------------------------------------------------
BLF7="$TMPDIR_TEST/test7.blf"
INPUT7="$TMPDIR_TEST/input7.txt"
printf '%s\nINVALID_LINE\n%s\n' "$ADDR1" "$HASH2" > "$INPUT7"

OUTPUT7=$("$HEX2BLF" "$INPUT7" "$BLF7" 2>&1)
LOADED=$(echo "$OUTPUT7" | grep -oP 'Loaded \K[0-9]+')
SKIPPED=$(echo "$OUTPUT7" | grep -oP 'skipped \K[0-9]+')

if [ "$LOADED" = "2" ] && [ "$SKIPPED" = "1" ] && ! echo "$OUTPUT7" | grep -q "Unrecognised line"; then
  pass "TEST 7: hex2blf skips invalid lines silently and reports count"
else
  fail "TEST 7: expected silent skip with Loaded=2 skipped=1, got Loaded=$LOADED skipped=$SKIPPED"
fi

# ---------------------------------------------------------------------------
# TEST 8: bloom filter built from hex hash160 is correctly queried
# (original behaviour regression)
# ---------------------------------------------------------------------------
FOUND8=$(echo "$HASH1" | "$BLFCHK" "$BLF1" 2>/dev/null)
if [ "$FOUND8" = "$HASH1" ]; then
  pass "TEST 8: blfchk finds hash in bloom filter built from hex hash160"
else
  fail "TEST 8: blfchk should find hash in bloom filter built from hex hash160 (got: '$FOUND8')"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
