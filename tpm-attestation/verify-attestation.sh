#!/bin/bash
set -euo pipefail

ATEST="${1:-}"
AIK="${2:-}"
if [ -z "$ATEST" -o -z "$AIK" ]; then
    echo "Usage: $0 <attestation.json> <aik-pub.json>"
    exit 1
fi

echo "JESSI Resource Pack API Verification"
TIMESTAMP=$(jq -r '.timestamp' "$ATEST")
echo "Timestamp: $TIMESTAMP"

jq 'del(.signature)' "$ATEST" > /tmp/attest-body.json
jq -r '.signature.value' "$ATEST" | openssl base64 -d -A > /tmp/sig.bin

# this shit is fucking disgusting, please kill me
python3 -c "
import base64, sys, json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
with open('$AIK') as f: aik = json.load(f)
mod = int.from_bytes(base64.b64decode(aik['modulus']), 'big')
exp = int.from_bytes(base64.b64decode(aik['exponent']), 'big')
pub = rsa.RSAPublicNumbers(exp, mod).public_key()
spki = pub.public_bytes(encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
with open('/tmp/aik-pub.pem', 'wb') as f: f.write(spki)
"
echo "AIK public key loaded: $(grep -c BEGIN /tmp/aik-pub.pem) lines"

if openssl dgst -sha256 -verify /tmp/aik-pub.pem -signature /tmp/sig.bin /tmp/attest-body.json; then
    echo "signature verified!"
else
    echo "signature verification failed! please contact BaconMania"
    exit 1
fi

echo ""
echo "hashes:"
jq -r '.files | to_entries[] | "\(.key): \(.value.sha256)"' "$ATEST"