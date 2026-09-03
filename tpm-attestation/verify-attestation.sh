set -euo pipefail

BODY="${1:-}"
SIG="${2:-}"
AIK="${3:-}"
if [ -z "$BODY" -o -z "$SIG" -o -z "$AIK" ]; then
    echo "Usage: $0 <signed-body.bin> <signature.txt> <aik-pub.json>"
    echo ""
    echo "signed-body.bin: https://baconium.dev/jessi/resourcepacks/signed-body.bin"
    echo "signature.txt: the .signature.value field from attestation.json"
    echo "aik-pub.json: tpm-attestation/aik-pub.json in this repo"
    exit 1
fi

echo "JESSI Resource Pack API Attestation"

python3 -c "
import base64, sys, json
from cryptography.hazmat.primitives import serialization
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

if [ ! -f "$SIG" ]; then
    echo "error: signature file $SIG not found"
    exit 1
fi
cat "$SIG" | openssl base64 -d -A > /tmp/sig.bin 2>/dev/null
if [ $? -ne 0 -o ! -s /tmp/sig.bin ]; then
    echo "error: could not decode signature in $SIG"
    echo "make sure it contains only the base64 signature value"
    exit 1
fi
if openssl dgst -sha256 -verify /tmp/aik-pub.pem -signature /tmp/sig.bin "$BODY"; then
    echo "signature verified!"
else
    echo "signature NOT verified! please contact BaconMania"
    exit 1
fi

echo "to verify the attestation against the repo:"
echo ""
echo "1. download both files from the relay:"
echo ""
echo "curl -O https://baconium.dev/jessi/resourcepacks/attestation.json"
echo "curl -O https://baconium.dev/jessi/resourcepacks/signed-body.bin"
echo ""
echo "2. extract the signature:"
echo ""
echo "jq -r '.signature.value' attestation.json > signature.txt"
echo ""
echo "3. run this script:"
echo ""
echo "bash $0 signed-body.bin signature.txt tpm-attestation/aik-pub.json"
echo ""
echo "4. compare the hashes in attestation.json against the repo at the matching commit."
