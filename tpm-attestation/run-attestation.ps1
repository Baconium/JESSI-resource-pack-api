$ErrorActionPreference = 'Stop'

$OutDir = Join-Path $env:USERPROFILE "jessi-attestation"
$KeyName = 'JessiRelayAttestationKey'

# These values are different on the windows machine that actually runs the verification
$RelayUser = '[REDACTED]'
$RelayHost = '[REDACTED]'
$RelayPath = '~/jessi/resourcepacks'

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$sshKey = Join-Path $env:USERPROFILE ".ssh\id_ed25519_jessi_relay"
$knownHosts = Join-Path $env:USERPROFILE ".ssh\known_hosts"
$tmpDir = Join-Path $env:TEMP ("jessi-verify-" + (Get-Random).ToString())
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$batFile = Join-Path $env:TEMP ("jessi-scp-" + (Get-Random).ToString() + ".bat")

$scpFlags = "-q -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$knownHosts -i $sshKey"

Write-Output "fetching files from the webserver..."
$files = @(
    "common.php","session.php","wait.php","pack.php","deliver.php",
    "verify-test-vector.php",".htaccess","data/.htaccess"
)
foreach ($f in $files) {
    $localName = $f -replace '/', '_'
    $dst = Join-Path $tmpDir $localName
    $src = "${RelayUser}@${RelayHost}:${RelayPath}/${f}"
    $cmd = "scp $scpFlags $src $dst"
    Set-Content -Path $batFile -Value $cmd -Encoding ASCII
    cmd /c $batFile 2>&1 | Out-Null
    Write-Output "  $f"
}

Write-Output "computing hashes..."
$hashes = @{}
Get-ChildItem $tmpDir | ForEach-Object {
    $hash = Get-FileHash $_.FullName -Algorithm SHA256
    $hashes[$_.Name] = @{ sha256 = $hash.Hash.ToLower(); size = $_.Length }
}

$doc = @{
    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    path = $RelayPath
    files = $hashes
}

$docJson = $doc | ConvertTo-Json -Depth 4
$docBytes = [System.Text.Encoding]::UTF8.GetBytes($docJson)

try {
    $k = [System.Security.Cryptography.CngKey]::Open(
        $KeyName,
        [System.Security.Cryptography.CngProvider]::new(
            "Microsoft Platform Crypto Provider"))
    $rsa = New-Object System.Security.Cryptography.RSACng -ArgumentList $k
    $sig = $rsa.SignData(
        $docBytes,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $sigB64 = [Convert]::ToBase64String($sig)
} catch {
    Write-Error "TPM signing failed: $_"
    exit 1
}

$attestation = $doc.Clone()
$attestation.signature = @{
    algorithm = "RSA-PKCS1-SHA256"
    value = $sigB64
    keyName = $KeyName
    keySize = $rsa.Key.KeySize
}
$attestation.timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")

$json = $attestation | ConvertTo-Json -Depth 6
$stamp = (Get-Date -Format "yyyyMMdd-HHmmss")
$json | Out-File (Join-Path $OutDir "attestation-$stamp.json") -Encoding ASCII
$json | Out-File (Join-Path $OutDir "attestation-latest.json") -Encoding ASCII
Write-Output "attestation saved: $OutDir\attestation-latest.json"

Write-Output "uploading attestation to relay server..."
$localFile = Join-Path $OutDir "attestation-latest.json"
$remoteDest = "${RelayUser}@${RelayHost}:${RelayPath}/attestation.json"
$cmd = "scp $scpFlags $localFile $remoteDest"
Set-Content -Path $batFile -Value $cmd -Encoding ASCII
cmd /c $batFile 2>&1 | Out-Null
Write-Output "uploaded: https://baconium.dev/jessi/resourcepacks/attestation.json"

$rsa.Dispose()
$k.Dispose()
Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
Remove-Item -Force $batFile -ErrorAction SilentlyContinue