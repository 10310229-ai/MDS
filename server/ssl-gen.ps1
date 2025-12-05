<#
  ssl-gen.ps1
  Generates local TLS cert and key into server\ssl\

  Behavior:
  - If mkcert is installed it will create locally-trusted certs (recommended).
  - Else if openssl is available it will create a self-signed cert (not browser-trusted).
  - Otherwise prints guidance and exits with non-zero code.

  Usage (PowerShell):
    powershell -ExecutionPolicy Bypass -File .\server\ssl-gen.ps1

  After success you'll have:
    server\ssl\key.pem
    server\ssl\cert.pem

  The server already reads SSL_KEY_PATH / SSL_CERT_PATH env vars or defaults to server/ssl/key.pem and server/ssl/cert.pem.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$sslDir = Join-Path $scriptDir 'ssl'
Write-Host "Creating or ensuring ssl directory: $sslDir"
New-Item -ItemType Directory -Path $sslDir -Force | Out-Null

function Test-Command([string]$name) {
    return (Get-Command $name -ErrorAction SilentlyContinue) -ne $null
}

$keyPath = Join-Path $sslDir 'key.pem'
$certPath = Join-Path $sslDir 'cert.pem'

if (Test-Command 'mkcert') {
    Write-Host 'mkcert found — generating locally-trusted certificate for localhost and IPs.'
    & mkcert -key-file $keyPath -cert-file $certPath localhost 127.0.0.1 ::1
    if ($LASTEXITCODE -ne 0) { Write-Error "mkcert failed with exit code $LASTEXITCODE"; exit $LASTEXITCODE }
    Write-Host "Generated: $keyPath`n           $certPath"
    exit 0
}

if (Test-Command 'openssl') {
  Write-Host 'mkcert not found; using OpenSSL to generate a self-signed certificate (not browser-trusted).'
  & openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout $keyPath -out $certPath -subj "/CN=localhost"
  if ($LASTEXITCODE -ne 0) { Write-Error "OpenSSL failed with exit code $LASTEXITCODE"; exit $LASTEXITCODE }
  Write-Host "Generated: $keyPath`n           $certPath"
  Write-Warning 'This certificate is self-signed and will not be trusted by browsers unless you import it.'
  exit 0
}

Write-Host "Neither 'mkcert' nor 'openssl' found on PATH — attempting a PowerShell self-signed fallback (PFX + public PEM).
This will create a local self-signed certificate and export a PFX at server/ssl/cert.pfx and a public cert.pem.
The server supports using the PFX directly for HTTPS."

try {
  # Create a new self-signed certificate in the CurrentUser store
  $dns = @('localhost','127.0.0.1','::1')
  Write-Host 'Creating self-signed certificate for:' $dns -Separator ' '
  $cert = New-SelfSignedCertificate -DnsName $dns -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(2)

  # Export PFX (no password)
  $pfxPath = Join-Path $sslDir 'cert.pfx'
  $securePwd = ConvertTo-SecureString -String "" -Force -AsPlainText
  Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$($cert.Thumbprint)" -FilePath $pfxPath -Password $securePwd -Force

  # Export public certificate (DER) then convert to PEM
  $derPath = Join-Path $sslDir 'cert.cer'
  Export-Certificate -Cert "Cert:\CurrentUser\My\$($cert.Thumbprint)" -FilePath $derPath -Force
  $pemPath = Join-Path $sslDir 'cert.pem'
  $bytes = [System.IO.File]::ReadAllBytes($derPath)
  $b64 = [System.Convert]::ToBase64String($bytes)
  $lines = ($b64 -split "(.{64})" | Where-Object { $_ -ne '' }) -join "`n"
  $pem = "-----BEGIN CERTIFICATE-----`n$lines`n-----END CERTIFICATE-----`n"
  Set-Content -Path $pemPath -Value $pem -Encoding ascii

  Write-Host "Generated (PFX + public cert):`n  $pfxPath`n  $pemPath"
  Write-Warning 'The private key remains inside the PFX. The server supports loading the PFX directly. For browser trust, import the cert into your OS trust store.'
  exit 0
} catch {
  Write-Error "PowerShell fallback failed: $($_.Exception.Message)"
  exit 3
}
