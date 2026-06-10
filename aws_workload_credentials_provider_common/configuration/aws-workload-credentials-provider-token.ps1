# AWS Workload Credentials Provider - SSRF Token Seed Script
# Generates a random SSRF token and writes it to the token file.

$ErrorActionPreference = "Stop"

. "$PSScriptRoot\common.ps1"

$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $bytes = New-Object byte[] 32
    $rng.GetBytes($bytes)
    $token = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
    Set-Content -Path $SSRF_TOKEN_FILE -Value $token -NoNewline
} finally {
    [Array]::Clear($bytes, 0, $bytes.Length)
    $sha.Dispose()
    $rng.Dispose()
}
