<#
.SYNOPSIS
  Recomputes the SHA-256 hash of index.html's inline script and writes it into
  the Content-Security-Policy meta tag.

.DESCRIPTION
  script-src allows the one inline script by hash instead of 'unsafe-inline'.
  Any edit to that script, even whitespace, changes the hash, and a stale hash
  means the browser refuses to run the script and the page stays blank. Run
  this after every edit and before every push.

  The hash is taken over the script text with line endings normalised to LF,
  because the HTML parser does the same before the browser hashes it. That
  keeps the result correct whether Git checked the file out with CRLF or LF.

.PARAMETER Path
  The page to update. Defaults to index.html beside the tools folder.

.PARAMETER Check
  Report only. Exits 1 if the hash in the CSP is stale, 0 if it is current.
  Use this in deploy.ps1 to stop a push that would ship a blank page:
      & "$PSScriptRoot\tools\update-csp-hash.ps1" -Check
      if ($LASTEXITCODE -ne 0) { throw 'CSP hash is stale. Run tools\update-csp-hash.ps1.' }
#>
[CmdletBinding()]
param(
  [string]$Path,
  [switch]$Check
)
$ErrorActionPreference = 'Stop'

# $PSScriptRoot is empty under some invocation forms, and a param-block default
# that reads it then dies inside Join-Path with a message naming neither this
# script's purpose nor the file it wanted. Resolve it here, with fallbacks, and
# fail with something a reader can act on. This script is a mandatory pre-push
# step whose failure ships a blank page, so it must not depend on how it is run.
if (-not $Path) {
  $root = if ($PSScriptRoot) { $PSScriptRoot }
          elseif ($PSCommandPath) { Split-Path -Parent $PSCommandPath }
          else { $null }
  $candidates = @()
  if ($root) { $candidates += (Join-Path $root '..\index.html') }
  $candidates += (Join-Path (Get-Location).Path 'index.html')
  $Path = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $Path) {
    Write-Error "Could not find index.html. Looked in: $($candidates -join '; '). Pass -Path explicitly."
    exit 2
  }
}
if (-not (Test-Path $Path)) { Write-Error "No such file: $Path"; exit 2 }
$Path = (Resolve-Path $Path).Path
$utf8 = New-Object System.Text.UTF8Encoding($false)
$html = [System.IO.File]::ReadAllText($Path, $utf8)

# Inline scripts only: a bare <script> tag with no attributes, at the start of
# a line, so the words "<script>" inside an HTML comment cannot be mistaken for one.
$inline = [regex]::Matches($html, '(?m)^<script>([\s\S]*?)</script>')
if ($inline.Count -ne 1) {
  Write-Error "Expected exactly one inline <script> in $Path, found $($inline.Count). Each inline script needs its own hash in script-src."
  exit 2
}
$body = $inline[0].Groups[1].Value -replace "`r`n", "`n" -replace "`r", "`n"
$sha = [System.Security.Cryptography.SHA256]::Create()
$hash = [Convert]::ToBase64String($sha.ComputeHash($utf8.GetBytes($body)))
$want = "'sha256-$hash'"

$csp = [regex]::Match($html, '<meta http-equiv="Content-Security-Policy" content="[^"]*"')
if (-not $csp.Success) { Write-Error 'No Content-Security-Policy meta tag found.'; exit 2 }
$have = [regex]::Match($csp.Value, "'sha256-[^']*'")
if (-not $have.Success) { Write-Error "The CSP has no 'sha256-...' source in script-src to update."; exit 2 }

if ($have.Value -eq $want) { Write-Host "CSP hash is current: $want"; exit 0 }
if ($Check) { Write-Host "CSP hash is STALE. Have $($have.Value), need $want"; exit 1 }

$newMeta = $csp.Value.Replace($have.Value, $want)
$html = $html.Substring(0, $csp.Index) + $newMeta + $html.Substring($csp.Index + $csp.Length)
[System.IO.File]::WriteAllText($Path, $html, $utf8)
Write-Host "CSP hash updated: $want"
