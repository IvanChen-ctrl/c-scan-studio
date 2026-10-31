#Requires -Version 5.1
# Manual public publishing. Does not read or store GitHub credentials.
$ErrorActionPreference='Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Set-Location -LiteralPath $root
Write-Host 'C-Scan Studio: reviewed public GitHub publishing' -ForegroundColor Cyan
Write-Host 'All public uploads will be reviewed; no private data/models/logs are intended for publishing.'
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'GitHub CLI (gh) not found. Install from https://cli.github.com/ then run gh auth login.' }
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'Git not found. Install Git for Windows first.' }
& gh auth status
if ($LASTEXITCODE -ne 0) { throw 'Log in with: gh auth login, then rerun. Never paste tokens into scripts.' }
Write-Host 'Preparing audited source-only ZIP and local integrity manifest.'
$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) { & python scripts/build_release.py --outdir (Join-Path $env:TEMP 'CScanStudioRelease'); if ($LASTEXITCODE -ne 0) { throw 'Release build failed; nothing may be published.' } }
else { throw 'Publishing requires Python 3.10+ to rebuild and verify the source allowlist. Run GUI bootstrap or install Python.' }
if (-not (Test-Path -LiteralPath '.git')) { & git init -b main }
# Stage ONLY files approved by the generated manifest, not broad glob patterns.
$publicFiles = @(Import-Csv -LiteralPath 'FILE_INTEGRITY_SHA256.csv' -Encoding UTF8 | ForEach-Object { $_.Path })
if (-not $publicFiles -or $publicFiles.Count -lt 20) { throw 'Release manifest is empty or unexpectedly short.' }
$publicFiles += 'FILE_INTEGRITY_SHA256.csv'
& git add -- $publicFiles
if ($LASTEXITCODE -ne 0) { throw 'git add failed.' }
Write-Host 'Staged files to be public:' -ForegroundColor Yellow
& git diff --cached --name-only
Write-Host 'Review the above file names carefully. Your token or any private data must NOT appear.'
$answer = Read-Host 'To create/push a PUBLIC GitHub repo named c-scan-studio, enter PUBLISH exactly'
if ($answer -cne 'PUBLISH') { Write-Host 'Cancelled. No commit/push made.'; exit 2 }
& git diff --cached --quiet
if ($LASTEXITCODE -eq 1) { & git commit -m 'Release C-Scan Studio v3.3 unified console and security evidence' }
if ($LASTEXITCODE -ne 0) { throw 'git commit failed. Configure git user.name and user.email and retry.' }
& git remote get-url origin *> $null
$hasRemote = ($LASTEXITCODE -eq 0)
if ($hasRemote) {
  Write-Host 'Existing origin remote:' -ForegroundColor Cyan
  & git remote get-url origin
  $confirmRemote = Read-Host 'To PUSH to this existing remote, enter PUSH'
  if ($confirmRemote -cne 'PUSH') { Write-Host 'No push performed.'; exit 2 }
  & git push -u origin HEAD:main
} else {
  & gh repo create c-scan-studio --public --source . --remote origin --push --description 'Local-first, auditable Windows disk analyzer and allowlisted cache cleaner'
}
if ($LASTEXITCODE -ne 0) { throw 'GitHub create/push failed; check GitHub CLI output.' }
Write-Host 'Repository push command completed. Verify URL and Actions in the browser before claiming security evidence.' -ForegroundColor Green
