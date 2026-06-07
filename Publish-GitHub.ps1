param(
  [string]$RepoName = "MemCheckOverwatch",
  [string]$Description = "Non-injecting Windows-native MinGW memory checker with AI Overwatch reports.",
  [switch]$Private
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
  [Environment]::GetEnvironmentVariable("Path", "User")

if (!(Get-Command gh -ErrorAction SilentlyContinue)) {
  throw "GitHub CLI is not installed or not on PATH."
}

gh auth status
if ($LASTEXITCODE -ne 0) {
  throw "GitHub CLI is not authenticated. Run: gh auth login --web --git-protocol https"
}

$visibility = if ($Private) { "--private" } else { "--public" }

if (!(git remote get-url origin 2>$null)) {
  gh repo create $RepoName $visibility --source . --remote origin --description $Description
} else {
  Write-Host "Remote origin already exists: $(git remote get-url origin)"
}

git branch -M main
git push -u origin main
