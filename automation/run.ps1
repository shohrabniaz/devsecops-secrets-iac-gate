Set-Location (Split-Path -Parent $PSScriptRoot)
python -m src.cli scan --path .\fixtures --fail-on high
if ($LASTEXITCODE -eq 2) { Write-Host 'Gate correctly failed on bad fixtures' }
python tests\test_smoke.py
