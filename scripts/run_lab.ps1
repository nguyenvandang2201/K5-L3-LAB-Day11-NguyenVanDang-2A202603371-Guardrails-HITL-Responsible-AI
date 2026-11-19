# Run deterministic checks, live checkpoints and the generated report.
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw 'Create .venv and install requirements.txt first; see README.md.'
}
$env:PYTHONIOENCODING = 'utf-8'
Push-Location -LiteralPath $repoRoot
try {
    & $pythonPath -m pytest tests/smoke tests/public tests/unit -q
    if ($LASTEXITCODE -ne 0) { throw 'Local checks failed.' }
    & $pythonPath src/main.py --part 2
    if ($LASTEXITCODE -ne 0) { throw 'Checkpoint 2 failed.' }
    & $pythonPath src/main.py --part 3
    if ($LASTEXITCODE -ne 0) { throw 'Checkpoint 3 failed. Check your OpenRouter key in .env.' }
    & $pythonPath src/main.py --part 4
    if ($LASTEXITCODE -ne 0) { throw 'Checkpoint 4 failed. Check your OpenAI/Gemini key in .env.' }
    & $pythonPath -m pytest tests/smoke tests/public tests/unit -q
    if ($LASTEXITCODE -ne 0) { throw 'Submission contract checks failed.' }
    & $pythonPath scripts/grade.py --submission-dir . --out outputs/grade_report.json
    if ($LASTEXITCODE -ne 0) { throw 'Report generation failed.' }
    $report = Get-Content -LiteralPath outputs/grade_report.json -Raw | ConvertFrom-Json
    if ($report.technical_failure) { throw 'See outputs/grade_report.json for missing evidence.' }
    $attacks = Get-Content -LiteralPath outputs/attack_results.json -Raw | ConvertFrom-Json
    $attackRows = @($attacks.unsafe_attacks) + @($attacks.guards_attacks)
    if (@($attackRows | Where-Object { $_.error -or $_.layer -eq 'nemo_error' }).Count -gt 0) {
        throw 'Some live attacks failed at runtime; inspect the per-target attack logs.'
    }
    if (@($attacks.unsafe_attacks | Where-Object { $_.leaked }).Count -eq 0) {
        throw 'Red has not leaked a demo value yet; revise prompts and replay before submission.'
    }
    Write-Output 'Live artifacts and generated reports are ready for review in outputs/.'
}
finally {
    Pop-Location
}
