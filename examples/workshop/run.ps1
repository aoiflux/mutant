param([Parameter(Mandatory = $true)][string]$Step)

$src = "examples/workshop/$Step.mut"
$bin = "examples/workshop/$Step.mu"

mutant gen --src $src --dev
if ($LASTEXITCODE -eq 0) { mutant $bin --dev }
