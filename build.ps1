$ErrorActionPreference = "Stop"

$modulePath = "github.com/edgarpsda/devsecops-kit"
$repoRoot = (Get-Location).Path.Replace("\", "/")

function Get-GitValue {
    param (
        [string[]]$Arguments,
        [string]$Fallback
    )

    try {
        $value = & git -c "safe.directory=$repoRoot" @Arguments 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($value)) {
            return $Fallback
        }
        return $value.Trim()
    } catch {
        return $Fallback
    }
}

$version = Get-GitValue -Arguments @("describe", "--tags", "--always") -Fallback "development"
$commit = Get-GitValue -Arguments @("rev-parse", "--short", "HEAD") -Fallback "none"
$date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$ldflags = "-X $modulePath/cli/cmd.version=$version -X $modulePath/cli/cmd.commit=$commit -X $modulePath/cli/cmd.date=$date"

Write-Host "Building DevSecOps Kit"
Write-Host "Version: $version"
Write-Host "Commit : $commit"
Write-Host "Built  : $date"

go build -buildvcs=false -ldflags $ldflags -o devsecops.exe ./cmd/devsecops
