# In-A-Lign Quick Scanner for PowerShell
# Usage: .\scan.ps1 "text to scan"

param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Args
)

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
python "$scriptPath\inalign_scanner.py" --hook-mode @Args
