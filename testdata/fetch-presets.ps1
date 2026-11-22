$ErrorActionPreference = "Continue"
$dst = "D:\ConvertZapretToNFQWS\testdata\flowseal"
$names = @(
  "general",
  "general (ALT)", "general (ALT2)", "general (ALT3)", "general (ALT4)", "general (ALT5)",
  "general (ALT6)", "general (ALT7)", "general (ALT8)", "general (ALT9)", "general (ALT10)",
  "general (ALT11)", "general (ALT12)", "general (ALT13)",
  "general (EXP)",
  "general (FAKE TLS AUTO)", "general (FAKE TLS AUTO ALT)", "general (FAKE TLS AUTO ALT2)", "general (FAKE TLS AUTO ALT3)",
  "general (SIMPLE FAKE)", "general (SIMPLE FAKE ALT)", "general (SIMPLE FAKE ALT2)"
)
foreach ($n in $names) {
  $enc = $n -replace ' ', '%20'
  $url = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/$enc.bat"
  $out = Join-Path $dst "$n.bat"
  try {
    Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -TimeoutSec 30 | Out-Null
    Write-Output ("OK   " + $n)
  } catch {
    Write-Output ("FAIL " + $n + " : " + $_.Exception.Message)
  }
}
