# IoCSweep.ps1 | Windows IOC triage

PowerShell 7 script for authorized endpoint investigation. It inventories services, drivers, Run/RunOnce autoruns, scheduled tasks, permanent WMI event filters, running processes, network connections, and recently modified files. It can compare a list of textual indicators against selected enumerated fields and optionally hash executable files.

## What this helps investigate

- **Persistence:** Run keys, scheduled tasks and WMI event filters.
- **Host inventory:** processes, services, driver paths and unsigned/non-Microsoft driver candidates.
- **Network context:** a `netstat -ano` snapshot with PID association.
- **File review:** recent files from the current user's Downloads/Desktop and process temporary directory, and optional SHA-256 hashes for `*.exe`, `*.dll`, `*.sys` under paths passed to `-HashTrees`.

**Limits:** this is a triage inventory, not malware detection. Text-based `-IoCFile` matching currently searches service, driver, autorun, process and recent-file fields; it does **not** compare supplied hash indicators to `-HashTrees` output or parse domains out of `netstat` data. An empty matches file does not establish a clean host. Hash-tree mode can be resource-intensive.

## Requirements

Windows 10/11 or Windows Server; PowerShell 7+; admin access for full collection. `Get-CimInstance` is used for WMI event filters. No downloaded detection feed is bundled or required.

All runs write timestamped CSV/TXT files. Report data may contain sensitive user paths, command lines and network endpoints, so keep outputs private and retain raw artifacts only under an authorized evidence-handling procedure. This script does not authenticate, establish chain of custody or collect a complete forensic image.

## Reproducible lab demonstration

Run on a test Windows VM and set `$WorkDir` to an authorized writable directory. Use a synthetic indicator rather than any production data.

```powershell
$WorkDir = 'C:\Forensics\LabOutput'
$IndicatorPath = Join-Path $WorkDir 'synthetic-indicators.txt'
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
Set-Content -LiteralPath $IndicatorPath -Encoding utf8 -Value @(
  'SYNTHETIC_NONEXISTENT_PROCESS_2026'
)
$Script = (Resolve-Path '.\IoCSweep.ps1').Path
pwsh -NoProfile -File $Script -IoCFile $IndicatorPath -NoExplorer -OutputRoot $WorkDir
$Latest = Get-ChildItem -LiteralPath $WorkDir -Directory |
  Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
Get-ChildItem -LiteralPath $Latest.FullName -File |
  Select-Object Name,Length
$Summary = Get-ChildItem -LiteralPath $Latest.FullName -Filter 'IoC_Summary_*.txt' |
  Select-Object -First 1
Get-Content -LiteralPath $Summary.FullName
Get-ChildItem -LiteralPath $Latest.FullName -File |
  Get-FileHash -Algorithm SHA256 |
  Format-Table Path,Hash -AutoSize |
  Out-String -Width 240 | Set-Clipboard
```

**Expected:** the script reports each completed collection stage and writes `IoC_Services_*.csv`, `IoC_Drivers_*.csv`, `IoC_Autoruns_*.csv`, `IoC_ScheduledTasks_*.csv`, `IoC_WMIEventSubscriptions_*.csv`, `IoC_Processes_*.csv`, `IoC_Network_*.txt`, `IoC_RecentFiles_*.csv`, `IoC_UnsignedDrivers_*.csv`, and `IoC_Summary_*.txt`. With a deliberately nonexistent indicator, the summary should report no matches. These are expectations, not fabricated run results.

## Interpreting output

1. Review the summary for failed enumerations; absence of output is not success.
2. Compare process, autorun and WMI filter entries with your lab's known-good baseline.
3. Correlate PIDs from network snapshot with process inventory. Investigate rather than immediately delete.
4. Review driver signatures with vendor and deployment context; unsigned does not automatically mean malicious.
5. Hash the exported CSV/TXT files and keep machine name, times, PowerShell version, source commit and command line in an external acquisition log.

`-RecentDays` controls the lookback (7 by default). `-HashTrees` enables separate optional file hashing and may take a long time. `-NoExplorer` avoids launching Explorer after collection. `-OutputRoot` overrides `HOSTAUDIT_ROOT` and the script's fallback destination.

## Test status and remaining work

The PowerShell 7 WMI API compatibility fix uses `Get-CimInstance`, but has not been verified on a live Windows target in this review. Integration tests should assert WMI CSV schema, failure logging, indicator matching, and explicit output paths. The current script still defaults its recent-file scan to the current user's Downloads/Desktop/temp folders: review that scope before running on a sensitive machine.

License: MIT.
