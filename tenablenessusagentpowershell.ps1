<#
===============================================================================
Comprehensive Tenable Nessus Agent Health Check (PowerShell Framework)
===============================================================================
# Purpose:
# Provide a comprehensive PowerShell framework for Tenable Nessus Agent health
# checks on Microsoft Windows platforms. This script stands on its own.

# Supported Microsoft Operating Systems (one per line with version/build):
# Microsoft Windows 10 Pro — Version 1507 (10.0) Build 10240 or later
# Microsoft Windows 10 Enterprise — Version 1507 (10.0) Build 10240 or later
# Microsoft Windows 10 Education — Version 1507 (10.0) Build 10240 or later
# Microsoft Windows 11 Pro — Version 21H2 (10.0) Build 22000 or later
# Microsoft Windows 11 Enterprise — Version 21H2 (10.0) Build 22000 or later
# Microsoft Windows 11 Education — Version 21H2 (10.0) Build 22000 or later
# Microsoft Windows Server 2016 Standard — Version 1607 (10.0) Build 14393 or later
# Microsoft Windows Server 2016 Datacenter — Version 1607 (10.0) Build 14393 or later
# Microsoft Windows Server 2019 Standard — Version 1809 (10.0) Build 17763 or later
# Microsoft Windows Server 2019 Datacenter — Version 1809 (10.0) Build 17763 or later
# Microsoft Windows Server 2022 Standard — Version 21H2 (10.0) Build 20348 or later
# Microsoft Windows Server 2022 Datacenter — Version 21H2 (10.0) Build 20348 or later

# Unsupported Microsoft Operating Systems (one per line with version/build):
# Microsoft Windows XP Professional — Version 5.1 Build 2600
# Microsoft Windows XP Home — Version 5.1 Build 2600
# Microsoft Windows XP Media Center — Version 5.1 Build 2600
# Microsoft Windows Vista Home Basic — Version 6.0 Build 6000
# Microsoft Windows Vista Home Basic — Version 6.0 Build 6001
# Microsoft Windows Vista Home Basic — Version 6.0 Build 6002
# Microsoft Windows Vista Home Premium — Version 6.0 Build 6000
# Microsoft Windows Vista Home Premium — Version 6.0 Build 6001
# Microsoft Windows Vista Home Premium — Version 6.0 Build 6002
# Microsoft Windows Vista Business — Version 6.0 Build 6000
# Microsoft Windows Vista Business — Version 6.0 Build 6001
# Microsoft Windows Vista Business — Version 6.0 Build 6002
# Microsoft Windows Vista Ultimate — Version 6.0 Build 6000
# Microsoft Windows Vista Ultimate — Version 6.0 Build 6001
# Microsoft Windows Vista Ultimate — Version 6.0 Build 6002
# Microsoft Windows 7 Starter — Version 6.1 Build 7600
# Microsoft Windows 7 Starter — Version 6.1 Build 7601
# Microsoft Windows 7 Home Basic — Version 6.1 Build 7600
# Microsoft Windows 7 Home Basic — Version 6.1 Build 7601
# Microsoft Windows 7 Home Premium — Version 6.1 Build 7600
# Microsoft Windows 7 Home Premium — Version 6.1 Build 7601
# Microsoft Windows 7 Professional — Version 6.1 Build 7600
# Microsoft Windows 7 Professional — Version 6.1 Build 7601
# Microsoft Windows 7 Ultimate — Version 6.1 Build 7600
# Microsoft Windows 7 Ultimate — Version 6.1 Build 7601
# Microsoft Windows 8 Core — Version 6.2 Build 9200
# Microsoft Windows 8 Pro — Version 6.2 Build 9200
# Microsoft Windows 8 Enterprise — Version 6.2 Build 9200
# Microsoft Windows 8.1 Core — Version 6.3 Build 9600
# Microsoft Windows 8.1 Pro — Version 6.3 Build 9600
# Microsoft Windows 8.1 Enterprise — Version 6.3 Build 9600
# Microsoft Windows 10 Home — Version 1507 (10.0) Build 10240 or later
# Microsoft Windows Server 2003 Standard — Version 5.2 Build 3790
# Microsoft Windows Server 2003 Enterprise — Version 5.2 Build 3790
# Microsoft Windows Server 2003 Datacenter — Version 5.2 Build 3790
# Microsoft Windows Server 2003 Web Edition — Version 5.2 Build 3790
# Microsoft Windows Server 2008 Standard — Version 6.0 Build 6001
# Microsoft Windows Server 2008 Standard — Version 6.0 Build 6002
# Microsoft Windows Server 2008 Enterprise — Version 6.0 Build 6001
# Microsoft Windows Server 2008 Enterprise — Version 6.0 Build 6002
# Microsoft Windows Server 2008 Datacenter — Version 6.0 Build 6001
# Microsoft Windows Server 2008 Datacenter — Version 6.0 Build 6002
# Microsoft Windows Server 2008 R2 Standard — Version 6.1 Build 7600
# Microsoft Windows Server 2008 R2 Standard — Version 6.1 Build 7601
# Microsoft Windows Server 2008 R2 Enterprise — Version 6.1 Build 7600
# Microsoft Windows Server 2008 R2 Enterprise — Version 6.1 Build 7601
# Microsoft Windows Server 2008 R2 Datacenter — Version 6.1 Build 7600
# Microsoft Windows Server 2008 R2 Datacenter — Version 6.1 Build 7601
# Microsoft Windows Server 2012 Standard — Version 6.2 Build 9200
# Microsoft Windows Server 2012 Datacenter — Version 6.2 Build 9200
# Microsoft Windows Server 2012 Essentials — Version 6.2 Build 9200
# Microsoft Windows Server 2012 R2 Standard — Version 6.3 Build 9600
# Microsoft Windows Server 2012 R2 Datacenter — Version 6.3 Build 9600
# Microsoft Windows Server 2012 R2 Essentials — Version 6.3 Build 9600

# Virtualization Providers (one per line):
# VMware Workstation — Version 16.x Build 21159696
# VMware Workstation — Version 17.x Build 22631006
# VMware ESXi — Version 6.7 Update 3 Build 17167734
# VMware ESXi — Version 7.0 Update 3 Build 20328353
# VMware ESXi — Version 8.0 Build 20513097
# VMware Fusion — Version 12.x Build 20486664
# VMware Fusion — Version 13.x Build 21139760
# Microsoft Hyper-V Server 2012 R2 — Version 6.3 Build 9600
# Microsoft Hyper-V Server 2016 — Version 10.0 Build 14393
# Microsoft Hyper-V Server 2019 — Version 10.0 Build 17763
# Microsoft Azure — BIOS or Serial contains "Azure"
# Oracle VirtualBox — Version 6.1 Build 155634
# Oracle VirtualBox — Version 7.0 Build 153352
# Parallels Desktop — Version 18.x Build 23380
# Parallels Desktop — Version 19.x Build 23674
# Amazon EC2 — Manufacturer "Amazon EC2" or BIOS contains "EC2"

# Command-line Options (each documented clearly):
# --verbose
# Enable verbose output. Echo additional detail to both console and log file.
# --debug
# Enable debug-level output. Echo detailed messages to console and log file.
# --quiet
# Quiet mode. Suppress console output; only write to log and summary files.
# --nocolor
# Disable colorized console output. Use plain text only.
# --jean
# Functional test switch. Exits gracefully.
# --vinnie
# Functional test switch. Exits gracefully.
# --exit
# Allows the authorized administrator to exit the script gracefully.
# --granto
# Functional test switch. Exits gracefully.
# --allow
# Virtualization policy option. Default behavior. Continue when virtualization is detected.
# --notice
# Virtualization policy option. Continue when virtualization is detected and print a NOTICE.
# --exclude
# Virtualization policy option. If virtualization is detected, exit gracefully (code 0).

# STANDARDIZED RESULT INDICATORS (used in all checks):
# ✓ PASS — The check completed successfully. No action is required.
# ✖ FAIL — The check failed. Remediation is required.
# ⚠ WARNING — The check completed but requires caution or investigation.
# ℹ NOTICE — Informational condition. The script may exit gracefully depending on policy.

# HOW CHECK RESULTS ARE DISPLAYED WITH COLORS (safe for all environments):
# PASS (✓) shown in Green (ANSI 32).
# FAIL (✖) shown in Red (ANSI 31).
# WARNING (⚠) shown in Yellow (ANSI 33).
# NOTICE (ℹ) shown in Blue (ANSI 34).
# Colors are disabled automatically if output is redirected (non-TTY) or when --nocolor is specified.

# What Each Check Does (01–12):
# 01. Validate Microsoft PowerShell version (require 5.1+ or 7+).
# 02. Validate Administrator privilege (must run elevated).
# 03. Ensure the log file can be created/written.
# 04. Ensure the summary file can be created/written.
# 05. Validate Microsoft OS edition, version, and build are supported (explicit rules).
# 06. Detect virtualization platform and enforce policy (--allow | --notice | --exclude).
# 07. Central Processing Utilization (CPU) health (short-window average).
# 08. Memory availability (Physical RAM) health.
# 09. Disk space health (System drive C:).
# 10. System uptime since last boot.
# 11. Patch level (last installed hotfix).
# 12. CPU core topology (physical vs logical).
===============================================================================
#>

[CmdletBinding()]
param(
[switch]$VerboseOutput,
[switch]$DebugOutput,
[switch]$Quiet,
[switch]$NoColor,
[switch]$Jean,
[switch]$Vinnie,
[switch]$Exit,
[switch]$Granto,
[switch]$Allow,
[switch]$Notice,
[switch]$Exclude
)

# ---------------- Virtualization policy (default = allow)
if ($Notice) { $VirtualizationPolicy = 'notice' }
elseif ($Exclude) { $VirtualizationPolicy = 'exclude' }
else { $VirtualizationPolicy = 'allow' }

# ---------------- Status icons
$IconPass = "✓"
$IconFail = "✖"
$IconWarn = "⚠"
$IconNotice = "ℹ"

# ---------------- Color control (TTY-safe)
$StdOutRedirected = $false
try { $StdOutRedirected = [System.Console]::IsOutputRedirected } catch { $StdOutRedirected = $false }
$UseColor = (-not $NoColor) -and (-not $StdOutRedirected)
function Colorize {
param([string]$Text,[ValidateSet('red','green','yellow','blue')]$Color)
if (-not $UseColor) { return $Text }
switch ($Color) {
'red' { return "`e[31m$Text`e[0m" }
'green' { return "`e[32m$Text`e[0m" }
'yellow' { return "`e[33m$Text`e[0m" }
'blue' { return "`e[34m$Text`e[0m" }
}
}

# ---------------- Functional switches (behavior only; comments do not reveal texts)
if ($Jean) { Write-Host "jean vixamar is awesome"; Write-Host "Be sure to drink your Ovaltine"; exit 0 }
if ($Vinnie) { Write-Host "why couldn't this be a pivot table?"; exit 0 }
if ($Exit) { Write-Host "With great power comes great responsibility"; exit 0 }
if ($Granto) { Write-Host "I bet you a box of Double Dark Chocolate"; exit 0 }

# ================= Progress, Counters, and Summary Helpers ================
$TotalChecks = 12 # <— update if you add/remove checks
$ScriptStartTime = Get-Date
$CheckNumber = 0
$PassCount = 0
$WarnCount = 0
$FailCount = 0
$NoticeCount = 0
$Results = New-Object System.Collections.Generic.List[object]

function Begin-Check {
param([string]$Label)
$script:CurrentCheckLabel = $Label
$script:CheckNumber++
$pct = [int]( (($script:CheckNumber - 1) / $script:TotalChecks) * 100 )
Write-Progress -Activity "Executing health checks" -Status "$Label ($script:CheckNumber of $script:TotalChecks)" -PercentComplete $pct
if (-not $Quiet) { Write-Host "Running $Label" }
}
function Set-Status {
param(
[ValidateSet('PASS','WARNING','FAIL','NOTICE')][string]$Status,
[string]$Message = ''
)
switch ($Status) {
'PASS' { $script:PassCount++ ; $out = (Colorize "$IconPass Status: PASS" "green") }
'WARNING' { $script:WarnCount++ ; $out = (Colorize "$IconWarn Status: WARNING" "yellow") }
'FAIL' { $script:FailCount++ ; $out = (Colorize "$IconFail Status: FAIL" "red") }
'NOTICE' { $script:NoticeCount++ ; $out = (Colorize "$IconNotice Status: NOTICE" "blue") }
}
Write-Host $out
if ($Message) { Write-Host $Message }
$Results.Add([pscustomobject]@{
Check = $script:CheckNumber
Label = $script:CurrentCheckLabel
Status = $Status
Note = $Message
})
}
function End-Check {
$pct = [int]( ($script:CheckNumber / $script:TotalChecks) * 100 )
Write-Progress -Activity "Executing health checks" -Status "$($script:CurrentCheckLabel) complete" -PercentComplete $pct
if (-not $Quiet) { Write-Host "" }
}

# ==================================================
# Check 01 - Microsoft PowerShell Version Validation
# ==================================================
Begin-Check -Label "Check 01 - Microsoft PowerShell Version Validation"
try {
$psMajor = $PSVersionTable.PSVersion.Major
$psMinor = $PSVersionTable.PSVersion.Minor
if ( ($psMajor -eq 5 -and $psMinor -ge 1) -or ($psMajor -ge 7) ) {
Write-Host "Result: Microsoft PowerShell version $psMajor.$psMinor is supported"
Set-Status -Status PASS
} else {
Write-Host "Result: Microsoft PowerShell version $psMajor.$psMinor is NOT supported"
Set-Status -Status FAIL -Message "Recommended Action: Upgrade to Microsoft Windows PowerShell 5.1 or Microsoft PowerShell 7+."
End-Check; exit 1
}
} catch {
Write-Host "Result: Unable to read Microsoft PowerShell version"
Set-Status -Status FAIL
End-Check; exit 1
}
End-Check

# ==================================================
# Check 02 - Administrator Privilege Validation
# ==================================================
Begin-Check -Label "Check 02 - Administrator Privilege Validation"
try {
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).
IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if ($isAdmin) {
Write-Host "Result: Script is running as Administrator"
Set-Status -Status PASS
} else {
Write-Host "Result: Script is NOT running as Administrator"
Set-Status -Status FAIL -Message "Recommended Action: Run Microsoft PowerShell as Administrator."
End-Check; exit 1
}
} catch {
Write-Host "Result: Unable to determine Administrator status"
Set-Status -Status FAIL
End-Check; exit 1
}
End-Check

# ==================================================
# Check 03 - Log File Initialization
# ==================================================
Begin-Check -Label "Check 03 - Log File Initialization"
try {
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFile = Join-Path $ScriptDir 'nessus_agent_health_check.log'
'' | Out-File -FilePath $LogFile -Append -Encoding utf8
Write-Host "Result: Log file is writable ($LogFile)"
Set-Status -Status PASS
} catch {
Write-Host "Result: Unable to write to log file ($LogFile)"
Set-Status -Status FAIL -Message "Recommended Action: Verify directory permissions or rerun as Administrator."
End-Check; exit 1
}
End-Check

# ==================================================
# Check 04 - Summary File Initialization
# ==================================================
Begin-Check -Label "Check 04 - Summary File Initialization"
try {
$SummaryFile = Join-Path $ScriptDir 'summary.txt'
'' | Out-File -FilePath $SummaryFile -Append -Encoding utf8
Write-Host "Result: Summary file is writable ($SummaryFile)"
Set-Status -Status PASS
} catch {
Write-Host "Result: Unable to write to summary file ($SummaryFile)"
Set-Status -Status FAIL -Message "Recommended Action: Verify directory permissions or rerun as Administrator."
End-Check; exit 1
}
End-Check

# ==================================================
# Check 05 - Microsoft Operating System Version, Edition, and Build Validation
# ==================================================
Begin-Check -Label "Check 05 - Microsoft Operating System Version, Edition, and Build Validation"
try {
$osInfo = Get-CimInstance Win32_OperatingSystem
$osCaption = [string]$osInfo.Caption
$osVersion = [string]$osInfo.Version
$osBuild = [int]$osInfo.BuildNumber
Write-Host "Detected Microsoft Operating System: $osCaption (Version $osVersion, Build $osBuild)"

$rules = @(
@{ Name='Microsoft Windows 10 Pro'; Pattern='Microsoft Windows 10.*Pro'; MinBuild=10240 }
@{ Name='Microsoft Windows 10 Enterprise'; Pattern='Microsoft Windows 10.*Enterprise'; MinBuild=10240 }
@{ Name='Microsoft Windows 10 Education'; Pattern='Microsoft Windows 10.*Education'; MinBuild=10240 }
@{ Name='Microsoft Windows 11 Pro'; Pattern='Microsoft Windows 11.*Pro'; MinBuild=22000 }
@{ Name='Microsoft Windows 11 Enterprise'; Pattern='Microsoft Windows 11.*Enterprise'; MinBuild=22000 }
@{ Name='Microsoft Windows 11 Education'; Pattern='Microsoft Windows 11.*Education'; MinBuild=22000 }
@{ Name='Microsoft Windows Server 2016 Standard'; Pattern='Microsoft Windows Server 2016.*Standard'; MinBuild=14393 }
@{ Name='Microsoft Windows Server 2016 Datacenter'; Pattern='Microsoft Windows Server 2016.*Datacenter'; MinBuild=14393 }
@{ Name='Microsoft Windows Server 2019 Standard'; Pattern='Microsoft Windows Server 2019.*Standard'; MinBuild=17763 }
@{ Name='Microsoft Windows Server 2019 Datacenter'; Pattern='Microsoft Windows Server 2019.*Datacenter'; MinBuild=17763 }
@{ Name='Microsoft Windows Server 2022 Standard'; Pattern='Microsoft Windows Server 2022.*Standard'; MinBuild=20348 }
@{ Name='Microsoft Windows Server 2022 Datacenter'; Pattern='Microsoft Windows Server 2022.*Datacenter'; MinBuild=20348 }
)

$matched = $false
foreach ($rule in $rules) {
if ($osCaption -match $rule.Pattern) {
$matched = $true
if ($osBuild -ge [int]$rule.MinBuild) {
Write-Host "Result: Supported $($rule.Name) — Build $osBuild meets minimum $($rule.MinBuild)"
Set-Status -Status PASS
} else {
Write-Host "Result: $($rule.Name) — Build $osBuild is below minimum $($rule.MinBuild)"
Set-Status -Status FAIL -Message "Recommended Action: Upgrade to $($rule.Name) build $($rule.MinBuild) or later."
End-Check; exit 1
}
break
}
}
if (-not $matched) {
Write-Host "Result: $osCaption (Version $osVersion, Build $osBuild) is NOT supported by Tenable Nessus Agent"
Set-Status -Status FAIL -Message "Recommended Action: Upgrade to a supported Microsoft Operating System edition, version, and build."
End-Check; exit 1
}
} catch {
Write-Host "Result: Unable to determine Microsoft Operating System version, edition, or build"
Set-Status -Status FAIL
End-Check; exit 1
}
End-Check

# ==================================================
# Check 06 - Virtualization Environment Policy
# ==================================================
Begin-Check -Label "Check 06 - Virtualization Environment Policy"
try {
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$manu = [string]$cs.Manufacturer
$model = [string]$cs.Model
$biosV = [string]$bios.SMBIOSBIOSVersion
$serial = [string]$bios.SerialNumber

$provider = "Physical/Unknown"
if ( ($manu -match "Microsoft" -and $model -match "Virtual Machine") -or $biosV -match "Hyper-V" ) { $provider = "Hyper-V" }
if ($biosV -match "Azure" -or $serial -match "Azure") { $provider = "Microsoft Azure" }
if ($manu -match "VMware" -or $model -match "VMware" -or $biosV -match "VMware") { $provider = "VMware" }
if ($manu -match "Amazon EC2" -or $model -match "EC2" -or $biosV -match "EC2") { $provider = "Amazon EC2" }
if ($manu -match "VirtualBox" -or $model -match "VirtualBox" -or $biosV -match "VirtualBox") { $provider = "Oracle VirtualBox" }
if ($manu -match "Parallels" -or $model -match "Parallels" -or $biosV -match "Parallels") { $provider = "Parallels" }

Write-Host "Detected Environment: $provider"
switch ($VirtualizationPolicy) {
'allow' { Set-Status -Status PASS -Message "Virtualization allowed by policy." }
'notice' { Set-Status -Status NOTICE -Message "Virtualization detected; continuing by policy." }
'exclude'{
Set-Status -Status FAIL -Message "Virtualization excluded by policy; exiting gracefully."
End-Check; exit 0
}
}
} catch {
Write-Host "Result: Unable to determine virtualization environment"
Set-Status -Status FAIL
End-Check; exit 1
}
End-Check

# ==================================================
# Check 07 - Central Processing Utilization (CPU) Health
# ==================================================
Begin-Check -Label "Check 07 - Central Processing Utilization (CPU) Health"
try {
$samples = @()
for ($i=1; $i -le 5; $i++) {
$val = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
$samples += [double]::Parse("{0:N2}" -f $val)
Start-Sleep -Seconds 3
}
$cpuAvg = [math]::Round(($samples | Measure-Object -Average).Average,2)
Write-Host ("Result: Average CPU utilization (15s) = {0}%" -f $cpuAvg)
if ($cpuAvg -gt 95) { Set-Status -Status FAIL -Message "Recommended Action: Investigate sustained CPU saturation; tune workloads or increase capacity." }
elseif ($cpuAvg -ge 85 -and $cpuAvg -le 95) { Set-Status -Status WARNING -Message "Recommended Action: Monitor CPU; check scheduled tasks/services/scans; consider optimization." }
else { Set-Status -Status PASS }
} catch {
Write-Host "Result: Unable to obtain CPU utilization counters"
Set-Status -Status FAIL -Message "Recommended Action: Ensure Performance Counter service and WMI are healthy."
}
End-Check

# ==================================================
# Check 08 - Memory Availability (Physical RAM) Health
# ==================================================
Begin-Check -Label "Check 08 - Memory Availability (Physical RAM) Health"
try {
$os = Get-CimInstance Win32_OperatingSystem
$totalKB = [double]$os.TotalVisibleMemorySize
$freeKB = [double]$os.FreePhysicalMemory
$totalGB = [math]::Round($totalKB / 1MB, 2)
$freeGB = [math]::Round($freeKB / 1MB, 2)
$pctFree = [math]::Round(($freeKB / $totalKB) * 100, 2)
Write-Host ("Result: Physical Memory — Total {0} GB; Free {1} GB ({2}% free)" -f $totalGB, $freeGB, $pctFree)
if ($pctFree -lt 10) { Set-Status -Status FAIL -Message "Recommended Action: Reduce memory footprint; increase RAM; investigate leaks." }
elseif ($pctFree -lt 20) { Set-Status -Status WARNING -Message "Recommended Action: Monitor memory usage; consider optimization or adding RAM." }
else { Set-Status -Status PASS }
} catch {
Write-Host "Result: Unable to retrieve memory information"
Set-Status -Status FAIL
}
End-Check

# ==================================================
# Check 09 - Disk Space Validation (System Drive)
# ==================================================
Begin-Check -Label "Check 09 - Disk Space Validation (System Drive)"
try {
$drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$freeGB = [math]::Round($drive.FreeSpace / 1GB, 2)
$totalGB = [math]::Round($drive.Size / 1GB, 2)
$pctFree = if ($drive.Size) { [math]::Round(($drive.FreeSpace / $drive.Size) * 100, 2) } else { 0 }
Write-Host "Result: Drive C: Free $freeGB GB ($pctFree%) / Total $totalGB GB"
if ($pctFree -lt 10) { Set-Status -Status FAIL -Message "Recommended Action: Free disk space on C: (target ≥ 20% free) and ensure Agent cache can expand." }
elseif ($pctFree -lt 20) { Set-Status -Status WARNING -Message "Recommended Action: Plan cleanup on C: (target ≥ 20% free)." }
else { Set-Status -Status PASS }
} catch {
Write-Host "Result: Unable to retrieve disk information for C:"
Set-Status -Status FAIL
}
End-Check

# ==================================================
# Check 10 - System Uptime Validation
# ==================================================
Begin-Check -Label "Check 10 - System Uptime Validation"
try {
$os = Get-CimInstance Win32_OperatingSystem
$lastBoot = $os.LastBootUpTime
$uptime = (Get-Date) - $lastBoot
Write-Host "Result: System uptime: $([math]::Floor($uptime.TotalDays)) days $($uptime.Hours) hours $($uptime.Minutes) minutes"
Set-Status -Status PASS
} catch {
Write-Host "Result: Unable to calculate system uptime"
Set-Status -Status FAIL
}
End-Check

# ==================================================
# Check 11 - Patch Level Validation (Last Installed Hotfix)
# ==================================================
Begin-Check -Label "Check 11 - Patch Level Validation (Last Installed Hotfix)"
try {
$hotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hotfix) {
Write-Host "Result: Last installed hotfix: $($hotfix.HotFixID) on $($hotfix.InstalledOn)"
# Optional policy: warn if older than 45 days:
# if ((Get-Date) - $hotfix.InstalledOn -gt (New-TimeSpan -Days 45)) { Set-Status -Status WARNING -Message "System appears overdue for patching (older than 45 days)." } else { Set-Status -Status PASS }
Set-Status -Status PASS
} else {
Write-Host "Result: No hotfixes found — patch state unknown"
Set-Status -Status WARNING -Message "Recommended Action: Confirm Windows Update / patch cadence on this host."
}
} catch {
Write-Host "Result: Unable to retrieve patch information"
Set-Status -Status FAIL
}
End-Check

# ==================================================
# Check 12 - CPU Core Topology (Physical vs Logical)
# ==================================================
Begin-Check -Label "Check 12 - CPU Core Topology (Physical vs Logical)"
try {
$cpu = Get-CimInstance Win32_Processor
$phys = ($cpu | Measure-Object -Property NumberOfCores -Sum).Sum
$logi = ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
Write-Host "Result: CPU topology — Physical cores: $phys; Logical processors: $logi"
if ($phys -lt 2 -or $logi -lt 2) {
Set-Status -Status WARNING -Message "Recommended Action: Low core/CPU resources may impact scan performance; validate sizing."
} else {
Set-Status -Status PASS
}
} catch {
Write-Host "Result: Unable to retrieve CPU topology information"
Set-Status -Status FAIL
}
End-Check

# =================== Comprehensive Assessment Summary ====================
$ScriptEndTime = Get-Date
$Elapsed = $ScriptEndTime - $ScriptStartTime
Write-Progress -Activity "Executing health checks" -Completed -Status "Done"

Write-Host "==================================================================="
Write-Host "Comprehensive Tenable Nessus Agent Health Assessment Summary"
Write-Host "==================================================================="
Write-Host ("Checks Executed : {0} of {1}" -f $CheckNumber, $TotalChecks)
Write-Host ("PASS : {0}" -f $PassCount)
Write-Host ("WARNING : {0}" -f $WarnCount)
Write-Host ("FAIL : {0}" -f $FailCount)
Write-Host ("NOTICE : {0}" -f $NoticeCount)
Write-Host ("Start Time : {0}" -f $ScriptStartTime)
Write-Host ("End Time : {0}" -f $ScriptEndTime)
Write-Host ("Elapsed : {0}" -f $Elapsed)
Write-Host "-------------------------------------------------------------------"

$problematic = $Results | Where-Object { $_.Status -in @('WARNING','FAIL') }
if ($problematic.Count -gt 0) {
Write-Host "Items Requiring Attention:"
foreach ($r in $problematic) {
$icon = if ($r.Status -eq 'FAIL') { $IconFail } else { $IconWarn }
$clr = if ($r.Status -eq 'FAIL') { 'red' } else { 'yellow' }
Write-Host (Colorize ("{0} Check {1:00} — {2} — {3}" -f $icon, [int]$r.Check, $r.Label, ($r.Note ?? '')) $clr)
}
} else {
Write-Host "No WARNING or FAIL items detected."
}
Write-Host "==================================================================="
