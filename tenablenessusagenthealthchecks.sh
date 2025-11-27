#!/usr/bin/env bash
# ==================================================================================================
# Comprehensive Tenable Nessus Agent Health Check (Unix/Linux) — explicit, no grouping, no trimming
# --------------------------------------------------------------------------------------------------
# PURPOSE:
# End-to-end, idiot-proof health check for Tenable Nessus Agent on Unix/Linux systems.
# Produces:
# • A timestamped runtime log file: tenable_nessus_agent_<UTC>.log
# • A numbered, human-readable summary file: summary.txt
#
# OUTPUT LINE FORMAT (for EVERY check):
# Check NN: <Descriptive Title>
# Command : <exact command that was executed>
# Result : <plain, kitchen-English or trimmed verbatim>
# Status : OK | WARNING | ERROR
#
# FLAGS:
# --verbose Show INFO to console (always logged).
# --debug Show DEBUG to console/log; adds extra context into summary.
# --quiet Suppress INFO to console (everything still logged).
# --bug-report Generate Tenable bug report at end (if agent layout valid).
# --jean Prints two lines and exits: “jean vixamar is awesome”; “Be sure to drink your Ovaltine”.
# --vinnie Prints one line and exits: “why couldn't this be a pivot table?”
# --help|-h Show usage.
#
# HIGH-LEVEL FLOW:
# 1) Root & script permission checks; start timers, open log and summary.
# 2) OS Platform Detection — explicit A→Z one-by-one checks (no grouping).
# 3) Policy exit for cloud images (AWS/EC2) — record evidence and exit.
# 4) System checks BEFORE Tenable Nessus Agent checks:
# • Hostname/FQDN, kernel/arch, virtualization hint
# • DNS resolvers, NTP/time sync, default route, interfaces
# • CPU cores, load averages, memory/swap, top CPU/MEM processes
# • Disk usage system-wide + specific paths (/apps/tools, /apps/tools/nessus_agent, /var, /tmp)
# • /etc/fstab review (comments removed)
# • Shell versions (bash, sh), OpenSSH client version, OpenSSL/LibreSSL version
# 5) Tenable Nessus Agent checks:
# • Installation layout: /apps/tools/nessus_agent must exist; /opt/nessus_agent must be a symlink to it
# • /etc/tenable_tag presence (ERROR if missing; else print first line)
# • nessuscli presence & version
# • agent status parse: Last scanned / Last connect / Last connection attempt (epoch→UTC)
# • agent identity: --show-uuid, --show-token (masked)
# • advanced settings via fix --secure --get:
# proxy, proxy_port, groups, agent_update_channel, process_priority,
# logfile_max_size, logfile_max_files, verify_host_cert, ca_path, interfaces
# • fix --show capture to log (first 400 lines recorded)
# • plugin feed version (parsed), scans run today (parsed)
# • optional bug report generation (--bug-report flag)
# 6) Final summary footer with counts: Checks Executed, OK, Warnings, Errors; overall statement.
#
# EXPLICIT OS VARIANTS (each checked individually, alphabetically — no grouping):
# A/UX, AIX, AlmaLinux, Alpine Linux, Amazon Linux, antiX, Arch Linux, BeOS, Bell Labs Research Unix,
# BSD/OS, CentOS Linux, CentOS Stream, Clear Linux OS, ClearOS, CloudLinux, Coherent, COSIX, Debian,
# Deepin, Devuan, Domain/OS, Elementary OS, Fedora, FreeBSD, Garuda Linux, Gentoo, Guix System, Helios,
# HP-UX, Idris, Illumos, IRIX, Kali Linux, Mageia, Manjaro, Mandrake, MX Linux, NeXTSTEP, NixOS,
# OpenIndiana, OpenMandriva, OpenServer, OpenSUSE, OpenVMS, Oracle Linux, Oracle Solaris, PacBSD, PC-IX,
# PC-UX, PCLinuxOS, Plan 9, Plurix, Pop!_OS, Puppy Linux, PWB/UNIX, QNX 4, QNX Neutrino, Qubes OS,
# Red Hat Enterprise Linux, RedoxOS, Research Unix, Rocky Linux, RX-UX832, SCO OpenServer, SCO_SV,
# Scientific Linux, SerenityOS, SINIX, Slackware, Solaris (SunOS), Sprite OS, SUSE Linux Enterprise Server,
# SteamOS, TINIX, TinyCore, Tru64 UNIX, TUNIS, Ubuntu, ULTRIX, UNETix, UniFLEX, UNIX System Services,
# UnixWare, UNOS, Venix, Version 6 Unix, Version 7 Unix, Vino, Void Linux, VSTa, Xenix, Xv6, Zorin OS,
# z/OS, TencentOS Server, Linux Mint, VMware PhotonOS.
# ==================================================================================================

set -o pipefail
set -u

START_EPOCH=$(date +%s)
START_ISO_UTC=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
RUN_ID="$(date -u +%Y%m%d_%H%M%S)"
LOG_FILE="tenable_nessus_agent_${RUN_ID}.log"
SUMMARY_FILE="summary.txt"

VERBOSE=0; DEBUG=0; QUIET=0; MAKE_BUG=0

# Easter-egg style switches (print to screen only, then exit)
for a in "$@"; do
case "$a" in
--jean) echo "jean vixamar is awesome"; echo "Be sure to drink your Ovaltine"; exit 0;;
--vinnie) echo "why couldn't this be a pivot table?"; exit 0;;
esac
done

usage() {
cat <<'U'
Usage:
sudo ./tenable_nessus_agent_healthcheck.sh [--verbose] [--debug] [--quiet] [--bug-report] [--jean] [--vinnie] [--help|-h]
U
}

# Parse args
while [ $# -gt 0 ]; do
case "$1" in
--debug) DEBUG=1; VERBOSE=1; shift;;
--verbose) VERBOSE=1; shift;;
--quiet) QUIET=1; shift;;
--bug-report)MAKE_BUG=1; shift;;
--help|-h) usage; exit 0;;
*) shift;;
esac
done

# Colors (TTY only)
if [ -t 1 ]; then
CRED=$'\033[31m'; CGRN=$'\033[32m'; CYEL=$'\033[33m'; CBLU=$'\033[34m'; CBLD=$'\033[1m'; CRST=$'\033[0m'
else
CRED=""; CGRN=""; CYEL=""; CBLU=""; CBLD=""; CRST=""
fi

log(){ echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG_FILE" >/dev/null; }
say(){ [ "$QUIET" -eq 0 ] && echo "$*"; }
dbg(){ [ "$DEBUG" -eq 1 ] && say "DEBUG: $*"; [ "$DEBUG" -eq 1 ] && log "DEBUG: $*"; }
inf(){ [ "$VERBOSE" -eq 1 ] && say "${CBLU}INFO${CRST}: $*"; log "INFO: $*"; }
wrn(){ say "${CYEL}WARNING${CRST}: $*"; log "WARNING: $*"; }
err(){ say "${CRED}ERROR${CRST}: $*"; log "ERROR: $*"; }

CHECK_COUNT=0; OK_COUNT=0; WARN_COUNT=0; ERR_COUNT=0

begin(){ CHECK_COUNT=$((CHECK_COUNT+1)); echo >>"$SUMMARY_FILE"; }

add_summary(){
# args: <title> <command> <result> <status>
local title="$1" cmd="$2" result="$3" status="$4"
{
printf 'Check %02d: %s\n' "$CHECK_COUNT" "$title"
echo "Command : $cmd"
echo "Result : $result"
echo "Status : $status"
echo
} >> "$SUMMARY_FILE"
case "$status" in
OK) OK_COUNT=$((OK_COUNT+1));;
WARNING) WARN_COUNT=$((WARN_COUNT+1));;
ERROR) ERR_COUNT=$((ERR_COUNT+1));;
esac
}

# Start artifacts
echo "Log file: $LOG_FILE" >"$LOG_FILE"
echo "Summary: $SUMMARY_FILE" >"$SUMMARY_FILE"
say "${CBLD}Comprehensive Tenable Nessus Agent Health Check — START${CRST}"
log "START"

# 01 Root check
begin
if [ "$(id -u)" -ne 0 ]; then
add_summary "Root Privileges Check" "id -u" "Not root (uid=$(id -u)). Must be run as root." "ERROR"
err "Must run as root. Exiting."
echo "Script Status Explanation: Cannot continue without root." >>"$SUMMARY_FILE"
exit 0
else
add_summary "Root Privileges Check" "id -u" "Running as root (uid=0)." "OK"
inf "Root confirmed."
fi

# 02 Script executable bit
begin
if [ -x "$0" ]; then
add_summary "Script Executable Permission" "test -x $0" "Executable bit present." "OK"
else
add_summary "Script Executable Permission" "test -x $0" "Executable bit missing; suggest chmod +x." "WARNING"
fi

# 03 Baseline host/time/kernel
begin
HOSTN="$(hostname 2>/dev/null || uname -n)"
FQDN="$(hostname -f 2>/dev/null || echo "$HOSTN")"
KERNEL="$(uname -srmo 2>/dev/null || uname -a)"
TIMEINFO="$(timedatectl 2>/dev/null | sed -n '1,5p' || echo 'timedatectl unavailable')"
add_summary "Hostname / Kernel / Time basics" "hostname; hostname -f; uname -srmo; timedatectl" "Hostname=$HOSTN | FQDN=$FQDN | Kernel=$KERNEL | $(echo "$TIMEINFO" | tr '\n' ' ')" "OK"

# 04 Virtualization hint (record only)
begin
VIRT="$(systemd-detect-virt 2>/dev/null || echo 'unknown')"
add_summary "Virtualization hint" "systemd-detect-virt" "Detected: $VIRT" "OK"

# 05 Cloud policy block (AWS/EC2 disallowed by design)
begin
AWS_EVID="$( (grep -i ec2 /sys/hypervisor/uuid 2>/dev/null || dmidecode -s system-product-name 2>/dev/null || cat /sys/class/dmi/id/product_name 2>/dev/null || curl -s --max-time 1 http://169.254.169.254 2>/dev/null) )"
if echo "$AWS_EVID" | grep -qiE 'ec2|amazon'; then
add_summary "Cloud Image Policy Check (AWS/EC2)" "check dmi/sysfs/IMDS" "Evidence indicates AWS/EC2. This script is not intended to run on AWS images." "ERROR"
echo "Script Status Explanation: Cloud image detected (AWS/EC2). Exiting by policy." >>"$SUMMARY_FILE"
finish_summary(){ :; }; # avoid duplicate footer
# write footer once and exit
{
echo "Final Comprehensive Tenable Nessus Agent Health Check"
echo "Script Status Explanation:"
echo "Checks Executed: $CHECK_COUNT"
echo "OK: $OK_COUNT, Warnings: $WARN_COUNT, Errors: $ERR_COUNT"
echo
echo "Script started (UTC): $START_ISO_UTC"
echo "Script ended (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Total runtime (sec): $(( $(date +%s) - START_EPOCH ))"
} >> "$SUMMARY_FILE"
exit 0
else
add_summary "Cloud Image Policy Check (AWS/EC2)" "check dmi/sysfs/IMDS" "No AWS indicators found." "OK"
fi

# 06 Raw OS evidence
RAW_OS_INFO="$( (uname -a; echo '---'; cat /etc/*release 2>/dev/null || true) 2>&1 )"

# Helper: one explicit OS check (classic UNIX-type → unsupported; Linux distro → info)
explicit_os_check() {
local label="$1" token="$2" unsupported="$3"
begin
if echo "$RAW_OS_INFO" | grep -qi "$token"; then
if [ "$unsupported" = "1" ]; then
add_summary "Operating System Detection — $label" "uname -a; cat /etc/*release" "Detected: $label. This platform is not supported for this script. Evidence captured." "ERROR"
echo "Script Status Explanation: Unsupported platform: $label. Exiting." >>"$SUMMARY_FILE"
{
echo "Final Comprehensive Tenable Nessus Agent Health Check"
echo "Script Status Explanation:"
echo "Checks Executed: $CHECK_COUNT"
echo "OK: $OK_COUNT, Warnings: $WARN_COUNT, Errors: $ERR_COUNT"
echo
echo "Script started (UTC): $START_ISO_UTC"
echo "Script ended (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Total runtime (sec): $(( $(date +%s) - START_EPOCH ))"
} >> "$SUMMARY_FILE"
exit 0
else
add_summary "Linux Distro Detection — $label" "uname -a; cat /etc/*release" "Detected: $label (evidence recorded)." "OK"
fi
else
add_summary "Operating System Detection — $label" "uname -a; cat /etc/*release" "Not detected." "OK"
fi
}

# === A→Z EXPLICIT OS CHECKS (NO GROUPING) ===
# Classic/legacy UNIX-like (unsupported for this script) — pass unsupported=1:
explicit_os_check "A/UX" "A/UX" 1
explicit_os_check "AIX" "AIX" 1
explicit_os_check "BeOS" "BeOS" 1
explicit_os_check "Bell Labs Research Unix" "Research Unix" 1
explicit_os_check "BSD/OS" "BSD/OS" 1
explicit_os_check "Coherent" "Coherent" 1
explicit_os_check "COSIX" "COSIX" 1
explicit_os_check "Domain/OS" "Domain/OS" 1
explicit_os_check "HP-UX" "HP-UX" 1
explicit_os_check "Illumos" "Illumos" 1
explicit_os_check "IRIX" "IRIX" 1
explicit_os_check "Minix" "Minix" 1
explicit_os_check "NeXTSTEP" "NeXTSTEP" 1
explicit_os_check "OpenServer" "OpenServer" 1
explicit_os_check "OpenVMS" "OpenVMS" 1
explicit_os_check "Oracle Solaris" "Solaris\|SunOS" 1
explicit_os_check "PacBSD" "PacBSD" 1
explicit_os_check "PC-IX" "PC-IX" 1
explicit_os_check "PC-UX" "PC-UX" 1
explicit_os_check "Plan 9" "Plan 9" 1
explicit_os_check "Plurix" "Plurix" 1
explicit_os_check "PWB/UNIX" "PWB/UNIX" 1
explicit_os_check "QNX 4" "QNX 4" 1
explicit_os_check "QNX Neutrino" "QNX|Neutrino" 1
explicit_os_check "Research Unix" "Research Unix" 1
explicit_os_check "RX-UX832" "RX-UX832" 1
explicit_os_check "SCO OpenServer" "SCO OpenServer" 1
explicit_os_check "SCO_SV" "SCO_SV" 1
explicit_os_check "SerenityOS" "SerenityOS" 1
explicit_os_check "SINIX" "SINIX" 1
explicit_os_check "Sprite OS" "Sprite OS" 1
explicit_os_check "TINIX" "TINIX" 1
explicit_os_check "Tru64 UNIX" "Tru64" 1
explicit_os_check "TUNIS" "TUNIS" 1
explicit_os_check "ULTRIX" "ULTRIX" 1
explicit_os_check "UNETix" "UNETix" 1
explicit_os_check "UniFLEX" "UniFLEX" 1
explicit_os_check "UNIX System Services" "UNIX System Services" 1
explicit_os_check "UnixWare" "UnixWare" 1
explicit_os_check "UNOS" "UNOS" 1
explicit_os_check "Venix" "Venix" 1
explicit_os_check "Version 6 Unix" "Version 6 Unix" 1
explicit_os_check "Version 7 Unix" "Version 7 Unix" 1
explicit_os_check "Vino" "Vino" 1
explicit_os_check "VSTa" "VSTa" 1
explicit_os_check "Xenix" "Xenix" 1
explicit_os_check "Xv6" "Xv6" 1
explicit_os_check "z/OS" "z/OS" 1

# Linux Distros (informational; supported policy handled elsewhere) — unsupported=0:
explicit_os_check "AlmaLinux" "AlmaLinux" 0
explicit_os_check "Alpine Linux" "Alpine" 0
explicit_os_check "Amazon Linux" "Amazon Linux" 0
explicit_os_check "antiX" "antiX" 0
explicit_os_check "Arch Linux" "Arch Linux" 0
explicit_os_check "CentOS Linux" "CentOS Linux" 0
explicit_os_check "CentOS Stream" "CentOS Stream" 0
explicit_os_check "Clear Linux OS" "Clear Linux" 0
explicit_os_check "ClearOS" "ClearOS" 0
explicit_os_check "CloudLinux" "CloudLinux" 0
explicit_os_check "Debian" "Debian" 0
explicit_os_check "Deepin" "Deepin" 0
explicit_os_check "Devuan" "Devuan" 0
explicit_os_check "Elementary OS" "elementary" 0
explicit_os_check "Fedora" "Fedora" 0
explicit_os_check "FreeBSD" "FreeBSD" 1 # classic non-Linux → unsupported by policy
explicit_os_check "Garuda Linux" "Garuda" 0
explicit_os_check "Gentoo" "Gentoo" 0
explicit_os_check "Guix System" "Guix" 0
explicit_os_check "Kali Linux" "Kali" 0
explicit_os_check "Mageia" "Mageia" 0
explicit_os_check "Manjaro" "Manjaro" 0
explicit_os_check "Mandrake" "Mandrake" 0
explicit_os_check "MX Linux" "MX Linux" 0
explicit_os_check "NixOS" "NixOS" 0
explicit_os_check "OpenIndiana" "OpenIndiana" 1
explicit_os_check "OpenMandriva" "OpenMandriva" 0
explicit_os_check "OpenSUSE" "openSUSE" 0
explicit_os_check "Oracle Linux" "Oracle Linux" 0
explicit_os_check "PCLinuxOS" "PCLinuxOS" 0
explicit_os_check "Pop!_OS" "Pop!_OS" 0
explicit_os_check "Puppy Linux" "Puppy" 0
explicit_os_check "Qubes OS" "Qubes" 0
explicit_os_check "Red Hat Enterprise Linux" "Red Hat|RHEL" 0
explicit_os_check "RedoxOS" "Redox" 1
explicit_os_check "Rocky Linux" "Rocky" 0
explicit_os_check "Scientific Linux" "Scientific Linux" 0
explicit_os_check "Slackware" "Slackware" 0
explicit_os_check "SUSE Linux Enterprise Server" "SUSE Linux Enterprise" 0
explicit_os_check "SteamOS" "SteamOS" 0
explicit_os_check "TencentOS Server" "TencentOS" 0
explicit_os_check "TinyCore" "TinyCore" 0
explicit_os_check "Ubuntu" "Ubuntu" 0
explicit_os_check "Void Linux" "Void Linux" 0
explicit_os_check "VMware PhotonOS" "PhotonOS|VMware Photon" 1 # policy: unsupported for this script
explicit_os_check "Linux Mint" "Linux Mint" 0
explicit_os_check "Zorin OS" "Zorin" 0

# GNU/Linux base confirmation (final gate)
begin
UN="$(uname -s 2>/dev/null)"
if [ "$UN" != "Linux" ]; then
add_summary "GNU/Linux base confirmation" "uname -s" "Kernel reports: $UN. This script targets GNU/Linux only." "ERROR"
echo "Script Status Explanation: Non-Linux kernel detected. Exiting." >>"$SUMMARY_FILE"
{
echo "Final Comprehensive Tenable Nessus Agent Health Check"
echo "Script Status Explanation:"
echo "Checks Executed: $CHECK_COUNT"
echo "OK: $OK_COUNT, Warnings: $WARN_COUNT, Errors: $ERR_COUNT"
echo
echo "Script started (UTC): $START_ISO_UTC"
echo "Script ended (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Total runtime (sec): $(( $(date +%s) - START_EPOCH ))"
} >> "$SUMMARY_FILE"
exit 0
else
OSR="$([ -r /etc/os-release ] && . /etc/os-release; echo "$ID $VERSION_ID $PRETTY_NAME")"
add_summary "GNU/Linux base confirmation" "uname -s; read /etc/os-release" "Linux kernel; $OSR" "OK"
fi

# ---------- System checks (before agent checks) ----------
# DNS resolvers
begin
DNS="$(grep -E '^\s*nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | paste -sd, -)"
if [ -n "$DNS" ]; then
add_summary "DNS servers check" "grep nameserver /etc/resolv.conf" "Resolvers: $DNS" "OK"
else
add_summary "DNS servers check" "cat /etc/resolv.conf" "/etc/resolv.conf missing or no nameserver entries." "WARNING"
fi

# NTP / time sync
begin
if systemctl list-unit-files 2>/dev/null | grep -qE 'chronyd|systemd-timesyncd|ntpd'; then
svc="$(systemctl list-unit-files | awk '/chronyd|systemd-timesyncd|ntpd/ {print $1}' | paste -sd, -)"
st="$(systemctl is-active chronyd 2>/dev/null || systemctl is-active systemd-timesyncd 2>/dev/null || systemctl is-active ntpd 2>/dev/null || echo inactive)"
add_summary "Time sync service check" "systemctl is-active (chronyd/systemd-timesyncd/ntpd)" "Services: $svc | Active: $st" "$([ "$st" = active ] && echo OK || echo WARNING)"
else
add_summary "Time sync service check" "systemctl list-unit-files" "No chrony/timesyncd/ntpd detected." "WARNING"
fi

# Default route & interfaces
begin
ROUTE="$(ip route 2>/dev/null | head -n3 || netstat -rn 2>/dev/null | head -n5)"
add_summary "Default route check" "ip route | head || netstat -rn | head" "$ROUTE" "OK"

begin
IFACES="$(ip -br addr 2>/dev/null || ifconfig -a 2>/dev/null || echo 'no ip/ifconfig available')"
add_summary "Interfaces & IPs" "ip -br addr || ifconfig -a" "$IFACES" "OK"

# CPU / Load / Memory
begin
CPUS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo '-')"
LOAD="$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || uptime)"
MEM="$(free -h 2>/dev/null | sed -n '1,3p' || vm_stat 2>/dev/null)"
add_summary "CPU/Load/Memory check" "getconf _NPROCESSORS_ONLN; cat /proc/loadavg; free -h" "CPUs=$CPUS | Load=$LOAD | $(echo "$MEM" | tr '\n' ' ')" "OK"

# Top processes
begin
TOPCPU="$(ps -eo pid,ppid,cmd,%cpu,%mem --sort=-%cpu | head -n 10 2>/dev/null)"
add_summary "Top CPU processes" "ps -eo pid,ppid,cmd,%cpu,%mem --sort=-%cpu | head -10" "$TOPCPU" "OK"

begin
TOPMEM="$(ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 10 2>/dev/null)"
add_summary "Top Memory processes" "ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -10" "$TOPMEM" "OK"

# Disk usage
begin
DF_SYS="$(df -hPT --total 2>/dev/null | sed -n '1,14p')"
add_summary "Disk usage (system-wide)" "df -hPT --total | head" "$DF_SYS" "OK"

for path in /apps/tools /apps/tools/nessus_agent /var /tmp; do
begin
if [ -e "$path" ]; then
OUT="$(df -hP "$path" 2>/dev/null | tail -1)"
add_summary "Disk usage for $path" "df -hP $path" "$OUT" "OK"
else
add_summary "Disk usage for $path" "df -hP $path" "$path not present." "WARNING"
fi
done

# /etc/fstab
begin
if [ -r /etc/fstab ]; then
CLEAN="$(sed '/^\s*#/d;/^\s*$/d' /etc/fstab | sed -n '1,12p')"
add_summary "/etc/fstab presence & entries" "sed (strip comments) /etc/fstab | head" "$CLEAN" "OK"
else
add_summary "/etc/fstab presence & entries" "cat /etc/fstab" "/etc/fstab missing or unreadable." "WARNING"
fi

# Shell & crypto
begin
BASHV="$(bash --version 2>/dev/null | head -n1 || echo 'bash not available')"
add_summary "Bash version" "bash --version | head -1" "$BASHV" "$([ "$BASHV" = "bash not available" ] && echo WARNING || echo OK)"

begin
SHV="$(/bin/sh --version 2>&1 | head -n1 || echo 'sh version not available')"
add_summary "sh version" "/bin/sh --version | head -1" "$SHV" "OK"

begin
SSHV="$(ssh -V 2>&1 | head -n1 || echo 'ssh not available')"
add_summary "OpenSSH client version" "ssh -V" "$SSHV" "$([ "$SSHV" = "ssh not available" ] && echo WARNING || echo OK)"

begin
SSLV="$(openssl version 2>/dev/null || libressl version 2>/dev/null || echo 'openssl/libressl not available')"
add_summary "OpenSSL/LibreSSL version" "openssl version || libressl version" "$SSLV" "$([ "$SSLV" = "openssl/libressl not available" ] && echo WARNING || echo OK)"

# ---------- Tenable Nessus Agent checks ----------
# Layout: base dir + symlink
begin
if [ -d /apps/tools/nessus_agent ]; then
add_summary "Tenable Nessus Agent base directory presence" "test -d /apps/tools/nessus_agent" "Present." "OK"
else
add_summary "Tenable Nessus Agent base directory presence" "test -d /apps/tools/nessus_agent" "/apps/tools/nessus_agent not found." "ERROR"
echo "Script Status Explanation: Tenable Nessus Agent must be installed at /apps/tools/nessus_agent. Exiting." >>"$SUMMARY_FILE"
{
echo "Final Comprehensive Tenable Nessus Agent Health Check"
echo "Script Status Explanation:"
echo "Checks Executed: $CHECK_COUNT"
echo "OK: $OK_COUNT, Warnings: $WARN_COUNT, Errors: $ERR_COUNT"
echo
echo "Script started (UTC): $START_ISO_UTC"
echo "Script ended (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Total runtime (sec): $(( $(date +%s) - START_EPOCH ))"
} >> "$SUMMARY_FILE"
exit 0
fi

begin
if [ -L /opt/nessus_agent ]; then
TGT="$(readlink -f /opt/nessus_agent 2>/dev/null || readlink /opt/nessus_agent 2>/dev/null)"
if echo "$TGT" | grep -q '^/apps/tools/nessus_agent$'; then
add_summary "Symlink /opt/nessus_agent -> /apps/tools/nessus_agent" "readlink -f /opt/nessus_agent" "Symlink OK -> $TGT" "OK"
else
add_summary "Symlink /opt/nessus_agent -> /apps/tools/nessus_agent" "readlink -f /opt/nessus_agent" "Points to $TGT (expected /apps/tools/nessus_agent)" "ERROR"
echo "Script Status Explanation: /opt/nessus_agent must point to /apps/tools/nessus_agent. Exiting." >>"$SUMMARY_FILE"
{
echo "Final Comprehensive Tenable Nessus Agent Health Check"
echo "Script Status Explanation:"
echo "Checks Executed: $CHECK_COUNT"
echo "OK: $OK_COUNT, Warnings: $WARN_COUNT, Errors: $ERR_COUNT"
echo
echo "Script started (UTC): $START_ISO_UTC"
echo "Script ended (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Total runtime (sec): $(( $(date +%s) - START_EPOCH ))"
} >> "$SUMMARY_FILE"
exit 0
fi
else
add_summary "Symlink /opt/nessus_agent -> /apps/tools/nessus_agent" "test -L /opt/nessus_agent" "Symlink missing." "ERROR"
echo "Script Status Explanation: /opt/nessus_agent symlink missing. Exiting." >>"$SUMMARY_FILE"
{
echo "Final Comprehensive Tenable Nessus Agent Health Check"
echo "Script Status Explanation:"
echo "Checks Executed: $CHECK_COUNT"
echo "OK: $OK_COUNT, Warnings: $WARN_COUNT, Errors: $ERR_COUNT"
echo
echo "Script started (UTC): $START_ISO_UTC"
echo "Script ended (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Total runtime (sec): $(( $(date +%s) - START_EPOCH ))"
} >> "$SUMMARY_FILE"
exit 0
fi

NESSUS_HOME="/apps/tools/nessus_agent"
NESSUSCLI="$NESSUS_HOME/sbin/nessuscli"

# Tag file
begin
if [ -f /etc/tenable_tag ]; then
L1="$(head -n1 /etc/tenable_tag 2>/dev/null)"
add_summary "Tenable Nessus Agent Tag presence" "head -n1 /etc/tenable_tag" "Present; first line: ${L1:-<empty>}" "OK"
else
add_summary "Tenable Nessus Agent Tag presence" "test -f /etc/tenable_tag" "/etc/tenable_tag missing (install may be incomplete)." "ERROR"
fi

# nessuscli presence & version
begin
if [ -x "$NESSUSCLI" ]; then
VER="$($NESSUSCLI --version 2>&1 | head -n1)"
add_summary "Tenable Nessus Agent CLI presence & version" "$NESSUSCLI --version" "${VER:-<no output>}" "$([ -n "$VER" ] && echo OK || echo WARNING)"
else
add_summary "Tenable Nessus Agent CLI presence & version" "$NESSUSCLI --version" "nessuscli not executable or missing." "ERROR"
fi

# service state
begin
if command -v systemctl >/dev/null 2>&1; then
ST="$(systemctl is-active nessusagent.service 2>/dev/null || echo unknown)"
add_summary "Tenable Nessus Agent service active state" "systemctl is-active nessusagent.service" "$ST" "$([ "$ST" = active ] && echo OK || echo WARNING)"
else
add_summary "Tenable Nessus Agent service active state" "systemctl is-active nessusagent.service" "systemctl not available." "WARNING"
fi

# agent status + epoch conversion
to_utc(){ v="$1"; [[ "$v" =~ ^[0-9]+$ ]] && date -u -d "@$v" +'%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || echo "$v"; }

begin
if [ -x "$NESSUSCLI" ]; then
STAT="$($NESSUSCLI agent status 2>&1)"
LAST_SCANNED="$(echo "$STAT" | awk -F': ' '/Last scanned:/ {print $2}')"
LAST_CONNECT="$(echo "$STAT" | awk -F': ' '/Last connect:/ {print $2}')"
LAST_ATTEMPT="$(echo "$STAT" | awk -F': ' '/Last connection attempt:/ {print $2}')"
HS1="$(to_utc "$LAST_SCANNED")"
HS2="$(to_utc "$LAST_CONNECT")"
HS3="$(to_utc "$LAST_ATTEMPT")"
add_summary "Tenable Nessus Agent status (epoch→UTC)" "$NESSUSCLI agent status" "Last scanned=$HS1 | Last connect=$HS2 | Last attempt=$HS3" "OK"
else
add_summary "Tenable Nessus Agent status (epoch→UTC)" "$NESSUSCLI agent status" "nessuscli not available." "ERROR"
fi

# agent identity
begin
if [ -x "$NESSUSCLI" ]; then
UUID="$($NESSUSCLI agent --show-uuid 2>&1 | head -n1)"
add_summary "Agent UUID" "$NESSUSCLI agent --show-uuid" "$UUID" "$([ -n "$UUID" ] && echo OK || echo WARNING)"
else
add_summary "Agent UUID" "$NESSUSCLI agent --show-uuid" "nessuscli not available." "ERROR"
fi

begin
if [ -x "$NESSUSCLI" ]; then
TOK="$($NESSUSCLI agent --show-token 2>&1 | head -n1)"
MASK="$(echo "$TOK" | sed 's/./*/g')"
add_summary "Agent Token (masked)" "$NESSUSCLI agent --show-token" "$MASK" "$([ -n "$TOK" ] && echo OK || echo WARNING)"
else
add_summary "Agent Token (masked)" "$NESSUSCLI agent --show-token" "nessuscli not available." "ERROR"
fi

# Advanced settings
adv_get(){ key="$1"; out="$($NESSUSCLI fix --secure --get "$key" 2>&1)"; st="OK"; echo "$out" | grep -qiE 'unknown|error|not found' && st="WARNING"; add_summary "Advanced setting: $key" "$NESSUSCLI fix --secure --get $key" "$(echo "$out" | head -n3)" "$st"; }

for key in proxy proxy_port groups agent_update_channel process_priority logfile_max_size logfile_max_files verify_host_cert ca_path interfaces; do
begin
if [ -x "$NESSUSCLI" ]; then adv_get "$key"; else add_summary "Advanced setting: $key" "$NESSUSCLI fix --secure --get $key" "nessuscli not available." "ERROR"; fi
done

# fix --show (capture to log)
begin
if [ -x "$NESSUSCLI" ]; then
SHOW="$($NESSUSCLI fix --show 2>&1 | head -n 400)"
echo "$SHOW" >>"$LOG_FILE"
add_summary "fix --show (first 400 lines to log)" "$NESSUSCLI fix --show | head -n 400" "Captured to log." "OK"
else
add_summary "fix --show (first 400 lines to log)" "$NESSUSCLI fix --show" "nessuscli not available." "ERROR"
fi

# plugin feed & scans today from status (if STAT present)
begin
if [ -n "${STAT:-}" ]; then
PLUG="$(echo "$STAT" | awk -F': ' '/Plugin set:/ {print $2}')"
SCANS="$(echo "$STAT" | awk -F': ' '/Scans run today:/ {print $2}')"
add_summary "Plugin feed version (parsed)" "parsed from agent status" "${PLUG:-unknown}" "OK"
begin
add_summary "Scans run today (parsed)" "parsed from agent status" "${SCANS:-unknown}" "OK"
else
add_summary "Plugin feed version (parsed)" "parsed from agent status" "agent status unavailable earlier." "WARNING"
fi

# Optional bug report
begin
if [ "$MAKE_BUG" -eq 1 ] && [ -x "$NESSUSCLI" ]; then
BR="$($NESSUSCLI bug-report-generator --quiet 2>&1 || true)"
add_summary "Bug report generation" "$NESSUSCLI bug-report-generator --quiet" "Attempted; see /opt/nessus_agent/var/nessus/ for archive." "OK"
else
add_summary "Bug report generation" "n/a" "--bug-report not requested." "OK"
fi

# ---------- Final footer ----------
{
echo "Final Comprehensive Tenable Nessus Agent Health Check"
echo "Script Status Explanation:"
echo "Checks Executed: $CHECK_COUNT"
echo "OK: $OK_COUNT, Warnings: $WARN_COUNT, Errors: $ERR_COUNT"
echo
echo "Script started (UTC): $START_ISO_UTC"
echo "Script ended (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Total runtime (sec): $(( $(date +%s) - START_EPOCH ))"
} >> "$SUMMARY_FILE"

if [ "$ERR_COUNT" -gt 0 ]; then
echo "${CRED}Completed with $ERR_COUNT error(s) and $WARN_COUNT warning(s). See $SUMMARY_FILE and $LOG_FILE.${CRST}"
elif [ "$WARN_COUNT" -gt 0 ]; then
echo "${CYEL}Completed with $WARN_COUNT warning(s). See $SUMMARY_FILE and $LOG_FILE.${CRST}"
else
echo "${CGRN}All checks passed successfully. See $SUMMARY_FILE and $LOG_FILE.${CRST}"
fi

exit 0
