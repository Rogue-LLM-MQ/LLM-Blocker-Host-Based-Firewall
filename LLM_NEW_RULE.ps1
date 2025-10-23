<# 
.SYNOPSIS
  Blocks outbound traffic to common LLM/AI domains by resolving their A/AAAA records
  and creating per-IP block rules. Safe to re-run . Includes uninstall.

.PARAMETER BlockBrowsers
  Also block outbound traffic from major browsers.

.PARAMETER LogFile
  Custom log path.

.PARAMETER Domains
  Override the default domain list.

.EXAMPLE
  .\LLM_NEW_RULE.ps1

.EXAMPLE
  .\LLM_NEW_RULE.ps1 -BlockBrowsers

.EXAMPLE
  .\LLM_NEW_RULE.ps1 -Uninstall
#>

[CmdletBinding()]
param(
  [switch]$BlockBrowsers,
  [switch]$Uninstall,
  [string]$LogFile = "C:\Users\omkar\OneDrive\Desktop\Chatgpt\llm_block_log.txt",
  [string[]]$Domains = @(
    "chat.openai.com",
    "chatgpt.com",
    "claude.ai",
    "gemini.google.com",
    "character.ai",
    "aistudio.google.com",
    "stableaudio.com",
    "dreamstudio.stability.ai",
    "deepseek.com",
    "copilot.microsoft.com",
    "perplexity.ai",
    "huggingface.co",
    "phind.com",
    "jasper.ai",
    "poe.com"
  )
)

# ---- Admin check -------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "Run this script in an elevated PowerShell session (as Administrator)."
  exit 1
}

# ---- Constants ---------------------------------------------------------------
$RuleGroup  = "LLM Firewall Block"
$RulePrefix = "LLM_Block"
$BrowserRulePrefix = "LLM_Block_Browser"

$BrowserPaths = @(
  "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
  "$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe",
  "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
  "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
)

# ---- Logging ----------------------------------------------------------------
if (!(Test-Path $LogFile)) {
  New-Item -ItemType File -Path $LogFile -Force | Out-Null
}
Add-Content $LogFile "`n=== $(if($Uninstall){'LLM Firewall Uninstall'}else{'LLM Firewall Block'}) started at $(Get-Date) ==="

function Log([string]$msg) {
  $line = "[$(Get-Date -f s)] $msg"
  Add-Content $LogFile $line
  Write-Host $line
}

# ---- Uninstall path ----------------------------------------------------------
if ($Uninstall) {
  $toRemove = Get-NetFirewallRule -PolicyStore ActiveStore -Group $RuleGroup -ErrorAction SilentlyContinue
  if ($toRemove) {
    $toRemove | Remove-NetFirewallRule
    Log "Removed $(($toRemove | Measure-Object).Count) firewall rule(s) in group '$RuleGroup'."
  } else {
    Log "No rules found in group '$RuleGroup'."
  }
  Log "=== Uninstall finished ==="
  exit 0
}

# ---- Resolve and (idempotently) create rules --------------------------------
$resolvedCount = 0
$createdCount  = 0

foreach ($domain in $Domains) {
  try {
    # Collect unique IPv4/IPv6; Resolve-DnsName may throw or return duplicates
    $ips = (Resolve-DnsName -Name $domain -Type A,AAAA -ErrorAction Stop |
            Where-Object { $_.Type -in @('A','AAAA') } |
            Select-Object -ExpandProperty IPAddress -Unique)

    if (-not $ips) {
      Log "WARN: No IPs resolved for $domain."
      continue
    }

    $resolvedCount += $ips.Count
    foreach ($ip in $ips) {
      # Rule name is fixed per domain+IP so re-runs won't duplicate
      $safeIp = ($ip -replace ":", "_")        # Windows rule names can't handle ':'
      $ruleName = "$RulePrefix`_${domain}`_${safeIp}"

      $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
      if ($existing) {
        # Update the rule if it drifted (ensure it's enabled, outbound, block, same group)
        Set-NetFirewallRule -DisplayName $ruleName -Enabled True -Direction Outbound -Action Block -Group $RuleGroup -Profile Any | Out-Null
        # Ensure correct endpoint set (some systems expose this separately by filter)
        # For safety, re-apply remote address:
        Set-NetFirewallRule -DisplayName $ruleName -RemoteAddress $ip | Out-Null
        Log "Updated existing rule: $ruleName ($ip)"
      } else {
        New-NetFirewallRule `
          -DisplayName $ruleName `
          -Group $RuleGroup `
          -Direction Outbound `
          -Action Block `
          -RemoteAddress $ip `
          -Enabled True `
          -Profile Any `
          -Description "Block outbound to $domain ($ip) - $RuleGroup" | Out-Null
        $createdCount++
        Log "Created block rule for $domain ($ip)"
      }
    }
  }
  catch {
    Log "ERROR: Failed to resolve or create rules for $domain. $($_.Exception.Message)"
  }
}

# ---- Optional: Block browser executables (global, not domain-scoped) --------
if ($BlockBrowsers) {
  foreach ($path in $BrowserPaths) {
    if (Test-Path $path) {
      $name = Split-Path $path -Leaf
      $ruleName = "$BrowserRulePrefix`_$name"
      $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
      if (-not $existing) {
        New-NetFirewallRule `
          -DisplayName $ruleName `
          -Group $RuleGroup `
          -Program $path `
          -Direction Outbound `
          -Action Block `
          -Enabled True `
          -Profile Any `
          -Description "Blocks ALL outbound traffic for $name - $RuleGroup" | Out-Null
        Log "Created global browser block for $name"
      } else {
        Set-NetFirewallRule -DisplayName $ruleName -Enabled True -Direction Outbound -Action Block -Group $RuleGroup -Profile Any | Out-Null
        Log "Updated existing global browser block for $name"
      }
    }
  }
} else {
  Log "Browser blocking skipped (use -BlockBrowsers to enable)."
}

Log "Resolved IPs total: $resolvedCount"
Log "New rules created: $createdCount"
Log "=== LLM Firewall Block finished at $(Get-Date) ==="
Write-Host "LLM/ChatGPT blocking rules applied/updated. See log: $LogFile"




