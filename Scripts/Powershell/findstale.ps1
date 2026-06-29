<#
.SYNOPSIS
    Finds stale Active Directory user accounts and stages them for cleanup.

.DESCRIPTION
    Identifies enabled accounts that have not logged on within a threshold,
    excluding accounts you explicitly protect (service accounts, break-glass,
    never-logged-on-but-recently-created, etc).

    Default action is REPORT ONLY. Disabling and deletion are opt in.

    Recommended lifecycle:
        1. Report     (default)        review the list
        2. Disable    (-Disable)       move to a holding OU, disable
        3. Delete     (-Delete)        only after a quarantine window

.PARAMETER InactiveDays
    Days since last logon to consider an account stale. Default 90.

.PARAMETER SearchBase
    Optional OU distinguished name to limit the scope. Default is the whole domain.

.PARAMETER ExcludeGroups
    Accounts in these groups are never touched. Put your service account and
    break-glass groups here.

.PARAMETER Disable
    Disable the stale accounts and move them to the holding OU.

.PARAMETER HoldingOU
    Distinguished name of the OU to move disabled accounts into.

.PARAMETER Delete
    Permanently delete. Requires accounts to already be disabled and older than
    -QuarantineDays. Will not run unless -IUnderstand is also passed.

.PARAMETER QuarantineDays
    Minimum days an account must have been disabled before -Delete will remove it.
    Default 30.

.PARAMETER IUnderstand
    Safety switch required for -Delete. Forces you to acknowledge the action.

.EXAMPLE
    .\Find-StaleADAccounts.ps1
    Reports accounts stale for 90+ days. Touches nothing.

.EXAMPLE
    .\Find-StaleADAccounts.ps1 -InactiveDays 120 -Disable -HoldingOU "OU=Disabled,DC=keenan,DC=sec"
    Disables accounts inactive 120+ days and moves them to the holding OU.

.EXAMPLE
    .\Find-StaleADAccounts.ps1 -Delete -IUnderstand -QuarantineDays 30
    Deletes accounts that were already disabled 30+ days ago.

.NOTES
    Requires the ActiveDirectory module (RSAT) and rights to read/modify the
    target accounts. Run the report mode first. Always.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [int]$InactiveDays = 90,

    [string]$SearchBase,

    [string[]]$ExcludeGroups = @('Service Accounts', 'Break Glass', 'Protected Accounts'),

    [switch]$Disable,

    [string]$HoldingOU,

    [switch]$Delete,

    [int]$QuarantineDays = 30,

    [switch]$IUnderstand,

    [string]$ReportPath = ".\StaleAccounts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

# --- Preflight ---------------------------------------------------------------

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT first."
    return
}
Import-Module ActiveDirectory -ErrorAction Stop

if ($Disable -and -not $HoldingOU) {
    Write-Error "-Disable requires -HoldingOU so you can review accounts before deletion."
    return
}

if ($Delete -and -not $IUnderstand) {
    Write-Error "-Delete is destructive. Re-run with -IUnderstand once you have reviewed the list."
    return
}

$cutoff = (Get-Date).AddDays(-$InactiveDays)

# Build the list of SamAccountNames that are off limits.
$protected = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($g in $ExcludeGroups) {
    try {
        Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop |
            Where-Object objectClass -eq 'user' |
            ForEach-Object { [void]$protected.Add($_.SamAccountName) }
    }
    catch {
        Write-Warning "Exclude group '$g' not found or unreadable. Skipping it."
    }
}

# --- Find stale accounts -----------------------------------------------------

$props = 'LastLogonDate', 'whenCreated', 'Enabled', 'DistinguishedName',
         'Description', 'PasswordLastSet', 'Modified'

$adParams = @{
    Filter     = 'Enabled -eq $true'
    Properties = $props
}
if ($SearchBase) { $adParams['SearchBase'] = $SearchBase }

$stale = Get-ADUser @adParams | Where-Object {
    # exclude protected accounts
    -not $protected.Contains($_.SamAccountName) -and
    # never logged on AND created before the cutoff (truly abandoned),
    # or logged on but not since the cutoff
    (
        ($_.LastLogonDate -and $_.LastLogonDate -lt $cutoff) -or
        (-not $_.LastLogonDate -and $_.whenCreated -lt $cutoff)
    )
}

if (-not $stale) {
    Write-Host "No stale accounts found older than $InactiveDays days. Clean domain." -ForegroundColor Green
    return
}

$report = $stale | Select-Object SamAccountName, Name, Enabled,
    @{N = 'LastLogon'; E = { if ($_.LastLogonDate) { $_.LastLogonDate } else { 'NEVER' } } },
    @{N = 'DaysInactive'; E = {
        $ref = if ($_.LastLogonDate) { $_.LastLogonDate } else { $_.whenCreated }
        [int]((Get-Date) - $ref).TotalDays
    } },
    whenCreated, PasswordLastSet, Description, DistinguishedName

$report | Export-Csv -Path $ReportPath -NoTypeInformation
Write-Host "Found $($stale.Count) stale account(s). Report written to $ReportPath" -ForegroundColor Yellow
$report | Format-Table SamAccountName, LastLogon, DaysInactive, Enabled -AutoSize

# --- Report only -------------------------------------------------------------

if (-not $Disable -and -not $Delete) {
    Write-Host "`nReport mode only. Nothing changed. Review the CSV, then re-run with -Disable." -ForegroundColor Cyan
    return
}

# --- Disable stage -----------------------------------------------------------

if ($Disable) {
    foreach ($acct in $stale) {
        if ($PSCmdlet.ShouldProcess($acct.SamAccountName, "Disable and move to $HoldingOU")) {
            try {
                Disable-ADAccount -Identity $acct.DistinguishedName -ErrorAction Stop
                Set-ADUser -Identity $acct.DistinguishedName -Description "Disabled stale $(Get-Date -Format yyyy-MM-dd). $($acct.Description)" -ErrorAction Stop
                Move-ADObject -Identity $acct.DistinguishedName -TargetPath $HoldingOU -ErrorAction Stop
                Write-Host "Disabled and moved: $($acct.SamAccountName)" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed on $($acct.SamAccountName): $($_.Exception.Message)"
            }
        }
    }
}

# --- Delete stage ------------------------------------------------------------

if ($Delete) {
    $quarantineCutoff = (Get-Date).AddDays(-$QuarantineDays)

    foreach ($acct in $stale) {
        # Only delete accounts that are already disabled and have sat past quarantine.
        if ($acct.Enabled) {
            Write-Warning "Skipping $($acct.SamAccountName): still enabled. Disable it first."
            continue
        }
        if ($acct.Modified -gt $quarantineCutoff) {
            Write-Warning "Skipping $($acct.SamAccountName): not past $QuarantineDays day quarantine."
            continue
        }

        if ($PSCmdlet.ShouldProcess($acct.SamAccountName, "PERMANENTLY DELETE")) {
            try {
                Remove-ADUser -Identity $acct.DistinguishedName -Confirm:$false -ErrorAction Stop
                Write-Host "Deleted: $($acct.SamAccountName)" -ForegroundColor Red
            }
            catch {
                Write-Warning "Failed to delete $($acct.SamAccountName): $($_.Exception.Message)"
            }
        }
    }
}