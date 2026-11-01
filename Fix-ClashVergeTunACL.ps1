<#
.SYNOPSIS
    Repair over-permissive ACLs on a Windows volume root (default C:\).

.DESCRIPTION
    Some tools and "one-click permission fix" guides leave a volume root
    world-writable, e.g.:

        Everyone : Full Control   (inherited by subfolders and files)
        BUILTIN\Users : Modify   (applied to the root itself)

    Windows never ships like that. Besides being a privilege-escalation
    hole, it makes security-aware software refuse to run. The well-known
    symptom is Clash Verge Rev failing to start the mihomo core:

        verge-mihomo.exe: core path "\\?\C:\" has an untrusted write ACE:
        ace_index=4, sid=S-1-5-32-545, type=0, flags=0x03,
        mask=0x001F01FF, dangerous=0x000C0040

    This script removes the Everyone and BUILTIN\Users ACEs and re-adds
    Users in the shape Windows uses by default:

        Users : Read & Execute   (this folder only)
        Users : Modify           (subfolders and files only, inherit-only)

    so folders under the root stay usable for everyday work, while the
    root itself is no longer writable by non-administrators.

    Only the root DACL of one volume is touched:
      * no recursion into subfolders
      * no /reset, no ownership change, no file deletion
      * the current ACL is saved as an SDDL string before any change

.PARAMETER Root
    Volume root to repair, e.g. "C:\" (default) or "D:\".

.PARAMETER CheckOnly
    Report the current state and exit. No change is made.
    Does not require elevation.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Fix-ClashVergeTunACL.ps1 -CheckOnly

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Fix-ClashVergeTunACL.ps1
    # must be elevated

.LINK
    https://www.clashverge.dev/faq/windows.html
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidatePattern('^[A-Za-z]:\\?$')]
    [string]$Root = 'C:\',

    [switch]$CheckOnly
)

if (-not $Root.EndsWith('\')) { $Root = $Root + '\' }

# Well-known SIDs that must not hold write rights on a volume root.
# S-1-1-0 Everyone, S-1-5-32-545 Users, S-1-5-11 Authenticated Users,
# S-1-5-4 Interactive, S-1-5-2 Network, S-1-5-7 Anonymous,
# plus the account running this script.
$UntrustedSids = @(
    'S-1-1-0',
    'S-1-5-32-545',
    'S-1-5-11',
    'S-1-5-4',
    'S-1-5-2',
    'S-1-5-7',
    [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
)

# Rights that make a volume root "untrusted writable".
# Matches the criteria used by the Clash Verge Rev service: delete child
# objects, change permissions, take ownership, full control.
# Plain "create folder / append data" is a Windows default for
# Authenticated Users and is deliberately NOT treated as dangerous.
$dangerousMask = [int][Security.AccessControl.FileSystemRights](
    'DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
)   # 0x000C0040 - note: FullControl already contains all of these bits

function Get-SidString {
    param($IdentityReference)
    try {
        return $IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        return ''
    }
}

function Get-RootAclFindings {
    param([string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    $results = @()

    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }

        # Inherit-only ACEs never apply to the object itself.
        $prop = [int]$rule.PropagationFlags
        if (($prop -band [int][Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }

        $sid = Get-SidString $rule.IdentityReference
        if ($UntrustedSids -notcontains $sid) { continue }

        if (([int]$rule.FileSystemRights -band $dangerousMask) -eq 0) { continue }

        $results += [pscustomobject]@{
            Account = $rule.IdentityReference.ToString()
            SID     = $sid
            Rights  = $rule.FileSystemRights.ToString()
            AutoFix = ($sid -eq 'S-1-1-0' -or $sid -eq 'S-1-5-32-545')
        }
    }
    return $results
}

function Show-Acl {
    param([string]$Title, [string]$Path)
    Write-Host ''
    Write-Host "=== $Title ===" -ForegroundColor Yellow
    (Get-Acl -LiteralPath $Path).Access | ForEach-Object {
        '  {0,-62} {1,-6} {2}  inherited={3}' -f `
            $_.IdentityReference, $_.AccessControlType, $_.FileSystemRights, $_.IsInherited
    }
}

# ------------------------------------------------------------- CheckOnly
if ($CheckOnly) {
    $findings = Get-RootAclFindings -Path $Root
    Show-Acl -Title "ACL of $Root" -Path $Root
    Write-Host ''
    if ($findings.Count -eq 0) {
        Write-Host "OK: $Root is not writable by untrusted accounts." -ForegroundColor Green
        exit 0
    }
    Write-Host "UNSAFE: $Root grants write-capable rights to untrusted accounts." -ForegroundColor Red
    $findings | ForEach-Object {
        $hint = if ($_.AutoFix) { 'fixed by this script' } else { 'needs manual review' }
        Write-Host ("  {0} ({1}) -> {2}  [{3}]" -f $_.Account, $_.SID, $_.Rights, $hint) -ForegroundColor Red
    }
    exit 1
}

# ------------------------------------------------------------- elevation
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERROR: must be run as Administrator (elevated).' -ForegroundColor Red
    Write-Host 'Use Run-Fix-As-Admin.bat, or an already elevated PowerShell.' -ForegroundColor Red
    exit 1
}

if (-not (Test-Path -LiteralPath $Root)) {
    Write-Host "ERROR: path not found: $Root" -ForegroundColor Red
    exit 1
}

# ------------------------------------------------------------- backup
$backupDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$backup = Join-Path $backupDir ('Root_ACL_backup_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt')
(Get-Acl -LiteralPath $Root).Sddl | Set-Content -Path $backup -Encoding ASCII
Write-Host "[1/4] ACL of $Root backed up to:" -ForegroundColor Cyan
Write-Host "      $backup"

# ------------------------------------------------------------- before
Show-Acl -Title "BEFORE ($Root)" -Path $Root

# ------------------------------------------------------------- remove
$acl = Get-Acl -LiteralPath $Root
$removed = 0
foreach ($rule in @($acl.Access)) {
    $sid = Get-SidString $rule.IdentityReference
    if ($sid -eq 'S-1-1-0' -or $sid -eq 'S-1-5-32-545') {
        [void]$acl.RemoveAccessRule($rule)
        $removed++
    }
}
Write-Host ''
Write-Host "[2/4] Removed $removed ACE(s) for Everyone / Users." -ForegroundColor Cyan

# ------------------------------------------------------------- re-add
$usersSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')

$readRule = New-Object Security.AccessControl.FileSystemAccessRule(
    $usersSid,
    [Security.AccessControl.FileSystemRights]::ReadAndExecute,
    [Security.AccessControl.InheritanceFlags]::None,
    [Security.AccessControl.PropagationFlags]::None,
    [Security.AccessControl.AccessControlType]::Allow
)

$modifyRule = New-Object Security.AccessControl.FileSystemAccessRule(
    $usersSid,
    [Security.AccessControl.FileSystemRights]::Modify,
    ([Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'),
    [Security.AccessControl.PropagationFlags]::InheritOnly,
    [Security.AccessControl.AccessControlType]::Allow
)

[void]$acl.AddAccessRule($readRule)
[void]$acl.AddAccessRule($modifyRule)

if ($PSCmdlet.ShouldProcess($Root, 'Apply repaired ACL')) {
    Set-Acl -LiteralPath $Root -AclObject $acl
}
Write-Host '[3/4] New ACL applied.' -ForegroundColor Cyan

# ------------------------------------------------------------- after
Show-Acl -Title "AFTER ($Root)" -Path $Root

$remaining = Get-RootAclFindings -Path $Root
Write-Host ''
if ($remaining.Count -eq 0) {
    Write-Host "[4/4] OK: $Root is no longer writable by untrusted accounts." -ForegroundColor Green
} else {
    Write-Host '[4/4] WARNING: still writable by:' -ForegroundColor Yellow
    $remaining | ForEach-Object {
        Write-Host ("      {0} ({1}) -> {2}" -f $_.Account, $_.SID, $_.Rights) -ForegroundColor Yellow
    }
    Write-Host '      These are not Everyone/Users entries and were left untouched.'
    Write-Host '      Review them manually in Properties > Security > Advanced.'
}

Write-Host ''
Write-Host 'If the goal was Clash Verge Rev TUN mode:'
Write-Host '  1) Fully quit Clash Verge Rev from the tray icon.'
Write-Host '  2) Start it again as a NORMAL user.'
Write-Host '  3) Settings > Service Mode: reinstall / repair the service.'
Write-Host '  4) Turn TUN mode back on.'
Write-Host ''
Write-Host ('Rollback SDDL: ' + $backup)
