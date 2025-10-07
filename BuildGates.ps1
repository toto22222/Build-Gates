# Automated Windows Build Audit Script
# -----------------
# Run this script as Administrator for full functionality
# Before running this script on powershell, please ensure you are running with execution policy bypassed
# e.g. powershell -ep bypass
# -----------------
# Remark: BIOS checks available for Lenovo device only as of now
# -----------------

Write-Output @"
                                             
                                                      
   (             (   (    (                )          
 ( )\    (   (   )\  )\ ) )\ )       )  ( /(   (      
 )((_)  ))\  )\ ((_)(()/((()/(    ( /(  )\()) ))\ (   
((_)_  /((_)((_) _  ((_))/(_))_  )(_))(_))/ /((_))\  
 | _ )(_))(  (_)| | _| |(_)) __|((_)_ | |_ (_)) ((_) 
 | _ \| || | | || |/ _` |  | (_ |/ _`  ||  _|/ -_)(_-< 
 |___/ \_,_| |_||_|\_,_|   \___|\__,_| \__|\___|/__/ 
                                                      
----------------------------
A tool for automated Windows Build Review.
Last Update: 03-10-2025
----------------------------
"@



# Function to check if running as Administrator
function Is-Admin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Initialize global array to store warnings
$global:Warnings = @()

# Start of script
Write-Host "Starting Windows Build Audit..." -ForegroundColor Green

try {
    # Get username
    Write-Host "`n--- User Name ---" -ForegroundColor Cyan
    whoami
} catch {
    Write-Error "Error getting username: $_"
}
Start-Sleep -Milliseconds 500


try {
    # Systeminfo - grep specific info
    Write-Host "`n--- System Info ---" -ForegroundColor Cyan
    $systemInfo = systeminfo
    $osName = $systemInfo | Select-String "OS Name"
    $osVersion = $systemInfo | Select-String "OS Version"
    $osManufacturer = $systemInfo | Select-String "OS Manufacturer"
    $domain = $systemInfo | Select-String "Domain"
    $vbsStatus = $systemInfo | Select-String "Virtualization-based Security"
    
    # Extract hotfixes more precisely
    $hotfixStart = $systemInfo | Select-String "Hotfix\(s\)"
    $hotfixIndex = $systemInfo.IndexOf($hotfixStart.Line)
    $hotfixes = @()
    for ($i = $hotfixIndex + 1; $i -lt $systemInfo.Length; $i++) {
        if ($systemInfo[$i].Trim() -eq "" -or $systemInfo[$i] -match "Network Card\(s\)" -or $systemInfo[$i] -match "Hyper-V Requirements") {
            break
        }
        $hotfixes += $systemInfo[$i]
    }

    Write-Host $osName
    Write-Host $osVersion
    Write-Host $osManufacturer
    Write-Host $domain
    Write-Host $vbsStatus
    Write-Host "Hotfixes:"
    $hotfixes

    # Check Virtualization-based Security status
    if ($vbsStatus -notmatch "Running") {
        Write-Host "Warning: Virtualization-based Security is not Running" -ForegroundColor Yellow
        $global:Warnings += "Virtualization-based Security is not Running"
    }
} catch {
    Write-Error "Error getting systeminfo: $_"
}
Start-Sleep -Milliseconds 500


try {
    # Check applied group policy
    Write-Host "`n--- Applied Group Policy Objects ---" -ForegroundColor Cyan
    $gpResult = gpresult /R
    $appliedGPOs = $gpResult | Select-String "Applied Group Policy Objects" -Context 0,10
    Write-Host $appliedGPOs
    Write-Host "....... if you need more info use command gpresult /R"
} catch {
    Write-Error "Error getting gpresult: $_"
}
Start-Sleep -Milliseconds 500

try {
    # Check account lockout policy, password policy
    Write-Host "`n--- Account Policies ---" -ForegroundColor Cyan
    net accounts
} catch {
    Write-Error "Error getting net accounts: $_"
}
Start-Sleep -Milliseconds 500


try {
    # Check groups
    Write-Host "`n--- User Groups ---" -ForegroundColor Cyan
    $groups = whoami /groups
    $groups
    # Strings to check in group names
    $sensitiveStrings = @("admin", "debug", "backup", "elevated", "operator", "owner", "controller", "log", "remote", "server", "manage", "config", "sql")  
    $foundSensitiveGroups = @()

    foreach ($group in $groups) {
        # Extract the group name from the output line (first field before extra spaces or tabs)
        $groupName = ($group -split '\s+')[0]
        foreach ($string in $sensitiveStrings) {
            if ($groupName -match "(?i)$string") {  # Case-insensitive match
                $foundSensitiveGroups += $groupName
                Write-Host "Warning: User is in special group '$groupName'" -ForegroundColor Yellow
                $global:Warnings += "User is in special group '$groupName'"
            }
        }
    }
} catch {
    Write-Error "Error getting groups: $_"
}
Start-Sleep -Milliseconds 500


try {
    # Check priv tokens
    Write-Host "`n--- User Privileges ---" -ForegroundColor Cyan
    $privs = whoami /priv
    $privs
    $specialPrivs = @("SeDebugPrivilege", "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeBackupPrivilege", "SeCreateTokenPrivilege", "SeLoadDriverPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege")
    foreach ($priv in $specialPrivs) {
        if ($privs -match $priv) {
            Write-Host "Warning: User has special privilege '$priv'" -ForegroundColor Red
            $global:Warnings += "User has special privilege '$priv'"
        }
    }
    Write-Host "Note: Please review privilege token manually to ensure nothing missed" -ForegroundColor Yellow
} catch {
    Write-Error "Error getting privileges: $_"
}
Start-Sleep -Milliseconds 500

try {
    # Check if local admin and guest are disabled
    Write-Host "`n--- Local Users ---" -ForegroundColor Cyan
    $localUsers = Get-LocalUser
    $localUsers | Format-Table Name, Enabled
    if (($localUsers | Where-Object { $_.Name -eq 'Administrator' -and $_.Enabled -eq $true })) {
        Write-Host "Warning: Local Administrator is enabled" -ForegroundColor Yellow
        $global:Warnings += "Local Administrator is enabled"
    }
    if (($localUsers | Where-Object { $_.Name -eq 'Guest' -and $_.Enabled -eq $true })) {
        Write-Host "Warning: Local Guest is enabled" -ForegroundColor Yellow
        $global:Warnings += "Local Guest is enabled"
    }
} catch {
    Write-Error "Error getting local users: $_"
}
Start-Sleep -Milliseconds 500

try {
    # Check who is local admin
    Write-Host "`n--- Local Administrators Group ---" -ForegroundColor Cyan
    net localgroup Administrators
} catch {
    Write-Error "Error getting local administrators: $_"
}
Start-Sleep -Milliseconds 500

try {
    # Check cached logons count
    Write-Host "`n--- Cached Logons Count ---" -ForegroundColor Cyan
    $winlogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount
    Write-Host "CachedLogonsCount: $($winlogon.CachedLogonsCount)"
    $value = $winlogon.CachedLogonsCount -as [int]
    if ($value -gt 4) {
        Write-Host "Warning: CachedLogonsCount is greater than 4 ($value)" -ForegroundColor Yellow
        $global:Warnings += "CachedLogonsCount is greater than 4 ($value)"
    }
} catch {
    Write-Error "Error querying cached logons: $_"
}
Start-Sleep -Milliseconds 500

try {
    # Check LSA Protection
    Write-Host "`n--- LSA Protection Status ---" -ForegroundColor Cyan
    $lsaRunAsPPL = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
    $lsaRunAsPPLBoot = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPLBoot" -ErrorAction SilentlyContinue
    
    # Print RunAsPPL value
    Write-Host "RunAsPPL: $($lsaRunAsPPL.RunAsPPL)"
    
    # Check RunAsPPL
    if ($lsaRunAsPPL -and $lsaRunAsPPL.RunAsPPL -eq 1) {
        Write-Host "RunAsPPL: Enabled with UEFI variable"
    } elseif ($lsaRunAsPPL -and $lsaRunAsPPL.RunAsPPL -eq 0) {
        Write-Host "Warning: RunAsPPL is disabled" -ForegroundColor Red
        $global:Warnings += "RunAsPPL is disabled"
    } elseif ($lsaRunAsPPL -and $lsaRunAsPPL.RunAsPPL -eq 2) {
        Write-Host "Warning: RunAsPPL is enabled without UEFI variable" -ForegroundColor Yellow
        $global:Warnings += "RunAsPPL is enabled without UEFI variable"
    } else {
        Write-Host "Warning: RunAsPPL is not set or has an unexpected value (current value: $($lsaRunAsPPL.RunAsPPL))" -ForegroundColor Red
        $global:Warnings += "RunAsPPL is not set or has an unexpected value"
    }
    
    # Print RunAsPPLBoot value
    Write-Host "RunAsPPLBoot: $($lsaRunAsPPLBoot.RunAsPPLBoot)"
    
    # Check RunAsPPLBoot alignment with RunAsPPL
    if ($lsaRunAsPPLBoot -and $lsaRunAsPPL -and $lsaRunAsPPLBoot.RunAsPPLBoot -eq $lsaRunAsPPL.RunAsPPL) {
        Write-Host "RunAsPPLBoot: Aligned with RunAsPPL (value: $($lsaRunAsPPLBoot.RunAsPPLBoot))"
    } else {
        Write-Host "Warning: RunAsPPLBoot is not aligned with RunAsPPL (current value: $($lsaRunAsPPLBoot.RunAsPPLBoot))" -ForegroundColor Yellow
        $global:Warnings += "RunAsPPLBoot is not aligned with RunAsPPL"
    }

    # Note on best practices
    Write-Host "Note: For best security practices, RunAsPPL should be set to 1 (enabled with UEFI variable) and RunAsPPLBoot should match RunAsPPL." -ForegroundColor Yellow
} catch {
    Write-Error "Error checking LSA protection status: $_"
}
Start-Sleep -Milliseconds 500


if (Is-Admin) {
    try {
        # Confirm Secure Boot
        Write-Host "`n--- Secure Boot Status ---" -ForegroundColor Cyan
        $secureBoot = Confirm-SecureBootUEFI
        Write-Host "Secure Boot Enabled: $secureBoot"
        if (-not $secureBoot) {
            Write-Host "Warning: Secure Boot is not enabled" -ForegroundColor Red
            $global:Warnings += "Secure Boot is not enabled"
        }
    } catch {
        Write-Error "Error checking Secure Boot: $_"
    }
    Start-Sleep -Milliseconds 500

    try {
        # BitLocker status
        Write-Host "`n--- BitLocker Status ---" -ForegroundColor Cyan
        $bdeStatus = manage-bde -status
        $protectionLine = $bdeStatus | Select-String "Protection Status:"
        Write-Host $protectionLine
        if ($protectionLine -notmatch "\s*Protection Status:\s*Protection On") {
            Write-Host "Warning: BitLocker protection is not on" -ForegroundColor Red
            $global:Warnings += "BitLocker protection is not on"
        }
    } catch {
        Write-Error "Error checking BitLocker: $_"
    }
} else {
    Write-Host "`n--- Secure Boot Status ---" -ForegroundColor Cyan
    Write-Host "`nWarning: Skipping Secure Boot check - not running as Administrator" -ForegroundColor Yellow
    $global:Warnings += "Skipped Secure Boot check - not running as Administrator"
    Write-Host "`n--- BitLocker Status ---" -ForegroundColor Cyan
    Write-Host "`nWarning: Skipping BitLocker check - not running as Administrator" -ForegroundColor Yellow
    $global:Warnings += "Skipped BitLocker check - not running as Administrator"
}
Start-Sleep -Milliseconds 500


if (Is-Admin) {
    try {
        # Check System Manufacturer
        $systemInfo = systeminfo
        $manufacturer = $systemInfo | Select-String "System Manufacturer"
        Write-Host "`n--- BIOS Password Protection ---" -ForegroundColor Cyan
        if ($manufacturer -match "Lenovo") {
            # BIOS Password Protection (Lenovo-specific)
            $biosSettings = Get-WmiObject -Namespace root\WMI -Class Lenovo_BiosSetting |
                Where-Object { ($_.CurrentSetting -split ',')[0] -in @('SystemManagementPasswordControl','BIOSPasswordAtBootDeviceList') } |
                Select-Object InstanceName, CurrentSetting, Active |
                Format-Table -AutoSize
            $biosSettings
            $disableFound = Get-WmiObject -Namespace root\WMI -Class Lenovo_BiosSetting |
                Where-Object { ($_.CurrentSetting -split ',')[0] -in @('SystemManagementPasswordControl','BIOSPasswordAtBootDeviceList') -and $_.CurrentSetting -match 'Disable' }
            if ($disableFound) {
                Write-Host "Warning: BIOS or UEFI password protection may not be implemented" -ForegroundColor Red
                $global:Warnings += "BIOS or UEFI password protection may not be implemented"
            }
            Write-Host "Note: Please review BIOS settings manually to confirm" -ForegroundColor Yellow
        } else {
            Write-Host "Warning: BIOS Password Protection check skipped - Unsupported System Manufacturer (current: $manufacturer)" -ForegroundColor Yellow
            Write-Host "BIOS checks available for Lenovo devices only as of now" -ForegroundColor Yellow
            $global:Warnings += "BIOS Password Protection check skipped - Unsupported System Manufacturer "
        }
    } catch {
        Write-Error "Error checking BIOS password protection or system manufacturer: $_"
    }
} else {
    Write-Host "`n--- BIOS Password Protection ---" -ForegroundColor Cyan
    Write-Host "`nWarning: Skipping BIOS Password Protection check - not running as Administrator" -ForegroundColor Yellow
    $global:Warnings += "Skipped BIOS Password Protection check - not running as Administrator"
}
Start-Sleep -Milliseconds 500

try {
    # Windows Defender status
    Write-Host "`n--- Windows Defender Status ---" -ForegroundColor Cyan
    $mpStatus = Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, IsTamperProtected, AntispywareSignatureLastUpdated, AntivirusSignatureLastUpdated
    Start-Sleep -Milliseconds 100  # Ensure output is captured before proceeding
    $mpStatus | Format-Table -AutoSize
    if (-not $mpStatus.RealTimeProtectionEnabled -or -not $mpStatus.IsTamperProtected) {
        Write-Host "Warning: Real-time protection or tamper protection is disabled" -ForegroundColor Red
        $global:Warnings += "Real-time protection or tamper protection is disabled"
    }
} catch {
    Write-Error "Error getting Defender status: $_"
}
Start-Sleep -Milliseconds 500

try {
    # UAC Consent Prompt
    Write-Host "`n--- UAC Consent Prompt Behavior ---" -ForegroundColor Cyan
    $systemPolicy = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin
    Write-Host "ConsentPromptBehaviorAdmin: $($systemPolicy.ConsentPromptBehaviorAdmin)"
    $value = $systemPolicy.ConsentPromptBehaviorAdmin
    if ($value -eq 5) {
        Write-Host "Warning: UAC set to weakened level (5)" -ForegroundColor Yellow
        $global:Warnings += "UAC set to weakened level (5)"
    } elseif ($value -ne 2) {
        Write-Host "Note: Best practice is 2 (Always Notify)"
    }
} catch {
    Write-Error "Error querying UAC: $_"
}
Start-Sleep -Milliseconds 500

try {
    # Installed Software
    Write-Host "`n--- Installed Software ---" -ForegroundColor Cyan
    Get-WmiObject -Class Win32_Product | Select-Object Name, Version | Format-Table
    # Manual review for unapproved/outdated
    Write-Host "Review the list above for unapproved or outdated software."
} catch {
    Write-Error "Error getting installed software: $_"
}
Start-Sleep -Milliseconds 500

try {
    # Check for cleartext passwords
    Write-Host "`n--- Cleartext Sensitive Data Check ---" -ForegroundColor Cyan
    $path = "C:\Users\$env:USERNAME\Desktop"
    Write-Host "Searching path: $path"
    $findings = Get-ChildItem -Path $path -Recurse -Include *.txt,*.docx -ErrorAction SilentlyContinue | Select-String "password|credit card|ssn" -ErrorAction SilentlyContinue
    if ($findings) {
        $findings | Out-File -FilePath "cleartextpw.txt"
        Write-Host "Warning: Cleartext sensitive data found and saved to cleartextpw.txt" -ForegroundColor Yellow
        $global:Warnings += "Cleartext sensitive data found and saved to cleartextpw.txt"
    } else {
        Write-Host "No cleartext sensitive data found."
    }
} catch {
    Write-Error "Error checking for cleartext data: $_"
}
Start-Sleep -Milliseconds 500

try {
    # DEP Support Policy
    Write-Host "`n--- DEP Support Policy ---" -ForegroundColor Cyan
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $value = $osInfo.DataExecutionPrevention_SupportPolicy
    Write-Host "DataExecutionPrevention_SupportPolicy: $value"
    if ($value -eq 2) {
        Write-Host "Warning: DEP policy is set to default OptIn (2)" -ForegroundColor Yellow
        $global:Warnings += "DEP policy is set to default OptIn (2)"
    }
} catch {
    Write-Error "Error getting DEP policy: $_"
}
Start-Sleep -Milliseconds 500

try {
    # Check Kernel DMA Protection
    Write-Host "`n--- Kernel DMA Protection Status ---" -ForegroundColor Cyan
    $dmaProtection = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
    if ($dmaProtection.SecurityServicesRunning -contains 3) {
        Write-Host "DMA Protection: Enabled"
    } else {
        Write-Host "Warning: DMA Protection is not Enabled" -ForegroundColor Yellow
        $global:Warnings += "DMA Protection is not Enabled"
    }
} catch {
    Write-Host "Note: Unable to check Kernel DMA Protection status via Win32_DeviceGuard" -ForegroundColor Yellow
    $global:Warnings += "Unable to check Kernel DMA Protection status via Win32_DeviceGuard"
}
Start-Sleep -Milliseconds 500


try {
    # Process Mitigation - DEP and ASLR
    Write-Host "`n--- Process Mitigation (DEP and ASLR) ---" -ForegroundColor Cyan
    $mitigation = Get-ProcessMitigation -System
    Write-Host "DEP:"
    $mitigation.DEP | Format-List
    if ($mitigation.DEP.Enable -eq "OFF") {
        Write-Host "Warning: DEP Enable is False" -ForegroundColor Yellow
        $global:Warnings += "DEP Enable is False"
    }
    Write-Host "ASLR:"
    $mitigation.ASLR | Format-List
    if ($mitigation.ASLR.ForceRelocateImages -ne "ON") {
        Write-Host "Warning: ASLR ForceRelocateImages is not True" -ForegroundColor Yellow
        $global:Warnings += "ASLR ForceRelocateImages is not True"
    }
    if ($mitigation.ASLR.BottomUp -eq "OFF") {
        Write-Host "Warning: ASLR BottomUp is False" -ForegroundColor Yellow
        $global:Warnings += "ASLR BottomUp is False"
    }
    if ($mitigation.ASLR.HighEntropy -eq "OFF") {
        Write-Host "Warning: ASLR HighEntropy is False" -ForegroundColor Yellow
        $global:Warnings += "ASLR HighEntropy is False"
    }
} catch {
    Write-Error "Error getting process mitigation: $_"
}
Start-Sleep -Milliseconds 500


try {
    # Check Kernel-mode Hardware-enforced Stack Protection
    Write-Host "`n--- Kernel-mode Hardware-enforced Stack Protection Status ---" -ForegroundColor Cyan
    $ksKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks'
    $ksStatus = Get-ItemProperty -Path $ksKey -ErrorAction Stop
    
    # Print KernelShadowStacks status
    Write-Host "KernelShadowStacks Enabled: $($ksStatus.Enabled)"
    
    # Check if Enabled is set to 1 (enabled)
    if ($ksStatus -and $ksStatus.Enabled -eq 1) {
        Write-Host "Kernel-mode Hardware-enforced Stack Protection: Enabled"
    } elseif ($ksStatus -and $ksStatus.Enabled -eq 0) {
        Write-Host "Warning: Kernel-mode Hardware-enforced Stack Protection is disabled" -ForegroundColor Yellow
        $global:Warnings += "Kernel-mode Hardware-enforced Stack Protection is disabled"
    } else {
        Write-Host "Warning: KernelShadowStacks is not set or has an unexpected value (current value: $($ksStatus.Enabled))" -ForegroundColor Yellow
        $global:Warnings += "KernelShadowStacks is not set or has an unexpected value"
    }
    
    # Note on best practices
    Write-Host "Note: For best security practices, KernelShadowStacks should be set to 1 to enable hardware-enforced stack protection." -ForegroundColor Yellow
} catch {
    Write-Error "Error checking Kernel-mode Hardware-enforced Stack Protection status: $_"
}
Start-Sleep -Milliseconds 500


Write-Host "`nAudit Complete." -ForegroundColor Green

# Print Audit Summary
Write-Host "`nAudit Summary" -ForegroundColor Cyan
Write-Host "---------"
if ($global:Warnings.Count -eq 0) {
    Write-Host "No warnings found during the audit."
} else {
    foreach ($warning in $global:Warnings) {
        Write-Host "- $warning"
    }
}
Write-Host ""
