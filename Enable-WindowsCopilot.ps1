#Requires -RunAsAdministrator

<#
.SYNOPSIS
A PowerShell script that modifies the `IntegratedServicesRegionPolicySet.json` file to unblock the Windows Copilot feature for a specific region. The script also updates certain registry keys to enable the Copilot feature and launches it.

.DESCRIPTION
This script is designed to enable the Windows Copilot feature for a specific region. It does this by removing the specified region from the list of disabled regions in the `IntegratedServicesRegionPolicySet.json` file located in the `C:\Windows\System32` directory and updating a set of registry keys

The script
  1. Checks if it's running with administrator privileges, which are required to modify the JSON file and update the registry keys. If not, it throws an error and stops execution.
  2. Reads the JSON file and converts it to a PowerShell object. It then iterates over the policies in the object, and if a policy is related to Copilot and the specified region is in the list of disabled regions, it removes the region from the list.
  3. If any changes were made to the JSON file, it checks the file's access control list (ACL) to ensure it has write permissions. If not, it updates the ACL to grant full control to the Administrators group. It then proceeds to write the updated JSON object back to the file.
  4. It then terminates all processes of Microsoft Edge, which will also 'crash' New Teams and New Outlook applications that use MsEdgeWebView2, however it is expected that they auto-restart.
  5. Finally, the script updates certain registry keys to enable the Copilot feature and launches it.

Copyright (c) 2024 Robbert Berghuis | https://www.linkedin.com/in/robbertberghuis

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The use of the third-party software links on this website is done at your own discretion and risk and with agreement that you will be solely responsible for any damage to your computer system or loss of data that results from such activities. You are solely responsible for adequate protection and backup of the data and equipment used in connection with any of the software linked to this website, and we will not be liable for any damages that you may suffer connection with downloading, installing, using, modifying or distributing such software. No advice or information, whether oral or written, obtained by you from us or from this website shall create any warranty for the software.

.INPUTS
None

.OUTPUTS
None

.PARAMETER UnlockCountry
The ISO 3166-2 alpha-2 code representation of the country to unlock, defaults to NL
Script does not validate if the input is an official ISO 3166-2 alpha-2 code but confirms if the input consists of 2 alphabetical characters

.NOTES
Copyright (c) 2024 Robbert Berghuis | https://www.linkedin.com/in/robbertberghuis

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The use of the third-party software links on this website is done at your own discretion and risk and with agreement that you will be solely responsible for any damage to your computer system or loss of data that results from such activities. You are solely responsible for adequate protection and backup of the data and equipment used in connection with any of the software linked to this website, and we will not be liable for any damages that you may suffer connection with downloading, installing, using, modifying or distributing such software. No advice or information, whether oral or written, obtained by you from us or from this website shall create any warranty for the software.

.EXAMPLE
# To use this script, you need to run it with administrator privileges.
# You can do this by right-clicking on the PowerShell icon and selecting "Run as administrator".

# Then navigate to the script's location, below example would navigate to the Downloads folder
Set-Location (Join-Path -Path $HOME -Child "Downloads")

# It might also be required to bypass the execution policy preventing the run of any unsigned / untrusted script.
# The following cmdlet can service this for the current process (only)
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process

# The code is provided as-is under the MIT license as per Notes and Description.
# Always read and understand the code before executing it

# When read, understood and confirmed. Run the script as below to unlock Copilot for Windows for NL
.\Enable-WindowsCopilot.ps1 -UnlockCountry NL

.LINK
https://www.linkedin.com/in/robbertberghuis
https://github.com/rberghuis/WindowsCopilot
https://opensource.org/license/mit

#>

[CmdletBinding()]
Param (
    # Not the most acurate check, but should suffice to capture input that (in theory) matches with the ISO-codes found at https://en.wikipedia.org/wiki/ISO_3166-2
    [ValidateScript({ $_ -match "[a-zA-Z]{2}" })]
    [ValidateNotNullOrEmpty()]
    [string]$UnlockCountry = 'NL' # Update this value to remove the applicable country-level restriction
)

$ErrorActionPreference = 'Stop'

# Confirm if run as Admin, required to update the JSON-file in C:\Windows\System32 and writing HKLM registry keys
If ($False -eq (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Throw "You need to run this PowerShell script from an elevated prompt (run as admin)"
    Break
}

#region Unblock Windows Copilot for this specific 'Country'
# Specify the path to the JSON file
$jsonFile = "C:\Windows\System32\IntegratedServicesRegionPolicySet.json"

# Check if the path exists
If (-Not (Test-Path -Path $jsonFile)) {
    Throw "The file '$($jsonFile)' does not exist"
    Break
}

# Read content and convert to JSON, it is UTF8 encoded
Try {
    $ISRPS = Get-Content -Path $jsonFile -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
} Catch {
    Throw "Failed to read the JSON file '$($jsonFile)'"
    Break
}

# Tracking var to indicate if 'something has changed'
$SomethingHasChanged = $false

# For all policies, focus on (any of) the settings concerning Copilot 
$ISRPS.Policies | Where-Object { $_.'$comment' -like '*Copilot*' } | ForEach-Object {
    # If the Region is listed
    If ($_.Conditions.Region.Disabled -contains $UnlockCountry) {
        # Remove the region from the list
        $_.Conditions.Region.Disabled = $_.Conditions.Region.Disabled | Where-Object { $_ -ne $UnlockCountry }

        # Mark variable to ensure we also write the new output to the JSON file
        $SomethingHasChanged = $true
    }
}

# Only if 'something has changed', we will write new output to the existing JSON file
If ($SomethingHasChanged) {
    # First check the ACL to confirm we can write to the file, in my test Administrators only had 'ReadAndExecute', file owned by 'NT Service\TrustedInstaller'
    $ACL = Get-ACL -Path $jsonFile

    # Read the access for the local Administrators group
    $AdminAccess = $ACL.Access | Where-Object { $_.IdentityReference -eq 'BUILTIN\Administrators' }

    # Check if either FullControl is not provided, or not 'Allow'-ed, if either isn't true, then update the ACL
    If ($AdminAccess.FileSystemRights -ne 'FullControl' -or $AdminAccess.AccessControlType -ne 'Allow') {
        # Create a new ACL Rule, that Allow FullControl for the local Administrators (group)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule( `
            (New-Object System.Security.Principal.NTAccount('BUILTIN\Administrators')), `
            [System.Security.AccessControl.FileSystemRights]"FullControl", `
            [System.Security.AccessControl.AccessControlType]::Allow `
        )

        # Add the new ACL Rule
        $ACL.AddAccessRule($rule)

        # Commit the change of ACL on the file
        Try {
            Set-Acl -Path $jsonFile -AclObject $ACL -ErrorAction Stop
        } Catch {
            Throw "Failed to update the ACL on the JSON file '$($jsonFile)' to grant FullControl to the local Administrators group"
            Break
        }
    }

    # Write the new output replacing the old/existing content
    Try {
        $ISRPS | ConvertTo-Json -Depth 5 | ForEach-Object { [System.Text.RegularExpressions.Regex]::Unescape($_) } | Set-Content -Path $jsonFile -ErrorAction Stop
    } Catch {
        Throw "Failed to write the new JSON content to the file '$($jsonFile)'"
        Break
    }
}
#endregion

# Terminate all processes of MSEdge, this will also terminate New Teams and New Outlook apps using MsEdgeWebView2 but they should auto-restart
Get-Process 'msedge*' | Stop-Process -Confirm:$true

#region Set local settings and override policies
@(
    # Current User settings & policies
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings'; Key = 'AutoOpenCopilotLargeScreens'; Value = '1'; Type = 'Dword' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\WindowsCopilot';  Key = 'AllowCopilotRuntime'; Value = 1; Type = 'Dword' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\Shell\Copilot'; Key = 'CopilotDisabledReason'; Value = ''; Type = 'String' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\Shell\Copilot'; Key = 'IsCopilotAvailable'; Value = 1; Type = 'DWord' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\Shell\Copilot\BingChat'; Key = 'IsUserEligible'; Value = 1; Type = 'DWord' }
    @{ Path = 'HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot'; Key = 'TurnOffWindowsCopilot'; Value = 0; Type = 'DWord' }
    @{ Path = 'HKCU:\Software\Policies\Microsoft\Edge'; Key = 'DiscoverPageContextEnabled'; Value = 1; Type = 'DWord' }
    # Local Machine settings & policies
    @{ Path = 'HKLM:\Software\Policies\Microsoft\Edge'; Key = 'DiscoverPageContextEnabled'; Value = 1; Type = 'DWord' }
    @{ Path = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsCopilot'; Key = 'TurnOffWindowsCopilot'; Value = 0; Type = 'DWord' }
    @{ Path = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsCopilot'; Key = 'DisableAIDataAnalysis'; Value = 0; Type = 'DWord' } # Windows Recall
    # Hide and Show the Copilot button on the Taskbar
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Key = 'ShowCopilotButton'; Value = 0; Type = 'DWord' }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Key = 'ShowCopilotButton'; Value = 1; Type = 'DWord' }
) | Foreach-Object {
    # Check if the Value is as expected
    If ($_.Value -ne (Get-ItemProperty -Path $_.Path -ErrorAction SilentlyContinue)."$($_.Key)") {
        # Write the new value, this also creates registry keys when not set
        Try {
            Set-ItemProperty -Path $_.Path -Name $_.Key -Value $_.Value -Type $_.Type -Confirm:$false -Verbose -ErrorAction Stop
        } Catch [System.Management.Automation.ItemNotFoundException] {
            # Under the assumption everything is allowed/enabled by default, this is a non-terminating error that also has little value. Verbosing for visbility
            Write-Verbose "Cannot update the registry key as (part of) the path does not exists '$($input.Path)\$($input.Key)'." -Verbose
        } Catch {
            # Non-terminating error
            Write-Error "Failed to update the registry key '$($input.Path)\$($input.Key)' with value '$($input.Value)'. Windows Copilot might not function correctly..." -ErrorAction Continue
        }
    }
}
#endregion

#region Disable the 'ShowCopilotButton' and Enable it (again) to ensure the Taskbar is updated no longer works as Microsoft moved the Copilot button to the system tray.
If (($Host.UI.PromptForChoice("Restart Windows (File) Explorer, closing all existing windows?", "In order to properly effectuate the Copilot for Windows changes on your taskbar, it is recommended to restart the Windows Explorer. This will close all open windows. Do you want to continue?", @('&Yes', '&No'), 0)) -eq 0) {
    # Restarting File Explorer will ensure the Taskbar is updated but also 'crash' any open File Explorer windows - user choose to restart
    Try {
        Stop-Process -Name explorer -Force -ErrorAction Stop
        Start-Process explorer -ErrorAction Stop
    } Catch {
        # Non-terminating error. user problem from here on onwards
        Write-Error "Failed to restart the Windows Explorer process, the Taskbar might not be updated correctly..." -ErrorAction Continue
    }
}
#endregion

#region Launch Windows Copilot using a method to avoid launching it in elevated-mode (as we're running elevated PowerShell)
# Seems to be non-sense, but running Windows Copilot through Edge in elevated mode will prevent normal end-user tasks for which Edge is used in a 'non-elevated'-mode
Try {
    # Define a temp path to store a shortcurt
    $FilePath = Join-Path -Path $env:TEMP -ChildPath "$(Get-Date -Format FileDateTime)WindowsCopilot.lnk" -ErrorAction Stop

    # Create a new Shortcut
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($FilePath)
    $shortcut.TargetPath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    $Shortcut.Arguments = '--single-argument microsoft-edge:///?ux=copilot&tcp=1&source=taskbar'
    $shortcut.WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application"
    $Shortcut.Save()

    # Run the shortcut using a 'loophole' through explorer.exe - this ensures the process is launched without elevated privileges
    $newProc = New-Object System.Diagnostics.ProcessStartInfo "PowerShell"
    $newProc.Arguments = "explorer.exe $FilePath"
    $ProcStart = [System.Diagnostics.Process]::Start($newProc)

    # Wait for the process to finish
    While ($ProcStart.HasExited -eq $false -or (New-TimeSpan -Start $procStart.ExitTime -End (Get-Date)).Seconds -le 1) {
        Start-Sleep -Seconds 1
    }
} Catch {
    # Non-terminating error
    Write-Error "Failed to launch Windows Copilot, please try to launching it manually from the Taskbar" -ErrorAction Continue
} Finally {
    If ($FilePath) {
        # Remove the temp-file as we no longer need it
        Remove-Item -Path $FilePath -Confirm:$false -ErrorAction SilentlyContinue
    }
}
#endregion

# Exit
return
