# This is an DirSyncAdmins Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks if Directory Synced Users in Admin Roles are existing
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-DirSyncAdmins($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFAZAD0011"
		FindingName	     = "Directory Synced Users Found in Admin Roles"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "9.8"
		Description	     = "Account synchronization can be used to modify privileged users (including their credentials) or groups that have administrative privileges in Microsoft 365. Changes to, or compromise of directory-synced accounts can affect the integrity of the cloud environment."
		Remediation	     = "Follow Microsoft guidance and restrict all administrative privileges to Azure-only accounts using strong authentication methods, and if possible, only allow those accounts to be accessed from Azure-based workstations."
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Protecting Microsoft 365 from on-premises attacks'; 'URL' = "https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/protect-m365-from-on-premises-attacks" })
	}
}

Function Inspect-DirSyncAdmins
{
	Try
	{
		
		$path = New-Item -ItemType Directory -Force -Path "$($path)\DirSync"
		
		$adminRoles = Get-MgDirectoryRole | Where-Object { $_.DisplayName -like "*Administrator" }
		
		$allDirsyncAdmins = @()
		
		ForEach ($role in $adminRoles)
		{
			$roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
			
			Foreach ($user in $roleMembers)
			{
				$member = Get-AzureADObjectByObjectId -ObjectIds $user.Id
				If ($member.OnPremisesSyncEnabled -eq $true)
				{
					$dirsyncAdmins += "$role : $($member.UserPrincipalName)`n"
				}
			}
			
			If ($dirsyncAdmins.count -ne 0)
			{
				$dirsyncAdmins | Out-File "$path\$($role.DisplayName).txt"
				$allDirsyncAdmins += $dirsyncAdmins
			}
		}
		
		If ($allDirsyncAdmins.count -ne 0)
		{
			$endobject = Build-DirSyncAdmins($allDirsyncAdmins)
			Return $endobject
		}
		
		Return $null
		
	}
	Catch
	{
		Write-Warning "Error message: $_"
		$message = $_.ToString()
		$exception = $_.Exception
		$strace = $_.ScriptStackTrace
		$failingline = $_.InvocationInfo.Line
		$positionmsg = $_.InvocationInfo.PositionMessage
		$pscommandpath = $_.InvocationInfo.PSCommandPath
		$failinglinenumber = $_.InvocationInfo.ScriptLineNumber
		$scriptname = $_.InvocationInfo.ScriptName
		Write-Verbose "Write to log"
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname -failinglinenumber $failinglinenumber -failingline $failingline -pscommandpath $pscommandpath -positionmsg $pscommandpath -stacktrace $strace
		Write-Verbose "Errors written to log"
	}
	
}

Return Inspect-DirSyncAdmins


