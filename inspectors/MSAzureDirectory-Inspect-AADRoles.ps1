# This is an AADRoles Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks if the AAD Roles contain users
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-AADRoles($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFAZAD0009"
		FindingName	     = "Users Found in Azure AD Roles"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "0.0"
		Description	     = "Privileged roles and users that have administrative rights in Microsoft 365 should be reviewed periodically to ensure best practice and validation of the assigned permissions."
		Remediation	     = "Ensure that there are separate accounts for daily user activities and Azure administration. Remove unneeded administrative users to reduce the risk of successful account compromise attempts. Privileged Identity Management (PIM) in Azure can be used to further reduce risk associated with administrative accounts and privileged roles. NOTE - Not all directory roles will be returned by the query. Directory roles must be enabled, either directly or by user assignment, to be returned in the query. Once a role is enabled it will continue to be returned by this query, even if the user(s) are removed from the role."
		PowerShellScript = ''
		DefaultValue	 = "-"
		ExpectedValue    = "-"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		References	     = @(@{ 'Name' = 'What is Azure AD Privileged Identity Management?'; 'URL' = "https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure" })
	}
}

Function Inspect-AADRoles
{
	Try
	{
		
		$path = New-Item -ItemType Directory -Force -Path "$($path)\AzureAD-Roles"
		$roles = Get-MgDirectoryRole
		$messages = @()
		foreach ($role in $roles)
		{
			$members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
			$roleMembers = @()
			Foreach ($member in $members)
			{
				$roleMembers += Get-MgUser -UserId $member.Id | Select-Object CompanyName, Department, DisplayName, JobTitle, Mail -ErrorAction SilentlyContinue
			}
			$roleMembers | Export-CSV "$($path)\$($role.DisplayName)_AzureDirectoryRoleMembers.csv" -Force -NoTypeInformation
			$message = Write-Output "$($role.DisplayName) - $(@($roleMembers).count) members found"
			$messages += $message
			Get-ChildItem $path | Where-Object { ($_.Length -eq 0) -and ($_.Name -like "$($role.DisplayName)*.csv") } | Remove-Item
		}
		if ($messages.Count -ne 0)
		{
			$endobject = Build-AADRoles($messages)
			Return $endobject
		}
		else
		{
			Return $null
		}
		
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
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname
		Write-Verbose "Errors written to log"
	}
	
}

Return Inspect-AADRoles


