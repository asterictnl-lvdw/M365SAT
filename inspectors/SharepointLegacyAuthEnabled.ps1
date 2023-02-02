# This is an SharepointLegacyAuthEnabled Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft SharePoint
# Purpose: Checks which External Users can Reshare the same document
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-SharepointLegacyAuthEnabled($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMSP0006"
		FindingName	     = "SharePoint Legacy Authentication is Enabled"
		ProductFamily    = "Microsoft SharePoint"
		CVS			     = "9.1"
		Description	     = "SharePoint legacy authentication is enabled. Cyber adversaries frequently attempt credential stuffing and other attacks against legacy authentication protocols because they are subject to less scrutiny and are typically exempt from multi-factor authentication and other modern access requirements. It is recommended to globally disable SharePoint legacy authentication."
		Remediation	     = "Use the PowerShell Script to mitigate the issue and disable Legacy Authentication for SharePoint"
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		PowerShellScript = 'Set-SPOTenant -LegacyAuthProtocolsEnabled $False'
		References	     = @(@{ 'Name' = 'Set-SPOTenant Reference'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/sharepoint-online/set-spotenant?view=sharepoint-ps' },
			@{ 'Name' = 'How to: Block legacy authentication to Azure AD with conditional access'; 'URL' = 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication' },
			@{ 'Name' = 'Legacy Auth and the Risk'; 'URL' = 'https://contosoedu.com/legacy-auth-and-the-risk/' })
	}
}

function Inspect-SharepointLegacyAuthEnabled
{
	Try
	{
		
		If ($(Get-SPOTenant).LegacyAuthProtocolsEnabled)
		{
			$endobject = Build-SharepointLegacyAuthEnabled("Tenant LegacyAuthProtocolsEnabled configuration: $((Get-SPOTenant).LegacyAuthProtocolsEnabled)")
			return $endobject
		}
		return $null
		
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

return Inspect-SharepointLegacyAuthEnabled


