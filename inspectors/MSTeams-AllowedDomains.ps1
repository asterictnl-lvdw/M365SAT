# This is an MSTeamsAllowedDomains Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Teams
# Purpose: Checks if 
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-MSTeamsAllowedDomains($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMST0001"
		FindingName	     = "Microsoft Teams External Domain Communication Policies"
		ProductFamily    = "Microsoft Teams"
		CVS			     = "6.5"
		Description	     = "Microsoft Teams can communicate with external domains. This could lead to data exfiltration as external domains could include personal accounts. Please review this policy and ensure no malicious domains have access to join the Teams tenant."
		Remediation	     = "Review Microsoft Teams External Access Policies and validate that all results are expected, and no conflicting rules are in place."
		DefaultValue	 = "All Domains Allowed"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "Medium"
		RiskRating	     = "Medium"
		PowerShellScript = ''
		References	     = @(@{ 'Name' = 'Manage external access (federation) - Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoftteams/manage-external-access' },
			@{ 'Name' = 'Use guest and external access to collaborate with people outside your organization'; 'URL' = 'https://docs.microsoft.com/en-us/microsoftteams/communicate-with-users-from-other-organizations' })
	}
}


Function Inspect-MSTeamsAllowedDomains
{
	Try
	{
		
		Try
		{
			$configuration = Get-CsTenantFederationConfiguration
			$domains = @()
			
			If (($configuration.AllowedDomains -like "*AllowAllKnownDomains*") -and ($configuration.AllowFederatedUsers -eq $true))
			{
				$domains += "All Domains Allowed"
			}
			
			If (($configuration.AllowedDomains -like "*AllowAllKnownDomains*") -and ($configuration.AllowFederatedUsers -eq $false))
			{
				$domains += "All External Domains Blocked"
			}
			
			If ($configuration.AllowedDomains -Like "Domain=*")
			{
				$domains += "Allowed domains: $($configuration.AllowedDomains)"
			}
			
			If ($configuration.BlockedDomains)
			{
				$domains += "Blocked domains: $($configuration.BlockedDomains)"
			}
			If ($domains.Count -ne 0)
			{
				$endobject = Build-MSTeamsAllowedDomains($permissions.AllowedToCreateApps)
				Return $endobject
			}
			else
			{
				Return $null
			}
		}
		Catch
		{
			Write-Warning -Message "Error processing request. Manual verification required."
			Return "Error processing request."
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
return Inspect-MSTeamsAllowedDomains


