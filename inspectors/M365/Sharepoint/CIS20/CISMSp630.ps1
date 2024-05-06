# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v2.0.0
# Product Family: Microsoft Sharepoint
# Purpose: Ensure expiration time for external sharing links is set
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMSp630($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp630"
		FindingName	     = "CIS MSp 6.3 - Ensure expiration time for external sharing links is not set"
		ProductFamily    = "Microsoft SharePoint"
		RiskScore	     = "15"
		Description	     = "An attacker can compromise a user account for a short period of time, send anonymous sharing links to an external account, then take their time accessing the data. They can also compromise external accounts and steal the anonymous sharing links sent to those external entities well after the data has been shared. Restricting how long the links are valid can reduce the window of opportunity for attackers"
		Remediation	     = "Use the PowerShell Script to remediate the issue"
		PowerShellScript = 'Set-SPOTenant -RequireAnonymousLinksExpireInDays 30'
		DefaultValue	 = "-1"
		ExpectedValue    = "Value between 1 and 30 days"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Set Anonymous Link Expiration Settings for SharePoint Online and OneDrive for Business'; 'URL' = 'https://www.sharepointdiary.com/2017/09/set-anonymous-link-expiration-in-sharepoint-online.html' })
	}
}


function Audit-CISMSp630
{
	Try
	{
		$SharePointTenantSetting = (Get-SPOTenant).SharingCapability
		If ($SharePointTenantSetting -eq "ExternalUserAndGuestSharing")
		{
			$Days = (Get-SPOTenant).RequireAnonymousLinksExpireInDays
			If ($NumberOfDays -eq -1 -or $NumberOfDays -igt 30)
			{
				$endobject = Build-CISMSp630("RequireAnonymousLinksExpireInDays: $($Days)")
				return $endobject
			}
			Else
			{
				return $null
			}
		}
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Audit-CISMSp630


