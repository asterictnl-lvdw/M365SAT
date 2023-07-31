# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v2.0.0
# Product Family: Microsoft Sharepoint
# Purpose: Ensure SharePoint external sharing is managed through domain whitelist/blacklists
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMSp610($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp610"
		FindingName	     = "CIS MSp 6.1 - SharePoint external sharing is not managed through domain whitelist/blacklists"
		ProductFamily    = "Microsoft SharePoint"
		CVS			     = "8.2"
		Description	     = "Attackers will often attempt to expose sensitive information to external entities through sharing, and restricting the domains that users can share documents with will reduce that surface area."
		Remediation	     = "Use the PowerShell Command to enable external sharing through a whitelist/blacklist"
		PowerShellScript = 'Set-SPOTenant -SharingDomainRestrictionMode AllowList -SharingAllowedDomainList "domain1.com domain2.com"'
		DefaultValue	 = "ExternalUserAndGuestSharing (Anyone)"
		ExpectedValue    = "ExternalUserSharingOnly (New and Existing Guests)"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Restrict sharing of SharePoint and OneDrive content by domain'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/restricted-domains-sharing' })
	}
}


function Audit-CISMSp610
{
	Try
	{
		
		$ShareSettings = (Get-SPOTenant).SharingDomainRestrictionMode
		If ($ShareSettings -ne "AllowList")
		{
			$message = "SharingDomainRestrictionMode is set to $($ShareSettings)."
			$endobject = Build-CISMSp610($message)
			return $endobject
		}
		
		return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Audit-CISMSp610


