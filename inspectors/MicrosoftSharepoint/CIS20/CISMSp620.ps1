# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v2.0.0
# Product Family: Microsoft Sharepoint
# Purpose: Block OneDrive for Business sync from unmanaged devices
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMSp620($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp620"
		FindingName	     = "CIS MSp 6.2 - OneDrive for Business sync from unmanaged devices is not blocked"
		ProductFamily    = "Microsoft SharePoint"
		CVS			     = "8.2"
		Description	     = "Unmanaged devices pose a risk, since their security cannot be verified through existing security policies, brokers or endpoint protection. Allowing users to sync data to these devices takes that data out of the control of the organization. This increases the risk of the data either being intentionally or accidentally leaked. Note: This setting is only applicable to Active Directory domains when operating in a hybrid configuration. It does not apply to Azure AD domains. If there are devices which are only Azure AD joined, consider using a Conditional Access Policy instead."
		Remediation	     = "Use the PowerShell Command to block sync from unmanaged devices"
		PowerShellScript = 'Set-SPOTenant -ConditionalAccessPolicy AllowLimitedAccess'
		DefaultValue	 = "ExternalUserAndGuestSharing (Anyone)"
		ExpectedValue    = "ExternalUserSharingOnly (New and Existing Guests)"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Restrict sharing of SharePoint and OneDrive content by domain'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/restricted-domains-sharing' })
	}
}


function Audit-CISMSp620
{
	Try
	{
		
		$ShareSettings = (Get-SPOTenant).ConditionalAccessPolicy
		If ($ShareSettings -ne "AllowLimitedAccess")
		{
			$message = "ConditionalAccessPolicy is set to $($ShareSettings)."
			$endobject = Build-CISMSp620($message)
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

return Audit-CISMSp620


