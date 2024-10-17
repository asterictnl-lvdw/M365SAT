# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.1.0
# Product Family: Microsoft Sharepoint
# Purpose: Block OneDrive for Business sync from unmanaged devices
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMSp732($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp732"
		FindingName	     = "CIS MSp 7.3.2 - OneDrive for Business sync from unmanaged devices is not blocked"
		ProductFamily    = "Microsoft SharePoint"
		RiskScore	     = "15"
		Description	     = "Unmanaged devices pose a risk, since their security cannot be verified through existing security policies, brokers or endpoint protection. Allowing users to sync data to these devices takes that data out of the control of the organization. This increases the risk of the data either being intentionally or accidentally leaked. Note: This setting is only applicable to Active Directory domains when operating in a hybrid configuration. It does not apply to Azure AD domains. If there are devices which are only Azure AD joined, consider using a Conditional Access Policy instead."
		Remediation	     = "Use the PowerShell Command to block sync from unmanaged devices"
		PowerShellScript = 'Set-SPOTenant -ConditionalAccessPolicy AllowLimitedAccess'
		DefaultValue	 = "ExternalUserAndGuestSharing (Anyone)"
		ExpectedValue    = "ExternalUserSharingOnly (New and Existing Guests)"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Restrict sharing of SharePoint and OneDrive content by domain'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/restricted-domains-sharing' },
		@{ 'Name' = 'Allow syncing only on computers joined to specific domains'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/allow-syncing-only-on-specific-domains' })
	}
}


function Audit-CISMSp732
{
	Try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			$ShareSettings = (Get-PnPTenant).ConditionalAccessPolicy
			If ($ShareSettings -ne "AllowLimitedAccess")
			{
				$message = "ConditionalAccessPolicy is set to $($ShareSettings)."
				$ShareSettings | Format-Table -AutoSize | Out-File "$path\CISMSp732-SPOTenant.txt"
				$endobject = Build-CISMSp732($message)
				return $endobject
			}
			return $null
		}
		else
		{
			$ShareSettings = (Get-SPOTenant).ConditionalAccessPolicy
			If ($ShareSettings -ne "AllowLimitedAccess")
			{
				$message = "ConditionalAccessPolicy is set to $($ShareSettings)."
				$ShareSettings | Format-Table -AutoSize | Out-File "$path\CISMSp732-SPOTenant.txt"
				$endobject = Build-CISMSp732($message)
				return $endobject
			}
			return $null
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Audit-CISMSp732


