# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that 'Require Multi-Factor Authentication to register or join devices with Azure AD' is set to 'Yes'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz1210($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz1210"
		FindingName	     = "CIS Az 1.21 - Require Multi-Factor Authentication to register or join devices with Azure AD is set to No (0)"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "15"
		Description	     = "Multi-factor authentication is recommended when adding devices to Microsoft Entra ID. When set to Yes, users who are adding devices from the internet must first use the second method of authentication before their device is successfully added to the directory. This ensures that rogue devices are not added to the domain using a compromised user account. Note: Some Microsoft documentation suggests to use conditional access policies for joining a domain from certain whitelisted networks or devices. Even with these in place, using Multi-Factor Authentication is still recommended, as it creates a process for review before joining the domain."
		Remediation	     = "Manually change the setting in the Azure Portal by navigating to the link written in PowerShellScript"
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings/menuId~/null'
		DefaultValue	 = "0"
		ExpectedValue    = "1"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Azure MFA for Enrollment in Intune and Azure AD Device registration explained'; 'URL' = 'https://learn.microsoft.com/en-us/archive/blogs/janketil/azure-mfa-for-enrollment-in-intune-and-azure-ad-device-registration-explained' },
			@{ 'Name' = 'IM-6: Use strong authentication controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-6-use-strong-authentication-controls' })
	}
	return $inspectorobject
}

function Audit-CISAz1210
{
	try
	{
		$AffectedObject = @()
		# Actual Script
		$DeviceRegistrationPolicy = (Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy")
		
		# Validation
		if ($DeviceRegistrationPolicy.multiFactorAuthConfiguration -eq 0)
		{
			$finalobject = Build-CISAz1210("multiFactorAuthConfiguration: $($BetaSettingsObject.multiFactorAuthConfiguration)")
			return $finalobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISAz1210