# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks if Basic Authentication is possible on Mobile Devices
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CSTM-Ex006($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex006"
		FindingName	     = "CSTM-Ex006 - Basic Authentication Possible on Mobile Devices"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "9"
		Description	     = "Basic Authentication on Mobile Devices is possible with Basic Authentication. This leaves mobile devices vulnerable to attacks from outside"
		Remediation	     = "Require modern authentication, even more mobile devices. Please consult the references and the PowerShellScript for configuration instructions"
		PowerShellScript = 'Set-ActiveSyncOrganizationSettings -DefaultAccessLevel Block;'
		DefaultValue	 = "More than 0 devices"
		ExpectedValue    = "0 Devices"
		ReturnedValue    = "$($findings) Devices"
		Impact		     = "3"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Account setup with modern authentication in Exchange Online'; 'URL' = 'https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/outlook-for-ios-and-android/setup-with-modern-authentication' }, @{ 'Name' = 'Securing Outlook for iOS and Android in Exchange Online'; 'URL' = 'https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/outlook-for-ios-and-android/secure-outlook-for-ios-and-android' })
	}
	return $inspectorobject
}

function Audit-CSTM-Ex006
{
	$BasicAuthCheckMobileDeviceResults = @()
	try
	{
		$BasicAuthCheckMobileDevice = Get-MobileDevice -ResultSize Unlimited | Where { $_.DeviceOS -eq "OutlookBasicAuth" } | Format-Table -Auto UserDisplayName, DeviceAccessState
		if ($BasicAuthCheckMobileDevice.Count -igt 0)
		{
			foreach ($MobileDevice in $BasicAuthCheckMobileDevice)
			{
				$BasicAuthCheckMobileDeviceResults += $MobileDevice.UserDisplayName
			}
			$finalobject = Build-CSTM-Ex006($sendingInfrastructure.Count)
			return $finalobject
		}
		else
		{
			return $null
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CSTM-Ex006