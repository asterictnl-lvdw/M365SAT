# This is an BasicAuthCheckMobileDevice Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if BasicAuth for Mobile Devices is enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-BasicAuthCheckMobileDevice($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0010"
		FindingName	     = "Basic Authentication Possible on Mobile Devices"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "Basic Authentication on Mobile Devices is possible with Basic Authentication. This leaves mobile devices vulnerable to attacks from outside"
		Remediation	     = "Require modern authentication, even more mobile devices. Please consult the references and the PowerShellScript for configuration instructions"
		PowerShellScript = 'Set-ActiveSyncOrganizationSettings -DefaultAccessLevel Block;'
		DefaultValue	 = "More than 0 devices"
		ExpectedValue    = "0 Devices"
		ReturnedValue    = "$($findings.Count.ToString()) Devices"
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Account setup with modern authentication in Exchange Online'; 'URL' = 'https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/outlook-for-ios-and-android/setup-with-modern-authentication' }, @{ 'Name' = 'Securing Outlook for iOS and Android in Exchange Online'; 'URL' = 'https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/outlook-for-ios-and-android/secure-outlook-for-ios-and-android' })
	}
	return $inspectorobject
}

function Audit-BasicAuthCheckMobileDevice
{
	$BasicAuthCheckMobileDeviceResults = @()
	try
	{
		$BasicAuthCheckMobileDevice = Get-MobileDevice -ResultSize Unlimited | Where { $_.DeviceOS -eq "OutlookBasicAuth" } | Format-Table -Auto UserDisplayName, DeviceAccessState
		if ($BasicAuthCheckMobileDevice.Count -ne 0)
		{
			foreach ($MobileDevice in $BasicAuthCheckMobileDevice)
			{
				$BasicAuthCheckMobileDeviceResults += $MobileDevice.UserDisplayName
			}
			$finalobject = Build-AntiPhishPolicy($sendingInfrastructure)
			return $finalobject
		}
		else
		{
			return $null
		}
	}
	catch
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
return Audit-BasicAuthCheckMobileDevice