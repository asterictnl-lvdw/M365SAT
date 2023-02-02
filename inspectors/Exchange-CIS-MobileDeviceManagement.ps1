# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks CIS Bulletpoints: 7.2, 7.3, 7.4 , 7.5, 7.6, 7.7, 7.8, 7.9, 7.10
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-CISMobileDeviceAudit($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0015"
		FindingName	     = "The Mobile Device Audit Returned Incorrect Results based on the CIS Benchmark"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "This means that Mobile Device Audit Settings are not configured regarding the CIS Benchmark. This could lead to the following risks: Information Leaking, Information Disclosure, Data Exfiltration, Credential Theft, Weakend Security, Malware Installation}"
		Remediation	     = "Please change the affected Objects to the Values that are Expected! Set-MobileDebiceMailboxPolicy will help with this."
		PowerShellScript = 'Set-MobileDeviceMailboxPolicy -Identity Default -PasswordEnabled $true -AlphanumericPasswordRequired $true -PasswordRecoveryEnabled $true -AllowSimplePassword $false -MinPasswordLength 12 -MaxPasswordFailedAttempts 8 -PasswordHistory 5 -MinPasswordComplexCharacters 1 -MaxInactivityTimeLock 4 -DeviceEncryptionEnabled $true -Confirm $true'
		DefaultValue	 = "AlphanumericPasswordRequired: False <br /> PasswordEnabled: False <br /> PasswordRecoveryEnabled: False <br /> AllowSimplePassword: True <br /> MinPasswordLength: NULL <br /> MaxPasswordFailedAttempts: Unlimited <br /> PasswordExpiration: Unlimited <br /> PasswordHistory: 0 <br /> MinPasswordComplexCharacters: 1 <br /> MaxInactivityTimeLock: Unlimited <br /> DeviceEncryptionEnabled: False"
		ExpectedValue    = "AlphanumericPasswordRequired: True <br /> PasswordEnabled: True <br /> PasswordRecoveryEnabled: True <br /> AllowSimplePassword: False <br /> MinPasswordLength: >5 <br /> MaxPasswordFailedAttempts: <10 <br /> PasswordExpiration: Unlimited <br /> PasswordHistory: >4 <br /> MinPasswordComplexCharacters: 1 <br /> MaxInactivityTimeLock: <5 <br /> DeviceEncryptionEnabled: True"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = '2.2, 2.3, 3.6, 4.3, 4.4, 5, 5.1, 5.2, 6.2, 7, 7.1, 8.1, 8.2, 9.1, 9.4, 10.6, 13.6, 16, 16.6, 16.7, 16.11, 18.3, 18.4'; 'URL' = 'CIS_Microsoft_365_Foundations_Benchmark_v1.4.0.pdf' })
	}
	return $inspectorobject
}

function Audit-CISMobileDeviceAudit
{
	try
	{
		$CISMobileDeviceAuditData = @()
		$CISMobileDevice = Get-MobileDeviceMailboxPolicy | select AlphanumericPasswordRequired, PasswordEnabled, PasswordRecoveryEnabled, AllowSimplePassword, MinPasswordLength, MaxPasswordFailedAttempts, PasswordExpiration, PasswordHistory, MinPasswordComplexCharacters, MaxInactivityTimeLock, DeviceEncryptionEnabled
		if ($CISMobileDevice -ne $null)
		{
			if ($CISMobileDevice.AlphanumericPasswordRequired -match 'False')
			{
				$CISMobileDeviceAuditData += "AlphanumericPasswordRequired: " + $CISMobileDevice.AlphanumericPasswordRequired
			}
			if ($CISMobileDevice.PasswordEnabled -match 'False')
			{
				$CISMobileDeviceAuditData += "`n PasswordEnabled: " + $CISMobileDevice.PasswordEnabled
			}
			if ($CISMobileDevice.PasswordRecoveryEnabled -match 'False')
			{
				$CISMobileDeviceAuditData += "`n PasswordRecoveryEnabled: " + $CISMobileDevice.PasswordRecoveryEnabled
			}
			if ($CISMobileDevice.AllowSimplePassword -match 'True')
			{
				$CISMobileDeviceAuditData += "`n AllowSimplePassword: " + $CISMobileDevice.AllowSimplePassword
			}
			if ($CISMobileDevice.MinPasswordLength -ile 5 -or $null)
			{
				$CISMobileDeviceAuditData += "`n MinPasswordLength: " + $CISMobileDevice.MinPasswordLength
			}
			if (!$CISMobileDevice.MaxPasswordFailedAttempts -ilt 10)
			{
				$CISMobileDeviceAuditData += "`n MaxPasswordFailedAttempts: " + $CISMobileDevice.MaxPasswordFailedAttempts
			}
			if (!$CISMobileDevice.PasswordExpiration -eq 'Unlimited')
			{
				$CISMobileDeviceAuditData += "`n PasswordExpiration: " + $CISMobileDevice.PasswordExpiration
			}
			if ($CISMobileDevice.PasswordHistory -ile 4)
			{
				$CISMobileDeviceAuditData += "`n PasswordHistory: " + $CISMobileDevice.PasswordHistory
			}
			if (!$CISMobileDevice.MinPasswordComplexCharacters -eq 1)
			{
				$CISMobileDeviceAuditData += "`n MinPasswordComplexCharacters: " + $CISMobileDevice.MinPasswordComplexCharacters
			}
			if (!$CISMobileDevice.MaxInactivityTimeLock -ile 5)
			{
				$CISMobileDeviceAuditData += "`n MaxInactivityTimeLock: " + $CISMobileDevice.MaxInactivityTimeLock
			}
			if ($CISMobileDevice.DeviceEncryptionEnabled -match 'False')
			{
				$CISMobileDeviceAuditData += "`n DeviceEncryptionEnabled: " + $CISMobileDevice.DeviceEncryptionEnabled
			}
			$endobject = Build-CISMobileDeviceAudit($CISMobileDeviceAuditData)
			return $endobject
		}
		return $null
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
return Audit-CISMobileDeviceAudit