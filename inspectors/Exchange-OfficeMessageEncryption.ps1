# This is an OfficeMessageEncryption Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if Exchange has Message Encryption internally, externally and AzureRMS enabled as extra protection functions
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-OfficeMessageEncryption($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0052"
		FindingName	     = "Office Message Encryption is Not Enabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "8.6"
		Description	     = "Messages the organization sends using Exchange email may contain confidential information such as employee names, internal IT or security information, and other data vital to the organization's continued operations. If a suitably positioned adversary were to intercept or otherwise obtain the organization's email messages, they may be able to read this sensitive information as O365 emails are not cryptographically secured by default. O365 Message Encryption provides the ability to encrypt email sent through the organization's O365 instance and share encrypted email with any user that is emailed."
		Remediation	     = "Enabling Office Message Encryption can be a significant process that entails enabling the technology, determining which cryptographic key management strategy will be used, and enabling Exchange mail transport rules that will automatically encrypt the organization's email. For many organizations, this process can be simplified by using Microsoft's default cryptographic key management scheme; however, this is a decision that can only be made by someone with contextual knowledge of the organization's constraints. Please follow the detailed guide linked in the References section for more information."
		PowerShellScript = '$RMSConfig = Get-AipServiceConfiguration; $LicenseUri = $RMSConfig.LicensingIntranetDistributionPointUrl; Set-IRMConfiguration -LicensingLocation $LicenseUri; Set-IRMConfiguration -InternalLicensingEnabled $true -ExternalLicensingEnabled $true -AzureRMSLicensingEnabled $true'
		DefaultValue	 = "None"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Set up new Message Encryption capabilities'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/set-up-new-message-encryption-capabilities?view=o365-worldwide" })
	}
	return $inspectorobject
}


function Inspect-OfficeMessageEncryption
{
	Try
	{
		$EnabledSolutions = @()
		
		If (-NOT (Get-IRMConfiguration).InternalLicensingEnabled)
		{
			$EnabledSolutions += "InternalLicensingEnabled: "+ (Get-IRMConfiguration).InternalLicensingEnabled
		}
		If (-NOT (Get-IRMConfiguration).ExternalLicensingEnabled)
		{
			$EnabledSolutions += "InternalLicensingEnabled: " + (Get-IRMConfiguration).ExternalLicensingEnabled
		}
		If (-NOT (Get-IRMConfiguration).AzureRMSLicensingEnabled)
		{
			$EnabledSolutions += "InternalLicensingEnabled: " + (Get-IRMConfiguration).AzureRMSLicensingEnabled
		}
		If ($EnabledSolutions.Count -ne 0)
		{
			$endobject = Build-OfficeMessageEncryption($EnabledSolutions)
			Return $endobject
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

return Inspect-OfficeMessageEncryption


