# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Office Message Encryption check
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex028($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex028"
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


function Inspect-CSTM-Ex028
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
			$EnabledSolutions += "ExternalLicensingEnabled: " + (Get-IRMConfiguration).ExternalLicensingEnabled
		}
		If (-NOT (Get-IRMConfiguration).AzureRMSLicensingEnabled)
		{
			$EnabledSolutions += "AzureRMSLicensingEnabled: " + (Get-IRMConfiguration).AzureRMSLicensingEnabled
		}
		If ($EnabledSolutions.Count -ne 0)
		{
			$endobject = Build-CSTM-Ex028($EnabledSolutions)
			Return $endobject
		}

		
		return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CSTM-Ex028


