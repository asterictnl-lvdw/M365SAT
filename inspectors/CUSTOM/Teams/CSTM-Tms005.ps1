# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Teams
# Purpose: Ensure External Domain Communication Policies are existing
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Tms005($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Tms005"
		FindingName	     = "CSTM-Tms005 - Microsoft Teams Enhanced Encryption Not Enabled!"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "9"
		Description	     = "Enhanced Encryption enabled more protection on Microsoft Teams. Calling and Meeting end-to-end encryption ensures conversations stay encrypted and cannot be decoded unless users have access to."
		Remediation	     = "Enable End-To-End Encryption. Refer to the references on how to set-up end-to-end encryption in Teams"
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		PowerShellScript = 'Set-CsTeamsEnhancedEncryptionPolicy -Identity Global -CallingEndtoEndEncryptionEnabledType DisabledUserOverride'
		References	     = @(@{ 'Name' = 'Use end-to-end encryption for one-to-one Microsoft Teams calls'; 'URL' = 'https://docs.microsoft.com/en-us/microsoftteams/teams-end-to-end-encryption' })
	}
}


function Audit-CSTM-Tms005
{
	try
	{
		$MSTeamsEnhancedEncryption = @()
		$MSTeamsEnhancedEncryptionCMD = Get-CsTeamsEnhancedEncryptionPolicy -Identity Global
		if ($MSTeamsEnhancedEncryptionCMD.CallingEndtoEndEncryptionEnabledType -contains 'Disabled')
		{
			$MSTeamsEnhancedEncryption += "CallingEndtoEndEncryptionEnabledType: $($MSTeamsEnhancedEncryptionCMD.CallingEndtoEndEncryptionEnabledType)"
		}
		if ($MSTeamsEnhancedEncryptionCMD.MeetingEndToEndEncryption -contains 'Disabled')
		{
			$MSTeamsEnhancedEncryption += "MeetingEndToEndEncryption: $($MSTeamsEnhancedEncryptionCMD.MeetingEndToEndEncryption)"
		}
		if ($MSTeamsEnhancedEncryption.Count -gt 0)
		{
			$endobject = Build-CSTM-Tms005($MSTeamsEnhancedEncryption)
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
return Audit-CSTM-Tms005