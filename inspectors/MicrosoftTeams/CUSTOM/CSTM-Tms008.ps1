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

function Build-CSTM-Tms008($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Tms008"
		FindingName	     = "CSTM-Tms008 - Unapproved File Sharing Options are Enabled"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "12"
		Description	     = "Microsoft Teams enables collaboration via file sharing. This file sharing is conducted within Teams, using SharePoint Online, by default; however, third-party cloud services are allowed as well. "
		Remediation	     = "Use the PowerShell Script to disable the sharing options."
		DefaultValue	 = "All= True"
		ExpectedValue    = "All= False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "4"
		RiskRating	     = "High"
		Priority		 = "High"
		PowerShellScript = 'Set-CsTeamsClientConfiguration -AllowGoogleDrive $false -AllowShareFile $false -AllowBox $false -AllowDropBox $false -AllowEgnyte $false'
		References	     = @(@{ 'Name' = 'Set up Skype for Business Online'; 'URL' = 'https://docs.microsoft.com/en-us/skypeforbusiness/set-up-skype-for-business-online/set-up-skype-for-business-online' })
	}
}


function Audit-CSTM-Tms008
{
	try
	{
		$MSTeamsSettings_3Data = @()
		$MSTeamsSettings_3 = Get-CsTeamsClientConfiguration | Select-Object allow*
		if ($MSTeamsSettings_3.AllowDropBox -or $MSTeamsSettings_3.AllowGoogleDrive -or $MSTeamsSettings_3.AllowShareFile -or $MSTeamsSettings_3.AllowBox -or $MSTeamsSettings_3.AllowEgnyte -match 'True')
		{
			$MSTeamsSettings_3Data += " AllowDropBox: " + $MSTeamsSettings_3.AllowDropBox
			$MSTeamsSettings_3Data += "`n AllowGoogleDrive: " + $MSTeamsSettings_3.AllowGoogleDrive
			$MSTeamsSettings_3Data += "`n AllowShareFile: " + $MSTeamsSettings_3.AllowShareFile
			$MSTeamsSettings_3Data += "`n AllowBox: " + $MSTeamsSettings_3.AllowBox
			$MSTeamsSettings_3Data += "`n AllowEgnyte: " + $MSTeamsSettings_3.AllowEgnyte
			$endobject = Build-CSTM-Tms008($MSTeamsSettings_3Data)
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
return Audit-CSTM-Tms008