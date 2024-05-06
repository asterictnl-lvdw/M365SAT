# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Teams
# Purpose: Ensure external file sharing in Teams is enabled for only approved cloud storage services
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm811($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMTm811"
		FindingName	     = "CISM Tm 8.1.1 - External file sharing in Teams is not enabled for only approved cloud storage services"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "15"
		Description	     = "Ensuring that only authorized cloud storage providers are accessible from Teams will help to dissuade the use of non-approved storage providers."
		Remediation	     = "Use the PowerShell script to disallow External File Sharing:"
		PowerShellScript = 'Set-CsTeamsClientConfiguration -AllowGoogleDrive $false -AllowShareFile $false -AllowBox $false -AllowDropBox $false -AllowEgnyte $false'
		DefaultValue	 = "All True"
		ExpectedValue    = "All False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Manage Skype for Business Online with PowerShell'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/enterprise/manage-skype-for-business-online-with-microsoft-365-powershell?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-CISMTm811
{
	try
	{
		$ViolatedTeamsSettings = @()
		$TeamsExternalSharing = Get-CsTeamsClientConfiguration | select AllowDropbox, AllowBox, AllowGoogleDrive, AllowShareFile, AllowEgnyte
		if ($TeamsExternalSharing.AllowDropbox -eq $True)
		{
			$ViolatedTeamsSettings += "AllowDropbox: True"
		}
		if ($TeamsExternalSharing.AllowBox -eq $True)
		{
			$ViolatedTeamsSettings += "AllowBox: True"
		}
		if ($TeamsExternalSharing.AllowFederatedUsers -eq $True)
		{
			$ViolatedTeamsSettings += "AllowFederatedUsers: True"
		}
		if ($TeamsExternalSharing.AllowEgnyte -eq $True)
		{
			$ViolatedTeamsSettings += "AllowEgnyte: True"
		}
		
		if ($ViolatedTeamsSettings.Count -igt 0)
		{
			$TeamsExternalSharing | Format-Table -AutoSize | Out-File "$path\CISMTm811-TeamsClientConfiguration.txt"
			$endobject = Build-CISMTm811($ViolatedTeamsSettings)
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
return Audit-CISMTm811