# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Teams
# Purpose: Ensure users can report security concerns in Teams
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm861($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMTm861"
		FindingName	     = "CISM Tm 8.6.1 - Users cannot report security concerns in Teams"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "15"
		Description	     = "Users will be able to more quickly and systematically alert administrators of suspicious malicious messages within Teams. The content of these messages may be sensitive in nature and therefore should be kept within the organization and not shared with Microsoft without first consulting company policy."
		Remediation	     = "Use the PowerShell script to allow users to report security concerns in teams:"
		PowerShellScript = 'Set-CsTeamsMessagingPolicy -Identity Global -AllowSecurityEndUserReporting $true; $usersub = "example@contoso.com"; $params = @{ Identity = "DefaultReportSubmissionPolicy" EnableReportToMicrosoft = $false ReportChatMessageEnabled = $false ReportChatMessageToCustomizedAddressEnabled = $true ReportJunkToCustomizedAddress = $true ReportNotJunkToCustomizedAddress = $true ReportPhishToCustomizedAddress = $true ReportJunkAddresses = $usersub ReportNotJunkAddresses = $usersub ReportPhishAddresses = $usersub }; Set-ReportSubmissionPolicy @params; New-ReportSubmissionRule -Name DefaultReportSubmissionRule -ReportSubmissionPolicy DefaultReportSubmissionPolicy -SentTo $usersub'
		DefaultValue	 = "True"
		ExpectedValue    = "-"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'User reported message settings in Microsoft Teams'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/submissions-teams?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-CISMTm861
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMessagingPolicy -Identity Global | Select-Object AllowSecurityEndUserReporting
		$MicrosoftReportPolicy = Get-ReportSubmissionPolicy | Select-Object ReportJunkToCustomizedAddress, ReportNotJunkToCustomizedAddress, ReportPhishToCustomizedAddress, ReportJunkAddresses, ReportNotJunkAddresses, ReportPhishAddresses, ReportChatMessageEnabled, ReportChatMessageToCustomizedAddressEnabled
		if ($MicrosoftTeamsCheck.AllowSecurityEndUserReporting -eq $False)
		{
			$ViolatedTeamsSettings += "AllowSecurityEndUserReporting: $($MicrosoftTeamsCheck.AllowSecurityEndUserReporting)"
		}
		if ($MicrosoftReportPolicy.ReportJunkToCustomizedAddress -eq $False)
		{
			$ViolatedTeamsSettings += "ReportJunkToCustomizedAddress: $($MicrosoftReportPolicy.ReportJunkToCustomizedAddress)"
		}
		
		if ($MicrosoftReportPolicy.ReportNotJunkToCustomizedAddress -eq $False)
		{
			$ViolatedTeamsSettings += "ReportNotJunkToCustomizedAddress: $($MicrosoftReportPolicy.ReportNotJunkToCustomizedAddress)"
		}
		if ($MicrosoftReportPolicy.ReportPhishToCustomizedAddress -eq $False)
		{
			$ViolatedTeamsSettings += "ReportPhishToCustomizedAddress: $($MicrosoftReportPolicy.ReportPhishToCustomizedAddress)"
		}
		if ([string]::IsNullOrEmpty($MicrosoftReportPolicy.ReportJunkAddresses))
		{
			$ViolatedTeamsSettings += "ReportJunkAddresses: NULL"
		}
		if ([string]::IsNullOrEmpty($MicrosoftReportPolicy.ReportNotJunkAddresses))
		{
			$ViolatedTeamsSettings += "ReportNotJunkAddresses: NULL"
		}
		if ([string]::IsNullOrEmpty($MicrosoftReportPolicy.ReportPhishAddresses))
		{
			$ViolatedTeamsSettings += "ReportPhishAddresses: NULL"
		}
		if ($MicrosoftReportPolicy.ReportChatMessageEnabled -eq $True)
		{
			$ViolatedTeamsSettings += "ReportChatMessageEnabled: $($MicrosoftReportPolicy.ReportChatMessageEnabled)"
		}
		if ($MicrosoftReportPolicy.ReportChatMessageToCustomizedAddressEnabled -eq $False)
		{
			$ViolatedTeamsSettings += "ReportChatMessageToCustomizedAddressEnabled: $($MicrosoftReportPolicy.ReportChatMessageToCustomizedAddressEnabled)"
		}
		if ($ViolatedTeamsSettings.Count -igt 0)
		{
			$ViolatedTeamsSettings | Format-Table -AutoSize | Out-File "$path\CISMTm811-TeamsMessagingSubmissionPolicy.txt"
			$endobject = Build-CISMTm861($ViolatedTeamsSettings)
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
return Audit-CISMTm861