# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks the PolicyConfigAnalyzerRecommendation
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex007($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex007"
		FindingName	     = "CSTM-Ex007 - Multiple Policies Not Enabled that are found by the ConfigAnalyzerPolicyRecommendations!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore  	     = "9"
		Description	     = 'Anti-Spam, Anti-Phishing and Anti-Malware Policies are recommended to have an existing policy configured to minimize impact from spam and phishing and malware within your organization'
		Remediation	     = 'Configure the Anti-Spam, Anti-Phishing and Anti-Malware policy according to the recommendations. Please consult the text file for further information.'
		PowerShellScript = 'New-AntiPhishPolicy; New-HostedContentFilterPolicy; New-MalwareFilterPolicy'
		DefaultValue	 = "> 0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'ConfigAnalyzerPolicyRecommendations.txt'; 'URL' = "file://$($path)/ConfigAnalyzerPolicyRecommendations.txt" },
			@{ 'Name' = 'Lock, Stock and Office 365 ATP Automation'; 'URL' = "https://call4cloud.nl/2020/07/lock-stock-and-office-365-atp-automation/" })
	}
	return $inspectorobject
}

function Audit-CSTM-Ex007
{
	try
	{
		$finalobject = @()
		$ConfigAnalyzerPolicyRecommendation = Get-ConfigAnalyzerPolicyRecommendation -RecommendedPolicyType Strict
		foreach ($recommendation in $ConfigAnalyzerPolicyRecommendation)
		{
			$finalobject += $recommendation.SettingName
		}
		
		if ($ConfigAnalyzerPolicyRecommendation.Count -ne 0)
		{
			Get-ConfigAnalyzerPolicyRecommendation -RecommendedPolicyType Strict | ft PolicyGroup, SettingName, SettingNameDescription, Recommendation | Out-File "$path\ConfigAnalyzerPolicyRecommendations.txt"
			$endobject = Build-CSTM-Ex007($finalobject.count)
			return $endobject
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
return Audit-CSTM-Ex007