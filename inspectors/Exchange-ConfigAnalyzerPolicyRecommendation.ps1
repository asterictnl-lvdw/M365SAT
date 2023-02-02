# This is an ConfigAnalyzerPolicyRecommendation Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks recommended policies are correctly configured and if not it outputs to a txt file.
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Define Path
$path = @($OutPath)

function Build-ConfigAnalyzerPolicyRecommendation($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0016"
		FindingName	     = "Multiple Policies Not Enabled found by ConfigAnalyzerPolicyRecommendations!"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.3"
		Description	     = 'Anti-Spam, Anti-Phishing and Anti-Malware Policies are recommended to have an existing policy configured to minimize impact from spam and phishing and malware within your organization'
		Remediation	     = 'Configure the Anti-Spam, Anti-Phishing and Anti-Malware policy according to the recommendations. Please consult the text file for further information.'
		PowerShellScript = 'New-AntiPhishPolicy; New-HostedContentFilterPolicy; New-MalwareFilterPolicy'
		DefaultValue	 = "> 0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings.Count.ToString()
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'ConfigAnalyzerPolicyRecommendations.txt'; 'URL' = "file://$($path)/ConfigAnalyzerPolicyRecommendations.txt" },
			@{ 'Name' = 'Lock, Stock and Office 365 ATP Automation'; 'URL' = "https://call4cloud.nl/2020/07/lock-stock-and-office-365-atp-automation/" })
	}
	return $inspectorobject
}

function Audit-ConfigAnalyzerPolicyRecommendation
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
			$endobject = Build-ConfigAnalyzerPolicyRecommendation($finalobject)
			return $endobject
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
return Audit-ConfigAnalyzerPolicyRecommendation