# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks iFrames are identified as Spam
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex009($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex009"
		FindingName	     = "CSTM-Ex009 - iFrames Not Identified as Spam"
		ProductFamily    = "Microsoft Exchange"
		RiskScore		     = "9"
		Description	     = "Cyber adversaries often place HTML iframes in the body of an email as a vector for containing spam templates or other malicious content. the organization does not have Exchange spam/content Filter policies to flag emails containing iframes as spam. It is advisable to create content filter rules to detect iframes in email as spam."
		Remediation	     = "Use the PowerShell Script or the References to create a iFrame Spam policy"
		PowerShellScript = 'New-HostedContentFilterPolicy -Name "Example Policy" -HighConfidenceSpamAction Quarantine -SpamAction Quarantine -BulkThreshold 6 -MarkAsSpamFramesInHtml On -MarkAsSpamSpfRecordHardFail On -MarkAsSpamEmptyMessages On -MarkAsSpamJavaScriptInHtml On'
		DefaultValue	 = "Off"
		ExpectedValue    = "On"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Configuring Exchange Online Protection, First Steps'; 'URL' = "https://practical365.com/first-steps-configuring-exchange-online-protection/" },
			@{ 'Name' = 'Advanced Spam Filter (ASF) Settings in Exchange Online Protection'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/advanced-spam-filtering-asf-options?view=o365-worldwide" },
			@{ 'Name' = 'Set-HostedContentFilterPolicy Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-hostedcontentfilterpolicy?view=exchange-ps" })
	}
	return $inspectorobject
}

function Inspect-CSTM-Ex009
{
	Try
	{
		$IFrames = (Get-HostedContentFilterPolicy).MarkAsSpamFramesInHtml
		If ($IFrames -eq 'Off')
		{
			$endobject = Build-CSTM-Ex009($IFrames)
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

return Inspect-CSTM-Ex009


