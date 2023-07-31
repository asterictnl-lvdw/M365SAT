# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: IP Addresses Spam checker
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex020($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex020"
		FindingName	     = "CSTM-Ex020 - No Spam Filters to Flag Emails containing IP Addresses as Spam"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "3.3"
		Description	     = "The organization does not have Exchange Spam/Content Filter policies to flag emails containing IP addresses as spam. Cyber adversaries often send emails that contain the IP addresses of malicious websites or other attack infrastructure. This may occur during phishing or lateral phishing. For this reason it is advisable to create Exchange Transport Rules to detect IP addresses in email as spam."
		Remediation	     = "Use the PowerShell Command to mitigate this issue."
		PowerShellScript = 'Set-HostedContentFilterPolicy -Identity "Default" -AllowedSenderDomains $AllowedSenders -BulkSpamAction MoveToJmf -BulkThreshold 7 -EnableRegionBlockList $true -RegionBlockList "CN","NG","KP","RU","UA","TH","PH","JP","HK","TW" -HighConfidenceSpamAction MoveToJmf -IncreaseScoreWithBizOrInfoUrls On -IncreaseScoreWithNumericIps On -InlineSafetyTipsEnabled $true -MakeDefault -MarkAsSpamBulkMail Off -MarkAsSpamFromAddressAuthFail On -MarkAsSpamNdrBackscatter On -MarkAsSpamSpfRecordHardFail On -PhishSpamAction MoveToJmf -SpamAction MoveToJmf'
		DefaultValue	 = "Off"
		ExpectedValue    = "On"
		ReturnedValue    = $findings
		Impact		     = "Low"
		RiskRating	     = "Low"
		References	     = @(@{ 'Name' = 'Configuring Exchange Online Protection, First Steps'; 'URL' = "https://practical365.com/first-steps-configuring-exchange-online-protection/" },
			@{ 'Name' = 'Anti-Spam Settings With Region Blocking'; 'URL' = "https://www.msp360.com/resources/blog/securing-your-office-365-tenants-part-2/#:~:text=Safe%20Links%20Policy%27-,Anti%2DSpam%20Settings%20With%20Region%20Blocking,-Next%20up%20is" })
	}
	return $inspectorobject
}

function Inspect-CSTM-Ex020
{
	Try
	{
		$policies = Get-HostedContentFilterPolicy
		
		$settingOff = @()
		
		$settingOn = @()
		
		Foreach ($policy in $policies)
		{
			If ($policy.IncreaseScoreWithNumericIps -eq "On")
			{
				$settingOn += $policy.Name
			}
			elseif ($policy.IncreaseScoreWithNumericIps -ne "On")
			{
				$settingOff += "$($policy.Name): $($policy.IncreaseScoreWithNumericIps)"
			}
		}
		
		If ($settingOff.Count -eq 0)
		{
			$endobject = Build-CSTM-Ex020($settingOff)
			return $endobject
		}
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CSTM-Ex020


