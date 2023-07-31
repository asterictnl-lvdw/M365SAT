# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Phishing TransportRules Bypass
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex019($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex019"
		FindingName	     = "CSTM-Ex019 - Simulated Phishing Transport Rules - Security Bypasses"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "0.0"
		Description	     = "Your Organization has a Simulation Phish Policy Activated for educational purposes. If this is not the case, quickly disable this policy"
		Remediation	     = "Review Mail Flow rules that bypass spam filtering for Simulated Phishing platforms. Bypassing Spam filtering, Safe Links and Safe Attachments by IP, domain, or header values allows attackers to spoof domains and addresses, or modify the header of their emails and bypass security measures."
		PowerShellScript = 'New-HostedContentFilterPolicy -Name "Example Policy" -HighConfidenceSpamAction Quarantine -SpamAction Quarantine -BulkThreshold 6'
		DefaultValue	 = "No Policy"
		ExpectedValue    = "No Policy / Policy That Management is Aware off"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		References	     = @(@{ 'Name' = 'Soteria Curated List of Simulated Phishing Platform Resource Links'; 'URL' = "https://gist.github.com/ThoughtContagion/5f227b562bef4b19d5a5d0d4765f7890" },
			@{ 'Name' = 'Whitelist Dangers and Cyber-Security'; 'URL' = "https://www.spamstopshere.com/blog/email-security/whitelist-dangers-and-cyber-security" })
	}
	return $inspectorobject
}

Function Inspect-CSTM-Ex019
{
	Try
	{
		
		$rules = Get-TransportRule | Where-Object { ($_.State -eq "Enabled") -and (($_.Identity -like "*phish*") -or ($null -ne $_.HeaderContainsMessageHeader) -or ($_.HeaderContainsMessageHeader -like "X-MS-Exchange-Organization-SkipSafe*Processing") -or (($_.SetSCL -eq "-1") -and ($null -ne $_.SenderIpRanges))) }
		
		$bypasses = @()
		
		If (($rules | measure-object).count -gt 0)
		{
			$path = New-Item -ItemType Directory -Force -Path "$($path)\Mail-Flow-Rules\Simulated-Phishing"
			
			ForEach ($rule in $rules)
			{
				$name = $rule.Name
				
				$pattern = '[\\/():;]'
				
				$name = $name -replace $pattern, '-'
				
				$rule | Format-List | Out-File -FilePath "$($path)\$($name)_Simulated-Phish-Spam-Bypass-Rule.txt"
				
				If ($rule.SetHeaderName -eq "X-MS-Exchange-Organization-SkipSafeLinksProcessing")
				{
					$bypasses += "Safe Links Bypass"
				}
				If ($rule.SetHeaderName -eq "X-MS-Exchange-Organization-SkipSafeAttachmentProcessing")
				{
					$bypasses += "Safe Attachments Bypass"
				}
				If ($rule.SetHeaderName -eq "X-Forefront-Antispam-Report")
				{
					$bypasses += "Spam Bypass"
				}
				If ($rule.SetHeaderName -eq "X-MS-Exchange-Organization-BypassClutter")
				{
					$bypasses += "Junk Folder Bypass"
				}
				If (($rule.HeaderContainsMessageHeader -eq "X-PHISHTEST") -or ($rule.HeaderContainsMessageHeader -eq "X-PhishingTackle") -or ($rule.HeaderContainsMessageHeader -eq "X-EPHISHIENCY"))
				{
					$bypasses += "Use of default simulated phishing platform header"
				}
			}
			
			$allBypasses = $bypasses | Sort-Object
			
			$endobject = Build-CSTM-Ex019($allBypasses)
			return $endobject
		}
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CSTM-Ex019


