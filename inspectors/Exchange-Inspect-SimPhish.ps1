# This is an SimPhish Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if iFrames are marked as Spam
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Define Output for file
$path = @($OutPath)

function Build-SimPhish($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0034"
		FindingName	     = "Simulated Phishing Transport Rules - Security Bypasses"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "0.0"
		Description	     = "Your Organization has a Simulation Phish Policy Activated for educational purposes. If this is not the case, quickly disable this policy"
		Remediation	     = "UReview Mail Flow rules that bypass spam filtering for Simulated Phishing platforms. Bypassing Spam filtering, Safe Links and Safe Attachments by IP, domain, or header values allows attackers to spoof domains and addresses, or modify the header of their emails and bypass security measures."
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

Function Inspect-SimPhish
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
			
			$endobject = Build-SimPhish($allBypasses)
			return $endobject
		}
		
	}
	Catch
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

return Inspect-SimPhish


