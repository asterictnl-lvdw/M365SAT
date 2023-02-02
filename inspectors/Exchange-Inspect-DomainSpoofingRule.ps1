# This is an DomainSpoofingRule Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if Transport Rules against Domain Spoofing are created to Block them
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-DomainSpoofingRule($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0026"
		FindingName	     = "No Transport Rules to Block Domain Spoofing"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "No Exchange Online Transport Rules are in place to block emails that are spoofing Tenant owned domains. Domain spoofing occurs when an external entity sends email using a mail domain owned by another entity. There are legitimate use cases where domain spoofing is allowed. It is recommended to speak with stakeholders and determine if this type of rule is beneficial and if any exceptions are needed. Microsoft configures some Anti-Spoofing settings by default in the Anti-Phishing policies on tenants, this rule would complement default settings."
		Remediation	     = "Go to the Exchange Mail Flow rules screen and create a new rule which blocks emails sent from outside the organization, to inside the organization, where the sender's domain is any of the organization's owned domains."
		PowerShellScript = ''
		DefaultValue	 = "0"
		ExpectedValue    = "Transport Rules"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Anti-spoofing protection in EOP'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Inspect-DomainSpoofingRule
{
	Try
	{
		
		$rules = Get-TransportRule
		$flag = $False
		$domains = (Get-AcceptedDomain).DomainName
		
		$disabledRules = @()
		
		ForEach ($domain in $domains)
		{
			ForEach ($rule in $rules)
			{
				if (($rule.FromScope -eq "NotInOrganization") -AND ($rule.SenderDomainIs -contains $domain) -AND (($rule.DeleteMessage -eq $true) -OR ($null -ne $rule.RejectMessageReasonText) -OR ($rule.Quarantine -eq $true)))
				{
					$flag = $True
				}
				if (($flag -eq $true) -AND ($rule.State -eq "Disabled"))
				{
					$disabledRules += "Rule `"$($rule.Identity)`" is disabled."
				}
			}
		}
		
		If (($flag -eq $false) -and (($disabledRules | Measure-Object).Count -eq 0))
		{
			$endobject = Build-DomainSpoofingRule($disabledRules)
			return $endobject
		}
		elseif (($flag -eq $true) -and (($disabledRules | Measure-Object).Count -gt 0))
		{
			$endobject = Build-DomainSpoofingRule($disabledRules)
			return $endobject
		}
		else
		{
			return $null
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

return Inspect-DomainSpoofingRule


