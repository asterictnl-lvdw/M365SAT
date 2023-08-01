# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks Domain Spoofing
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex011($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex011"
		FindingName	     = "CSTM-Ex011 - No Transport Rules to Block Domain Spoofing"
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

function Inspect-CSTM-Ex011
{
	Try
	{
		
		$rules = Get-TransportRule
		$domains = (Get-AcceptedDomain).DomainName
		
		$disabledRules = @()
		
		ForEach ($domain in $domains)
		{
			ForEach ($rule in $rules)
			{
				if (($rule.FromScope -eq "NotInOrganization") -AND ($rule.SenderDomainIs -contains $domain) -AND (($rule.DeleteMessage -eq $true) -OR ($null -ne $rule.RejectMessageReasonText) -OR ($rule.Quarantine -eq $true)))
				{
					if ($rule.State -eq "Disabled")
					{
						$disabledRules += "Rule `"$($rule.Identity)`" is disabled."
					}
				}
			}
		}
		if ($disabledRules.Count -igt 0)
		{
				$endobject = Build-CSTM-Ex011($disabledRules)
				return $endobject
		}
		else
		{
			return $null
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CSTM-Ex011


