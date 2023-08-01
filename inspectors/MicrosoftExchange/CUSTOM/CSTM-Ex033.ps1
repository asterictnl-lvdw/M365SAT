# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Email Security Checks Bypass Based on Sender Domain
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex033($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex033"
		FindingName	     = "CSTM-Ex033 - Email Security Checks are Bypassed Based on Sender Domain"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "In the Exchange transport rules settings, it is possible to implement transport rules that bypass spam filtering and other email security capabilities (Exchange Online Protection) based on an IP address or domain (allowlisting). This makes a significant assumption of trust that should be reviewed and reconsidered. The transport rules listed herein bypass email security based on a domain allowlist."
		Remediation	     = "Locate the rules M365SAT has identified (they are listed in this report) and determine who created the rules. Pursue a dialogue or analysis of whether the Exchange Online Protection is necessary for continued operations and whether another solution is possible. If the rules are not necessary, remove the rules."
		PowerShellScript = '$rejectMessageText = "YOURTEXTHERE";New-TransportRule -name "Client Rules To External Block" -Priority 0 -SentToScope NotInOrganization -FromScope InOrganization -MessageTypeMatches AutoForward -RejectMessageEnhancedStatusCode 5.7.1 -RejectMessageReasonText $rejectMessageText Set-RemoteDomain -AutoForwardEnabled $false'
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Manage Mail Flow Rules in Exchange Online'; 'URL' = "https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/manage-mail-flow-rules" },
			@{ 'Name' = 'Bypassing Exchange Online Protection in Office 365'; 'URL' = "https://docs.sophos.com/central/Customer/help/en-us/central/Customer/tasks/bypassingexchange.html" })
	}
	return $inspectorobject
}

function Inspect-CSTM-Ex033
{
	Try
	{
		
		$domain_allowlist_rules = (Get-TransportRule | Where-Object { $_.SetSCL -AND ($_.SetSCL -as [int] -LE 0) -AND $_.SenderDomainIs }).Name
		
		If ($domain_allowlist_rules.Count -eq 0)
		{
			return $null
		}
		
		$endobject = Build-CSTM-Ex033($domain_allowlist_rules)
		Return $endobject
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CSTM-Ex033


