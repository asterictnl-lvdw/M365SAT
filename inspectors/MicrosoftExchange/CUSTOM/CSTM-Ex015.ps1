# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Exchange Mailbox with SendAs Delegates
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex015($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex015"
		FindingName	     = "CSTM-Ex015 - Exchange Mailboxes with SendOnBehalfOf Delegates Found"
		ProductFamily    = "Microsoft Exchange"
		RiskScore		     = "9"
		Description	     = "The Exchange Online mailboxes listed above have delegated SendOnBehalfOf permissions to another account."
		Remediation	     = "This finding refers to individual mailboxes that have SendOnBehalfOf delegated permissions. For these mailboxes, verify that the delegate access is expected, appropriate, and do not violate company policy."
		PowerShellScript = 'Get-EXOMailbox -ResultSize Unlimited -Properties GrantSendOnBehalfTo | Set-Mailbox -GrantSendOnBehalfTo @{remove="*"}'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings.ToString()
		Impact		     = "3"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Set-Mailbox Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-mailbox?view=exchange-ps" },
			@{ 'Name' = 'Remove Send on Behalf permissions using Powershell'; 'URL' = "https://morgantechspace.com/2015/08/powershell-remove-send-on-behalf-permissions.html" })
	}
	return $inspectorobject
}

Function Inspect-CSTM-Ex015
{
	Try
	{
		
		
		$GrantSendOnBehalfTo = Get-EXOMailbox -ResultSize Unlimited -Properties GrantSendOnBehalfTo | Where-Object { $_.GrantSendOnBehalfTo -like "*" }
		
		if ($GrantSendOnBehalfTo.Count -gt 0)
		{
			$GrantSendOnBehalfTo | Select-Object UserPrincipalName, GrantSendOnBehalfTo | Out-File -FilePath "$($path)\EXOGrantSendOnBehalfToPermissions.txt" -Append
			$endobject = Build-CSTM-Ex015($GrantSendOnBehalfTo.Count)
			return $endobject
		}
		Return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

Inspect-CSTM-Ex015


