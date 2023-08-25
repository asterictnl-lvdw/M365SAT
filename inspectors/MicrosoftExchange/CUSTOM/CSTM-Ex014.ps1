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

function Build-CSTM-Ex014($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex014"
		FindingName	     = "CSTM-Ex014 - Exchange Mailboxes with SendAs Delegates Found"
		ProductFamily    = "Microsoft Exchange"
		RiskScore		 = "9"
		Description	     = "The Exchange Online mailboxes listed above have delegated SendAs Access permissions to another account."
		Remediation	     = "This finding refers to individual mailboxes that have SendAs Access delegated permissions. For these mailboxes, verify that the delegate access is expected, appropriate, and do not violate company policy."
		PowerShellScript = 'Remove-MailboxPermission -Identity mailbox -AccessRights SendAs -Confirm:$false -User user'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings.ToString()
		Impact		     = "3"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Remove-MailboxPermission Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/remove-mailboxpermission?view=exchange-ps" })
	}
	return $inspectorobject
}

Function Inspect-CSTM-Ex014
{
	Try
	{
		
		
		$sendAs = Get-ExoMailbox -ResultSize Unlimited | Get-ExoRecipientPermission | Where-Object { ($_.Trustee -ne 'NT AUTHORITY\SELF') -and ($_.AccessControlType -eq "Allow") -and ($_.AccessRights -eq 'SendAs') }
		
		if ($sendAs.Count -gt 0)
		{
			$sendAs | Select-Object Identity, Trustee, AccessRights | Out-File -FilePath "$($path)\EXOSendAsPermissions.txt" -Append
			$endobject = Build-CSTM-Ex014($sendAs.Count)
			Return $endobject
		}
		Return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

Inspect-CSTM-Ex014


