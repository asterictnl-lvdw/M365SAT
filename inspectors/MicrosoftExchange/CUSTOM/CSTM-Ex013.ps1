# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks if a DLP Policy is enabled and enforced
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex013($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex013"
		FindingName	     = "CSTM-Ex013 - Exchange Mailboxes with FullAccess Delegates Found"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "12"
		Description	     = "The Exchange Online mailboxes listed above have delegated Full Access permissions to another account."
		Remediation	     = "This finding refers to individual mailboxes that have Full Access delegated permissions. For these mailboxes, verify that the delegate access is expected, appropriate, and do not violate company policy."
		PowerShellScript = 'Remove-MailboxPermission -Identity mailbox -AccessRights FullAccess -Confirm:$false -User user'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings
		Impact		     = "4"
		Likelihood	     = "3"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Remove-MailboxPermission Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/remove-mailboxpermission?view=exchange-ps" })
	}
	return $inspectorobject
}

Function Inspect-CSTM-Ex013
{
	Try
	{
		
		$FullAccess = Get-ExoMailbox -ResultSize Unlimited | Get-EXOMailboxPermission | Where-Object { ($_.User -ne 'NT AUTHORITY\SELF') -and ($_.AccessRights -eq 'FullAccess') }
		
		if ($FullAccess.Count -gt 0)
		{
			$FullAccess | Select-Object Identity, User, AccessRights | Out-File -FilePath "$($path)\EXOFullAccessPermissions.txt" -Append
			$endobject = Build-CSTM-Ex013($FullAccess.Count)
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

Inspect-CSTM-Ex013


