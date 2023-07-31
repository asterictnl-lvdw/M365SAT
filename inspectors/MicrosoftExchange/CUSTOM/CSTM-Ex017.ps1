# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Exchange Mailbox with Tenant Transport Rules to check
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex017($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex017"
		FindingName	     = "Tenant Transport Rules"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "0.0"
		Description	     = "There are Transport Rules Existing in Microsoft Exchange, please verify if they are not faulty or have any malicious intend"
		Remediation	     = "Review Mail Flow rules and validate that all results are expected and no conflicting rules are in place."
		PowerShellScript = 'Remove-TransportRule -Identity ID'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		References	     = @(@{ 'Name' = 'Manage Mail Flow Rules in Exchange Online'; 'URL' = "https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/manage-mail-flow-rules" })
	}
	return $inspectorobject
}

Function Inspect-CSTM-Ex017
{
	Try
	{
		$rules = Get-TransportRule
		
		If ($rules.count -igt 0)
		{
			$path = New-Item -ItemType Directory -Force -Path "$($path)\Mail-Flow-Rules"
			ForEach ($rule in $rules)
			{
				$name = $rule.Name
				
				$pattern = '[\\\[\]\{\}/():;\*]'
				
				$name = $name -replace $pattern, '-'
				
				$rule | Format-List | Out-File -FilePath "$($path)\$($name)_Mail-Flow-Rule.txt"
			}
			$endobject = Build-CSTM-Ex017($rules.Count)
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

return Inspect-CSTM-Ex017


