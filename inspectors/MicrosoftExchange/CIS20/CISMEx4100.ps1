# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure notifications for internal users sending malware is Enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)


function Build-CISMEx4100($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx4100"
		FindingName	     = "CIS MEx 4.10 - Notifications for internal users sending malware is Disabled"
		CVS			     = "2.0"
		Description	     = "This setting alerts administrators that an internal user sent a message that contained malware. This may indicate an account or machine compromise, that would need to be investigated."
		Remediation	     = "Configure a MalwareFilterPolicy by using the PowerShellScript"
		PowerShellScript = 'Set-MalwareFilterPolicy -Identity "Malware Filter Policy Name" -Action DeleteMessage -EnableInternalSenderAdminNotifications $true -InternalSenderAdminAddress "admin@yourdomain.com"'
		DefaultValue	 = "False"
		ExpectedValue    = "True, with a configured mailbox or distribution list address"
		ReturnedValue    = $findings
		Impact		     = "Low"
		RiskRating	     = "Low"
		References	     = @(@{ 'Name' = 'Configuring Exchange Online Protection'; 'URL' = "https://practical365.com/first-steps-configuring-exchange-online-protection/" },
			@{ 'Name' = 'Set-MalwareFilterPolicy Commandlet Reference Example 1'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-malwarefilterpolicy?view=exchange-ps" })
	}
	return $inspectorobject
}

function Inspect-CISMEx4100
{
	Try
	{
		$findings = @()
		$MalwareFilterPolicy = Get-MalwareFilterPolicy | Select-Object Identity, EnableInternalSenderAdminNotifications, InternalSenderAdminAddress
		
		foreach ($Policy in $MalwareFilterPolicy)
		{
			if ($Policy.EnableInternalSenderAdminNotifications -eq $false -or [String]::IsNullOrEmpty($Policy.InternalSenderAdminAddress))
			{
				$findings += "$($Policy.Identity): has EnableInternalSenderAdminNotifications on False and $($Policy.InternalSenderAdminAddress) as addresses"
			}
			
		}
		
		If ($findings.Count -igt 0)
		{
			$endobject = Build-CISMEx4100($findings)
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

return Inspect-CISMEx4100


