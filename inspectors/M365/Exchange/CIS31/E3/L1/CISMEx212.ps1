# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.1.0
# Product Family: Microsoft Exchange
# Purpose: Checks common malicious attachments and if they are filtered properly
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx212($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx212"
		FindingName	     = "CIS MEx 2.1.2 - Common Attachment Types Filter is disabled!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "3"
		Description	     = "The Common Attachment Types Filter lets a user block known and custom malicious file types from being attached to emails."
		Remediation	     = "Run the following Exchange Online PowerShell command"
		PowerShellScript = 'Set-MalwareFilterPolicy -Identity Default -EnableFileFilter $true'
		DefaultValue	 = "True"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Anti-Malware Policies Configure'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-malware-policies-configure?view=o365-worldwide' })
	}
}


function Inspect-CISMEx212
{
	Try
	{
		# These file types are from Microsoft's default definition of the common attachment types filter.
		$malwarefilterpolicy = Get-MalwareFilterPolicy
		
		if ($malwarefilterpolicy.EnableFileFilter -eq $False)
		{
			$malwarefilterpolicy | Format-Table -AutoSize | Out-File "$path\CISMEx212-MalwareFilterPolicySettings.txt"
			$finalobject = Build-CISMEx212($malwarefilterpolicy.EnableFileFilter)
			return $finalobject
		}
		return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CISMEx212


