# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Checks if the Customer Lockbox Feature is enabled or disabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx310($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx310"
		FindingName	     = "CIS MEx 3.1 - CustomerLockbox Feature is disabled"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "10"
		Description	     = "Enabling this feature protects organizational data against data spillage and exfiltration."
		Remediation	     = "Use the PowerShell script to enable CustomerLockBox for your Exchange Tenant"
		PowerShellScript = 'Set-OrganizationConfig -CustomerLockBoxEnabled $true'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Customer Lockbox Overview'; 'URL' = "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview" })
	}
	return $inspectorobject
}

function Audit-CISMEx310
{
	try
	{
		$CustomerLockbox = Get-OrganizationConfig | Select-Object CustomerLockBoxEnabled
		
		if ($CustomerLockbox.CustomerLockBoxEnabled -match 'False')
		{
			$endobject = Build-CISMEx310('CustomerLockBoxEnabled: ' + $CustomerLockbox.CustomerLockBoxEnabled)
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
return Audit-CISMEx310