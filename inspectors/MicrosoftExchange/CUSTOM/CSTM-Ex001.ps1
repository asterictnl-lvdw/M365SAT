# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks if ADFS is existing
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex001($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex001"
		FindingName	     = "CSTM-Ex001 - ADFS Configuration Found"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "0"
		Description	     = "Active Directory Federation Services (ADFS) configured on this Tenant. ADFS Claims Rules may act as replacements for some features in Azure, hence rendering certain findings a 'False Positive'"
		Remediation	     = "Review ADFS configuration for claims rules that may replace or negate findings in this report (eg, Forced MFA when outside of corporate networks)."
		PowerShellScript = '-'
		DefaultValue	 = "None"
		ExpectedValue    = "Not applicable"
		ReturnedValue    = $findings
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Active Directory Federation Services'; 'URL' = 'https://docs.microsoft.com/en-us/windows-server/identity/active-directory-federation-services' })
	}
	return $inspectorobject
}

function Inspect-CSTM-Ex001
{
	Try
	{
		
		$OrgsADFS = @()
		$Orgs = Get-OrganizationConfig
		foreach ($Org in $Orgs)
		{
			if (-not [string]::IsNullOrEmpty($Org.AdfsIssuer))
			{
				$OrgsADFS += $Org.Name;
			}
		}
		
		
		If ($OrgsADFS.Count -igt 0)
		{
			$finalobject = Build-CSTM-Ex001($OrgsADFS)
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
return Inspect-CSTM-Ex001


