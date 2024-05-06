# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Azure
# Purpose: Checks how many groups are enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CSTM-Az007($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Az007"
		FindingName	     = "CSTM-Az007 - Multiple Groups Security Disabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Multiple Groups in Azure Directory do not have any security restrictions enabled."
		Remediation	     = "Consider enabling Azure Directory Security for Groups to the respective groups"
		PowerShellScript = ''
		DefaultValue	 = "Not Enabled for Groups by Default"
		ExpectedValue    = "Enabled for Groups"
		ReturnedValue    = "Number of Groups without Security: $($findings)"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Azure AD Groups - in a nutshell'; 'URL' = 'https://byteben.com/bb/azure-ad-groups-in-a-nutshell/' })
	}
}

function Audit-CSTM-Az007
{
	try
	{
		$object = @()
		$groups = Get-MgGroup -All | Where-Object { $_.SecurityEnabled -eq $False } | select DisplayName, SecurityEnabled
		$groupscount = $groups.SecurityEnabled.Count
		if ($groupscount -ne 0)
		{
			foreach ($group in $groups)
			{
				$object += "$($group.DisplayName): $($group.SecurityEnabled)"
			}
			$finalobject = Build-CSTM-Az007($groupscount)
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
return Audit-CSTM-Az007