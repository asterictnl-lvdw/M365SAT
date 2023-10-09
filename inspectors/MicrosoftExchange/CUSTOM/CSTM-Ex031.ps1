# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Public Groups Inspection
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex031($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex031"
		FindingName	     = "CSTM-Ex031 - Microsoft Exchange & Microsoft Office 365 Contains Public Groups"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "0"
		Description	     = "Ensure that only organizationally managed and approved public groups exist."
		Remediation	     = "In the Microsoft 365 Administration portal, go to: Teams&Groups > Select the Public Group > Go To Settings > Set Privacy To Private"
		PowerShellScript = '$publicgroups = Get-UnifiedGroup | ? { $_.AccessType -eq "Public"}'
		DefaultValue	 = "0"
		ExpectedValue    = "Approved Public Groups Documented"
		ReturnedValue    = $findings
		Impact		     = "4"
		Likelihood	     = "1"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Reference - Get-UnifiedGroup'; 'URL' = "https://learn.microsoft.com/en-us/powershell/module/exchange/get-unifiedgroup?view=exchange-ps" },
			@{ 'Name' = 'Group Self-Service'; 'URL' = "https://blogs.perficient.com/2016/03/07/office-365-have-you-evaluated-these-exchange-online-features/" })
	}
	return $inspectorobject
}

function Audit-CSTM-Ex031
{
	try
	{
		$publicgroupsdata = @()
		$publicgroups = Get-UnifiedGroup | ? { $_.AccessType -eq "Public" }
		if ($publicgroups -ne $null)
		{
			foreach ($publicgroupsdataobj in $publicgroups)
			{
				$publicgroupsdata += "$($publicgroups.DisplayName),$($publicgroups.AccessType)"
			}
			$endobject = Build-CSTM-Ex031($publicgroupsdata)
			Return $endobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CSTM-Ex031