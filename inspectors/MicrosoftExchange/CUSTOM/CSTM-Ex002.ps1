# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks if Domain Spoofing is possible
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CSTM-Ex002($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex002"
		FindingName	     = "CSTM-Ex002 - Entities Allowed to Perform Domain Spoofing"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "Domain Spoofing occurs when an external entity sends email using a mail domain owned by another entity. There are legitimate use cases where domain spoofing is allowed. It is recommended to speak with stakeholders and determine if this type of rule is beneficial and if any exceptions are needed. Microsoft configures some Anti-Spoofing settings by default in the Anti-Phishing policies on tenants, this rule would complement default settings."
		Remediation	     = "Review the Tenant Allow/Block List under Spoofing in the Security console."
		PowerShellScript = ''
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Manage the Tenant Allow/Block List in EOP'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/tenant-allow-block-list?view=o365-worldwide' })
	}
	return $inspectorobject
}

function Inspect-CSTM-Ex002
{
	Try
	{
		
		$Objects = Get-TenantAllowBlockListSpoofItems | Where-Object { $_.Action -eq "Allow" }
		$sendingInfrastructure = @()
		
		If ($Objects.Count -igt 0)
		{
			ForEach ($Object in $Objects)
			{
				$Object | Export-Csv -Path "$($path)\AllowedSpoofingList.csv" -NoTypeInformation -Append
				$sendingInfrastructure += $Object.SendingInfrastructure
			}
			$finalobject = Build-CSTM-Ex002($sendingInfrastructure)
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

return Inspect-CSTM-Ex002


