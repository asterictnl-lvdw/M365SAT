# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Exchange
# Purpose: Checks if the Teams DLP Policy if configured is correctly enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx322($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx322"
		FindingName	     = "CIS MEx 3.2.2 - Teams DLP Policies Not Enabled and Enforced"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "2"
		Description	     = "Enabling the default Teams DLP policy rule in Microsoft 365 helps protect an organization's sensitive information by preventing accidental sharing or leakage of that information in Teams conversations and channels."
		Remediation	     = "Use the PowerShell script to create a new DLPCompliancePolicy or review the policies existence and if they are enabled."
		PowerShellScript = 'New-DlpCompliancePolicy -Name "SSN Teams Policy" -Comment "SSN Teams Policy" -TeamsLocation All -Mode Enable'
		DefaultValue	 = "Enable"
		ExpectedValue    = "Enable"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Learn about data loss prevention'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/dlp-learn-about-dlp?view=o365-worldwide" },
			@{ 'Name' = 'Create, test, and tune a DLP policy'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/create-test-tune-dlp-policy?view=o365-worldwide" })
	}
	return $inspectorobject
}

Function Audit-CISMEx322
{
	Try
	{
		try
		{
			$dlpPolicies = Get-DlpCompliancePolicy | Where-Object { $_.Mode -notlike "Enable" }
			
			$policies = @()
			$IncorrectDLPPolicy = 0
			if (-not [string]::IsNullOrEmpty($dlpPolicies))
			{
				foreach ($policy in $dlpPolicies)
				{
					$policies += "$($policy.Name) state is $($policy.mode)"
					$Validate = Get-DlpCompliancePolicy -Identity $policy.Name | Select-Object TeamsLocation*
					if ($Validate.count -eq 0 -or $Validate.TeamsLocation -eq 0 -or $Validate.TeamsLocationException -igt 0)
					{
						$IncorrectDLPPolicy++
					}
				}
			}
			If ($IncorrectDLPPolicy -igt 0)
			{
					$endobject = Build-CISMEx322($policies)
					return $endobject
			}
			Return $null
			
		}
		catch
		{
			$dlpPolicies = "No DLP Compliance Policy"
			$endobject = Build-CISMEx322($policies)
			return $endobject
		}
		
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}
return Audit-CISMEx322