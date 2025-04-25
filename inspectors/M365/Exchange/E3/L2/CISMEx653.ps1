# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx653
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx653"
        ID               = "6.5.3"
        Title            = "(L2) Ensure additional storage providers are restricted in Outlook on the web"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "True"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Allowing additional storage providers like Box, Dropbox, and Google Drive in Outlook on the Web can expose the organization to increased risks of information leakage and malware infections from untrusted services. Restricting these providers mitigates this risk."
        Impact           = "The impact associated with this change is highly dependent upon current practices in the tenant. If users do not use other storage providers, then minimal impact is likely. However, if users do regularly utilize providers outside of the tenant this will affect their ability to continue to do so."
        Remediation  	 = 'Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -AdditionalStorageProvidersAvailable $false'
        References       = @(
            @{ 'Name' = '3rd Party Cloud Storage Services Supported by Office Apps'; 'URL' = 'https://support.microsoft.com/en-us/topic/3rd-party-cloud-storage-services-supported-by-office-apps-fce12782-eccc-4cf5-8f4b-d1ebec513f72' }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx653
{
	try
	{
		$AdditionalStorageProvidersAvailable = Get-OwaMailboxPolicy | Select-Object Name, AdditionalStorageProvidersAvailable
		$PolicyViolation = @()
		foreach ($Policy in $AdditionalStorageProvidersAvailable)
		{
			if ($AdditionalStorageProvidersAvailable.AdditionalStorageProvidersAvailable -match 'True')
			{
				$PolicyViolation += "$($Policy.Name): AdditionalStorageProvidersAvailable: $($AdditionalStorageProvidersAvailable.AdditionalStorageProvidersAvailable)"
			}
		}
		if ($PolicyViolation.count -igt 0)
		{
			$ExchangeMailTipsData | Format-List | Out-File -FilePath "$path\CISMEx653-OwaMailboxPolicySettings.txt"
			$endobject = Build-CISMEx653 -ReturnedValue ($PolicyViolation) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx653 -ReturnedValue ("AdditionalStorageProvidersAvailable: False") -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx653 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx653