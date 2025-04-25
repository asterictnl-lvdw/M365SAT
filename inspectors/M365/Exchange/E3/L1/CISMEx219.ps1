# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx219
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx219"
        ID               = "2.1.9"
        Title            = "(L1) Ensure that DKIM is enabled for all Exchange Online Domains"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "False on all custom domains"
        ExpectedValue    = "Enabled for all custom domains"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling DKIM (DomainKeys Identified Mail) for Exchange Online ensures that outbound messages are cryptographically signed, allowing recipient systems to verify that they originate from authorized servers. This minimizes the risk of email spoofing and enhances domain security."
        Impact           = "There should be no impact of setting up DKIM however, organizations should ensure appropriate setup to ensure continuous mail-flow."
        Remediation      = 'Set-DkimSigningConfig -Identity < domainName > -Enabled $True'
        References       = @(
            @{ 'Name' = 'Use DKIM to validate outbound email sent from your custom domain'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email?view=o365-worldwide' },
            @{ 'Name' = 'DKIM Configuration'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dkim-configure?view=o365-worldwide' },
            @{ 'Name' = 'DKIM FAQ'; 'URL' = 'http://dkim.org/info/dkim-faq.html' },
            @{ 'Name' = 'Set up DKIM to sign mail from your Microsoft 365 domain'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dkim-configure?view=o365-worldwide' }
        )
    }
    return $inspectorobject
}

function Inspect-CISMEx219
{
	Try
	{
		$domains_without_dkim = (Get-DkimSigningConfig | Where-Object { (!$_.Enabled) -and ($_.Domain -notlike "*.onmicrosoft.com") }).Domain
		
		
		If ($domains_without_dkim.Count -igt 0)
		{
			$domains_without_dkim | Format-Table -AutoSize | Out-File "$path\CISMEx219-DomainsWithoutDKIM.txt"
			$endobject = Build-CISMEx219 -ReturnedValue $domains_without_dkim  -Status "FAIL" -RiskScore "9" -RiskRating "Medium"
			Return $endobject
		}
		else
		{
			$endobject = Build-CISMEx219 -ReturnedValue "All domains have DKIM enabled" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
		
	}
	catch
	{
		$endobject = Build-CISMEx219 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Inspect-CISMEx219


