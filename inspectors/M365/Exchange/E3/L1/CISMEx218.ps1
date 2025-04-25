# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx218
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx218"
        ID               = "2.1.8"
        Title            = "(L1) Ensure that SPF records are published for all Exchange Domains"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "Null for all custom domains"
        ExpectedValue    = "'v=spf1 include:spf.protection.outlook.com include:<domain name> -all' for all Domains"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "SPF (Sender Policy Framework) records enable Exchange Online Protection and other email systems to verify the legitimacy of email origins. This helps identify spoofed emails, reducing the risk of phishing and spam."
        Impact           = "There should be minimal impact of setting up SPF records however, organizations should ensure proper SPF record setup as email could be flagged as spam if SPF is not setup appropriately"
        Remediation      = "Create an SPF TXT DNS record for each domain in accordance with the provided references. Note that incorrect configuration may affect mail deliverability. A gradual rollout is recommended: v=spf1 include:spf.protection.outlook.com include:<domain name> -all"
        References       = @(
            @{ 'Name' = 'Set Up SPF in Office 365 to Help Prevent Spoofing'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-spf-in-office-365-to-help-prevent-spoofing?view=o365-worldwide' },
            @{ 'Name' = 'Explaining SPF Records'; 'URL' = 'https://postmarkapp.com/blog/explaining-spf' },
            @{ 'Name' = 'Set up SPF to identify valid email sources for your Microsoft 365 domain'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-spf-configure?view=o365-worldwide' }
        )
    }
    return $inspectorobject
}

function Inspect-CISMEx218
{
	Try
	{
		if ($PSVersionTable.PSVersion.Major -eq 7){
			if($IsLinux){
				$domains = (Get-AcceptedDomain).DomainName | Where-Object { $_.Id -notlike "*.onmicrosoft.com" }
				$domains_without_records = @()
				ForEach ($domain in $domains)
				{
					try
					{
						$spf_record = (host -t txt $domain) | where-object {$_ -match "v=spf1 include:spf.protection.outlook.com"}
						if ([string]::IsNullOrEmpty($spf_record) -eq $true)
						{
							$domains_without_records += $domain
						}
					}
					catch
					{
						$domains_without_records += $domain
					}
				}
			}
			else{
				$domains = (Get-AcceptedDomain).DomainName | Where-Object { $_.Id -notlike "*.onmicrosoft.com" }
				$domains_without_records = @()
				
				# The redirection is kind of a cheesy hack to prevent the output from
				# cluttering the screen.
				ForEach ($domain in $domains)
				{
					try
					{
						$spf_record = (Resolve-DnsName -Name $domain -Type TXT | Where-Object { $_.Strings -match 'v=spf1' }).Strings
						if ([string]::IsNullOrEmpty($spf_record) -eq $true)
						{
							$domains_without_records += $domain
						}
					}
					catch
					{
						$domains_without_records += $domain
					}
				}
			}
		}else{
			$domains = (Get-AcceptedDomain).DomainName | Where-Object { $_.Id -notlike "*.onmicrosoft.com" }
			$domains_without_records = @()
			
			# The redirection is kind of a cheesy hack to prevent the output from
			# cluttering the screen.
			ForEach ($domain in $domains)
			{
				try
				{
					$spf_record = (Resolve-DnsName -Name $domain -Type TXT | Where-Object { $_.Strings -match 'v=spf1' }).Strings
					if ([string]::IsNullOrEmpty($spf_record) -eq $true)
					{
						$domains_without_records += $domain
					}
				}
				catch
				{
					$domains_without_records += $domain
				}
			}
		}
		
		
		If ($domains_without_records.Count -ne 0)
		{
			$domains_without_records | Format-Table -AutoSize | Out-File "$path\CISMEx218-DomainsWithoutSPF.txt"
			$endobject = Build-CISMEx218 -ReturnedValue $domains_without_records -Status "FAIL" -RiskScore "9" -RiskRating "Medium"
			Return $endobject
		}
		else
		{
			$endobject = Build-CISMEx218 -ReturnedValue $domains -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
		
	}
	catch
	{
		$endobject = Build-CISMEx218 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Inspect-CISMEx218


