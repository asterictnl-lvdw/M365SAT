# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm821
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm821"
        ID               = "8.2.1"
        Title            = "(L1) Ensure external access is restricted in the Teams admin center"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "All True \n AllowedDomains: AllowAllKnownDomains"
        ExpectedValue    = "All False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Allowing users to communicate with Skype or Teams users outside of an organization presents a potential security threat as external users can interact with organization users over Skype for Business or Teams. While legitimate, productivity-improving scenarios exist, they are outweighed by the risk of data loss, phishing, and social engineering attacks against organization users via Teams."
        Impact           = "The impact in terms of the type of collaboration users are allowed to participate in and the I.T. resources expended to manage an allowlist will increase. If a user attempts to join the inviting organization's meeting they will be prevented from joining unless they were created as a guest in EntraID or their domain was added to the allowed external domains list."
        Remediation      = 'Set-CsTenantFederationConfiguration -AllowFederatedUsers $false'
        References       = @(
            @{ 'Name' = 'IT Admins - Manage external meetings and chat with people and organizations using Microsoft identities'; 'URL' = "https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat?tabs=organization-settings" },
            @{ 'Name' = 'DarkGate malware delivered via Microsoft Teams - detection and response'; 'URL' = "https://levelblue.com/blogs/security-essentials/darkgate-malware-delivered-via-microsoft-teams-detection-and-response" },
            @{ 'Name' = 'Midnight Blizzard conducts targeted social engineering over Microsoft Teams'; 'URL' = "https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-conducts-targeted-social-engineering-over-microsoft-teams/" },
            @{ 'Name' = 'GIFShell Attack Lets Hackers Create Reverse Shell through Microsoft Teams GIFs'; 'URL' = "https://www.bitdefender.com/en-us/blog/hotforsecurity/gifshell-attack-lets-hackers-create-reverse-shell-through-microsoft-teams-gifs" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm821
{
	try
	{
		$ViolatedTeamsSettings = @()
		$TeamsExternalAccess = Get-CsTenantFederationConfiguration
		if ($TeamsExternalAccess.AllowFederatedUsers -eq $True)
		{
			$ViolatedTeamsSettings += "AllowFederatedUsers: True"
		}
		if ($TeamsExternalAccess.AllowedDomains.count -lt 1 -or $TeamsExternalAccess.AllowedDomains -eq "AllowAllKnownDomains")
		{
			$ViolatedTeamsSettings += "AllowedDomains: $($TeamsExternalAccess.AllowedDomains)"
		}
		if ($ViolatedTeamsSettings.Count -igt 0)
		{
			$TeamsExternalAccess | Format-Table -AutoSize | Out-File "$path\CISMTm821-TeamsTenantFederationConfiguration.txt"
			$endobject = Build-CISMTm821 -ReturnedValue ($ViolatedTeamsSettings) -Status "FAIL" -RiskScore "8" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm821 -ReturnedValue "AllowFederatedUsers: False \n AllowedDomains: $($TeamsExternalAccess.AllowedDomains)" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm821 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm821