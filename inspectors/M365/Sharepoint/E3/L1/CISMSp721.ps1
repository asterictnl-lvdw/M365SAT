# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp721
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMSp721"
        ID               = "7.2.1"
        Title            = "(L1) Ensure modern authentication for SharePoint applications is required"
        ProductFamily    = "Microsoft SharePoint"
        DefaultValue     = "True (Apps that don't use modern authentication are allowed)"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Modern authentication provides strong authentication mechanisms, such as multifactor authentication. Disabling legacy authentication ensures that only secure, modern methods are used to access SharePoint, reducing vulnerabilities."
        Impact           = "Implementation of modern authentication for SharePoint will require users to authenticate to SharePoint using modern authentication. This may cause a minor impact to typical user behavior. This may also prevent third-party apps from accessing SharePoint Online resources. Also, this will also block apps using the SharePointOnlineCredentials class to access SharePoint Online resources."
        Remediation = 'Set-SPOTenant -LegacyAuthProtocolsEnabled $false -LegacyBrowserAuthProtocolsEnabled $false'
        References       = @(
            @{ 'Name' = 'Set-SPOTenant Documentation'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/sharepoint-online/set-spotenant?view=sharepoint-ps' }
        )
    }
    return $inspectorobject
}

function Audit-CISMSp721
{
	try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-PnPTenant | Format-Table LegacyAuthProtocolsEnabled, LegacyBrowserAuthProtocolsEnabled
			if ($SharepointSetting.LegacyAuthProtocolsEnabled -ne $False)
			{
				$AffectedOptions += "LegacyAuthProtocolsEnabled: True"
			}
			if ($SharepointSetting.LegacyBrowserAuthProtocolsEnabled -ne $false)
			{
				$AffectedOptions += "LegacyBrowserAuthProtocolsEnabled: True"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp721-SPOTenant.txt"
				$endobject = Build-CISMSp721 -ReturnedValue $AffectedOptions -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp721 -ReturnedValue "LegacyAuthProtocolsEnabled: False \n LegacyBrowserAuthProtocolsEnabled: False" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
		else
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-SPOTenant | Format-Table LegacyAuthProtocolsEnabled, LegacyBrowserAuthProtocolsEnabled
			if ($SharepointSetting.LegacyAuthProtocolsEnabled -ne $False)
			{
				$AffectedOptions += "LegacyAuthProtocolsEnabled: True"
			}
			if ($SharepointSetting.LegacyBrowserAuthProtocolsEnabled -ne $false)
			{
				$AffectedOptions += "LegacyBrowserAuthProtocolsEnabled: True"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp721-SPOTenant.txt"
				$endobject = Build-CISMSp721 -ReturnedValue $AffectedOptions -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp721 -ReturnedValue "LegacyAuthProtocolsEnabled: False \n LegacyBrowserAuthProtocolsEnabled: False" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
	}
	catch
	{
		$endobject = Build-CISMSp721 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMSp721