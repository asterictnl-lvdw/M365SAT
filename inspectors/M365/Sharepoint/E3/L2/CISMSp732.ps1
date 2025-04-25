# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMSp732
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMSp732"
        ID               = "7.3.2"
        Title            = "(L2) Ensure OneDrive sync is restricted for unmanaged devices"
        ProductFamily    = "Microsoft SharePoint"
		DefaultValue	 = "TenantRestrictionEnabled False \n AllowedDomainList : {}"
		ExpectedValue    = "TenantRestrictionEnabled True \n AllowedDomainList : 1 domain"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Unmanaged devices pose a risk since their security cannot be verified through existing security policies, brokers, or endpoint protection. Allowing users to sync data to these devices takes that data out of the control of the organization, increasing the risk of intentional or accidental data leaks. Note: This setting is only applicable to Active Directory domains when operating in a hybrid configuration. It does not apply to Azure AD domains. For devices joined only to Azure AD, consider using a Conditional Access Policy."
        Impact           = "Enabling this feature will prevent users from using the OneDrive for Business Sync client on devices that are not joined to the domains that were defined."
        Remediation		 = 'Set-SPOTenantSyncClientRestriction -Enable -DomainGuids "786548DD-877B-4760-A749-6B1EFBC1190A; 877564FF-877B-4760-A749-6B1EFBC1190A"'
        References       = @(
            @{ 'Name' = 'Restrict sharing of SharePoint and OneDrive content by domain'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/restricted-domains-sharing' },
            @{ 'Name' = 'Allow syncing only on computers joined to specific domains'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/allow-syncing-only-on-specific-domains' }
        )
    }
    return $inspectorobject
}

function Audit-CISMSp732
{
	Try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			$ShareSettings = Get-PnPTenantSyncClientRestriction
			If ($ShareSettings.TenantRestrictionEnabled -ne $true)
			{
				$ShareSettings | Format-Table -AutoSize | Out-File "$path\CISMSp732-SPOTenant.txt"
				$endobject = Build-CISMSp732 -ReturnedValue ($ShareSettings.TenantRestrictionEnabled) -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp732 -ReturnedValue ($ShareSettings.TenantRestrictionEnabled) -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
		else
		{
			$ShareSettings = Get-SPOTenantSyncClientRestriction
			If ($ShareSettings.TenantRestrictionEnabled -ne $true)
			{
				$ShareSettings | Format-Table -AutoSize | Out-File "$path\CISMSp732-SPOTenant.txt"
				$endobject = Build-CISMSp732 -ReturnedValue ($ShareSettings.TenantRestrictionEnabled) -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp732 -ReturnedValue ($ShareSettings.TenantRestrictionEnabled) -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
	}
	catch
	{
		$endobject = Build-CISMSp732 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}

return Audit-CISMSp732


