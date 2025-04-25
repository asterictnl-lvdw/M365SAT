# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm811
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm811"
        ID               = "8.1.1"
        Title            = "(L2) Ensure external file sharing in Teams is enabled for only approved cloud storage services"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "All True"
        ExpectedValue    = "All False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Ensuring that only authorized cloud storage providers are accessible from Teams will help to dissuade the use of non-approved storage providers."
        Impact           = "The impact associated with this change is highly dependent upon current practices in the tenant. If users do not use other storage providers, then minimal impact is likely. However, if users do regularly utilize providers outside of the tenant this will affect their ability to continue to do so."
        Remediation      = 'Set-CsTeamsClientConfiguration -AllowGoogleDrive $false -AllowShareFile $false -AllowBox $false -AllowDropBox $false -AllowEgnyte $false'
        References       = @(
            @{ 'Name' = 'Manage Skype for Business Online with PowerShell'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/enterprise/manage-skype-for-business-online-with-microsoft-365-powershell?view=o365-worldwide" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm811
{
	try
	{
		$ViolatedTeamsSettings = @()
		$TeamsExternalSharing = Get-CsTeamsClientConfiguration | Select-Object AllowDropbox, AllowBox, AllowGoogleDrive, AllowShareFile, AllowEgnyte
		if ($TeamsExternalSharing.AllowDropbox -eq $True)
		{
			$ViolatedTeamsSettings += "AllowDropbox: True"
		}
		if ($TeamsExternalSharing.AllowBox -eq $True)
		{
			$ViolatedTeamsSettings += "AllowBox: True"
		}
		if ($TeamsExternalSharing.AllowGoogleDrive -eq $True)
		{
			$ViolatedTeamsSettings += "AllowGoogleDrive: True"
		}
		if ($TeamsExternalSharing.AllowShareFile -eq $True)
		{
			$ViolatedTeamsSettings += "AllowShareFile: True"
		}
		if ($TeamsExternalSharing.AllowFederatedUsers -eq $True)
		{
			$ViolatedTeamsSettings += "AllowFederatedUsers: True"
		}
		if ($TeamsExternalSharing.AllowEgnyte -eq $True)
		{
			$ViolatedTeamsSettings += "AllowEgnyte: True"
		}
		
		if ($ViolatedTeamsSettings.Count -igt 0)
		{
			$TeamsExternalSharing | Format-Table -AutoSize | Out-File "$path\CISMTm811-TeamsClientConfiguration.txt"
			$endobject = Build-CISMTm811 -ReturnedValue ($ViolatedTeamsSettings) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm811 -ReturnedValue "AllowDropbox: False \n AllowBox: True \n AllowGoogleDrive: True \n AllowShareFile: True \n AllowFederatedUsers: True \n AllowEgnyte: True" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm811 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm811