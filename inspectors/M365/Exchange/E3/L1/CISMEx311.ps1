# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx311
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx311"
        ID               = "3.1.1"
        Title            = "(L1) Ensure Microsoft 365 audit log search is Enabled"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Audit log search in the Microsoft Purview compliance portal helps organizations enhance security, meet compliance requirements, respond to incidents, and gain operational insights. When the audit log search is disabled, the ability to track and analyze activities within Microsoft 365 is significantly limited, increasing the risk of unmonitored or unauthorized actions."
        Impact           = "Disabling audit log search reduces visibility into user and admin activities, making it challenging to detect and investigate potential security incidents or compliance issues."
        Remediation 	 = 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true'
        References       = @(
            @{ 'Name' = 'Enable/Disable the Audit Log'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-log-enable-disable?view=o365-worldwide" }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx311
{
	try
	{
		$AuditLog = Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
		
		if ($AuditLog.UnifiedAuditLogIngestionEnabled -ne $True)
		{
			$AuditLog | Format-Table -AutoSize | Out-File "$path\CISMEx311-UnifiedAuditLogIngestion.txt"
			$endobject = Build-CISMEx311 -ReturnedValue ($AuditLog.UnifiedAuditLogIngestionEnabled) -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx311 -ReturnedValue ($AuditLog.UnifiedAuditLogIngestionEnabled) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx311 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx311