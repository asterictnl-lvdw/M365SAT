# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx611
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx611"
        ID               = "6.1.1"
        Title            = "(L1) Ensure 'AuditDisabled' organizationally is set to 'False'"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enforcing the default mailbox auditing ensures that auditing cannot be turned off intentionally or accidentally. Auditing mailbox actions allows for forensics and incident response (IR) teams to trace malicious activities, including unauthorized inbox access or tampering."
        Impact           = "Without mailbox auditing, it is difficult to trace unauthorized mailbox access or tampering, limiting the effectiveness of forensic investigations and incident response."
        Remediation	 	 = 'Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 180 -AuditAdmin $AuditAdmin -AuditDelegate $AuditDelegate -AuditOwner $AuditOwner; Set-OrganizationConfig -AuditDisabled $false'
        References       = @(
            @{ 'Name' = 'Manage mailbox auditing'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing?view=o365-worldwide" }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx611
{
	try
	{
		$MailboxAudit1 = Get-OrganizationConfig | Select-Object AuditDisabled
		if ($MailboxAudit1 -ne $false)
		{
			$MailboxAudit1 | Format-Table -AutoSize | Out-File "$path\CISMEx611-MailboxAuditOrganizationConfig.txt"
			$endobject = Build-CISMEx611 -ReturnedValue ("AuditDisabled: $($MailboxAudit1)") -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx611 -ReturnedValue ("AuditDisabled: $($MailboxAudit1)") -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx611 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx611
