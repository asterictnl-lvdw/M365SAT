# . "..\M365SAT.psm1"
function Get-M365SATCSVReport
{
	Param ($object,
		$OutPath,
		$inspectors)

        # Initalize Dates
        $StartDate = $object.StartDate
        $ReportDate = $object.EndDate

        # Sort all findings
        $SortedFindings = $object.Findings | Sort-Object -Descending { Switch -Regex ($_.RiskRating) { 'Critical' { 1 }	'High' { 2 } 'Medium' { 3 }	'Low' { 4 }	'Informational' { 5 } }; $_.RiskScore }

        #CompanyName
        try{
            # Microsoft Graph Variant
            $CompanyName = (Get-MgOrganization).DisplayName
            $TenantName = (((Get-MgOrganization).VerifiedDomains |  Where-Object { ($_.Name -like "*.onmicrosoft.com") -and ($_.Name -notlike "*mail.onmicrosoft.com") }).Name -split '.onmicrosoft.com')[0]
        }catch{
            # Microsoft Exchange Variant
            $CompanyName = (Get-AcceptedDomain | Where-Object { $_.Default -eq 'True' }).DomainName
            $TenantName = ((Get-AcceptedDomain |  Where-Object {  { $_.Default -eq 'True' } -and ($_.DomainName -like "*.onmicrosoft.com") -and ($_.DomainName -notlike "*mail.onmicrosoft.com") }).DomainName -split '.onmicrosoft.com')[0]
        }

        # Initialize Empty List
        $FinalFindings = @()

        # Create a count of findings
        $FindingCounter = 0

        foreach ($finding in $SortedFindings){
            if ($null -NE $finding.ReturnedValue){
                $FindingCounter += 1

                # Create empty list for References
                $refs = @()
                foreach ($Reference in $SortedFindings.References){
                    $refs += "$($Reference.Name) : $($Reference.URL)"
                }
            }
            $result = [PSCustomObject]@{
                ID			     = $finding.ID
                FindingName	     = $finding.FindingName
                ProductFamily    = $finding.ProductFamily
                RiskScore	     = $finding.RiskScore
                Description	     = $finding.Description
                Remediation	     = $finding.Remediation
                PowerShellScript = $finding.PowerShellScript
                DefaultValue	 = $finding.DefaultValue
                ExpectedValue    = $finding.ExpectedValue
                ReturnedValue    = $finding.ReturnedValue
                Impact		     = $finding.Impact
                Likelihood	     = $finding.Likelihood
                RiskRating	     = $finding.RiskRating
                Priority		 = $finding.Priority
                References	     = $refs
                'Remediation Status' = " "
                'Start Date'         = " "
                'Completion Date'    = " "
                'Notes'              = " "
            }
            $FinalFindings += $result
        }
        $FinalFindings | Export-Csv "$OutPath\$($TenantName)_$(Get-Date -Format "yyyyMMddhhmmss").csv" -Delimiter '^' -NoTypeInformation -Append -Force
}