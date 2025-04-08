function Invoke-M365SATChecksP7{
 <# This will be de new version of the checks with parallelization when supported properly#>
}

function Invoke-M365SATChecksNew
{
	
	Param ($inspectors,
		$Directory)
	
	$startdate = (Get-Date)
	
	# Maintain a list of all findings, beginning with an empty Array.
	$findings = @()
	
	foreach ($inspector in $inspectors.Inspectors)
	{
		Write-Host "$(Get-Date): Running $($inspector.Name)..." -ForegroundColor Yellow
		# Invoke the actual inspector module and store the resulting list of insecure objects.
		$finding = Invoke-Expression -Command "$($inspector.FullName)"
		
		# Add the finding to the list of all findings. But do check if the Finding is not null, else it is useless to add.
		if ($finding.Status -eq "FAIL")
		{
			Write-Host "$(Get-Date): $($inspector.Name) Status: $($finding.Status)" -ForegroundColor Red
			$findings += $finding
		}
		elseif ($finding.Status -eq "PASS")
		{
			Write-Host "$(Get-Date): $($inspector.Name) Status: $($finding.Status)" -ForegroundColor Green
			$findings += $finding
		}
		else 
		{
			Write-Host "$(Get-Date): $($inspector.Name) Status: $($finding.Status)" -ForegroundColor Gray
			$findings += $finding
		}
	}
	
	$endDate = (Get-Date)
	
	$executeinspectorsobject = New-Object PSObject -Property @{
		Findings	    = $findings
		StartDate	    = $startdate
		EndDate		    = $endDate
		Inspectors	    = $inspectors.Inspectors.Name
		InspectorsCount = $inspectors.Inspectors.Name.Count #$inspectors.Name.length
	}
	return $executeinspectorsobject
}

