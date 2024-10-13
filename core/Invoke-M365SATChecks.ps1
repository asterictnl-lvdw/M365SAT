function Invoke-M365SATChecksP7{
 <# This will be de new version of the checks with parallelization when supported properly#>
}

#The normal regular custom checks
function Invoke-M365SATCustomChecks
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
		if ($finding -ne $null)
		{
			Write-Host "$(Get-Date): $($inspector.Name) found a Violation!" -ForegroundColor Red
			$findings += $finding
		}
		else
		{
			Write-Host "$(Get-Date): $($inspector.Name) did not found any violation!" -ForegroundColor Green
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

#The actual script that should invoke only when the inspectors are downloaded from the original repository and not want to be saved online
function Invoke-M365SATChecks
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
		if ($finding -ne $null)
		{
			Write-Host "$(Get-Date): $($inspector.Name) found a Violation!" -ForegroundColor Red
			$findings += $finding
		}
		else
		{
			Write-Host "$(Get-Date): $($inspector.Name) did not found any violation!" -ForegroundColor Green
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

