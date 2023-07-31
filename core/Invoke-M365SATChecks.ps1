function Invoke-M365SATCustomChecks
{
	
	Param ($inspectors,
		$Directory)
	
	$startdate = (Get-Date)
	
	# Maintain a list of all findings, beginning with an empty Array.
	$findings = @()
	$inspectorList = @()
	$inspectorListFullName = @()
	
	# Convert the Object to an normalized Array 
	$inspectors.Name | ForEach-Object { $inspectorList += $_ }
	$inspectors.FullName | ForEach-Object { $inspectorListFullName += $_ }
	
	# For every inspector the user wanted to run...
	for ($i = 0; $i -lt $inspectors.FullName.length; $i++)
	{
		<#try
		{#>
		Write-Host "$(Get-Date): Executing Inspector: $($inspectors.Name[$i])"
		
		# Invoke the actual inspector module and store the resulting list of insecure objects.
		$finding = Invoke-Expression $inspectors.FullName[$i]
		# Add the finding to the list of all findings. But do check if the Finding is not null, else it is useless to add.
		if ($finding -ne $null)
		{
			Write-Host "Violation Found!" -ForegroundColor Red
			$findings += $finding
		}
		else
		{
			Write-Host "Did not found any violation!" -ForegroundColor Green
		}
		<#}
		catch
		{
			Write-ErrorLog "An Error Occured!"
		}#>
	}
	$endDate = (Get-Date)
	
	$executeinspectorsobject = New-Object PSObject -Property @{
		Findings	    = $findings
		StartDate	    = $startdate
		EndDate		    = $endDate
		Inspectors	    = $inspectorList
		InspectorsCount = $inspectorList.Count #$inspectors.Name.length
	}
	return $executeinspectorsobject
}

function Invoke-M365SATChecks
{
	Param ($inspectors,
		$Directory)
	
	$startdate = (Get-Date)
	
	# Maintain a list of all findings, beginning with an empty list.
	$findings = @()
	$inspectorList = @()
	$inspectorListFullName = @()
	
	$inspectors.Name | ForEach-Object { $inspectorList += $_ }
	$inspectors.FullName | ForEach-Object { $inspectorListFullName += $_ }
	
	# For every inspector the user wanted to run...
	foreach ($inspector in $inspectors) # Just a dummy to check if inspector List is ingested correctly
	{
		<#try
		{#>
		Write-Host "Executing Inspector: $($inspector.Name)..."
		
		# Invoke the actual inspector module and store the resulting list of insecure objects.
		$finding = Invoke-Expression -Command "$($inspector.FullName)"
		
		# Add the finding to the list of all findings. But do check if the Finding is not null, else it is useless to add.
		if ($finding -ne $null)
		{
			Write-Host "Violation Found!" -ForegroundColor Red
			$findings += $finding
		}
		else
		{
			Write-Host "Did not found any violation!" -ForegroundColor Green
		}
		<#}
		catch
		{
			Write-ErrorLog "An Error Occured!"
		}#>
		
	}
	$endDate = (Get-Date)
	
	$executeinspectorsobject = New-Object PSObject -Property @{
		Findings	    = $findings
		StartDate	    = $startdate
		EndDate		    = $endDate
		Inspectors	    = $inspectorList
		InspectorsCount = $inspectorList.Count #$inspectors.Name.length
	}
	return $executeinspectorsobject
}

