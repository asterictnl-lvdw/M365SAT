#This function is only called when ThreadJobs are existing to enhance performance.
function Invoke-M365SATChecksV2
{
	Param ($inspectors,
		$Directory)
	
	$jobs = @()
	$findings = @()
	
	$startdate = (Get-Date)
	
	[scriptblock]$script = {
		
		Param ($checker,
			$Folder)
		
		# Invoke the actual inspector module and store the resulting list of insecure objects.
		$finding = Invoke-Expression -Command "$($checker.FullName)"
		
		# Add the finding to the list of all findings. But do check if the Finding is not null, else it is useless to add.
		if ($finding -ne $null)
		{
			Write-Host "$(Get-Date): $($checker.Name) found a Violation!" -ForegroundColor Red
			return $finding
		}
		else
		{
			Write-Host "$(Get-Date): $($checker.Name) did not found any violation!" -ForegroundColor Green
			return $null
		}
	}
	
	Write-Host "Executing All Inspectors..."
	foreach ($inspector in $inspectors.Inspectors)
	{
		$jobs += Start-ThreadJob -Name $inspector.Name -ArgumentList ($inspector, $Directory) -ScriptBlock $script
	}
	
	# Getting Job results once a job is done iterating through the list and removing the job when results are stored in the object.
	while ((Get-Job).Count -igt 0)
	{
		
		$completed = Get-Job | Where-Object { $_.State -eq "Completed" -and $_.HasMoreData -eq $true }
		foreach ($job in $completed)
		{
			$i = 0
			$output = Receive-Job -Name $job.Name
			if ([string]::IsNullOrEmpty($output))
			{
				Remove-Job -Job $job -Force
			}
			else
			{
				$findings += $output
				Remove-Job -Job $job -Force
			}
		}
		#This to disallow to stress the CPU with the constant while loop. The loop will continue anyway until all jobs are removed (completed).
		$i++ #Increment the value by 1 eachtime the loop is activated as safety measure
		Start-Sleep -Seconds $i
	}
	
	Get-Job | Remove-Job -Force #To remove all jobs and free up memory
	
	$endDate = (Get-Date)
	
	$executeinspectorsobject = New-Object PSObject -Property @{
		Findings	    = $findings
		StartDate	    = $startdate
		EndDate		    = $endDate
		Inspectors	    = $inspectors.Inspectors.Name #$inspectorList
		InspectorsCount = $inspectors.Inspectors.Name.Count #$inspectorList.Count
	}
	return $executeinspectorsobject
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

