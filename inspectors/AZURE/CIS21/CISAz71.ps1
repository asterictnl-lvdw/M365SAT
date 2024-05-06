# Date: 25-1-2023071
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure an Azure Bastion Host Exists
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz71($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz71"
		FindingName	     = "CIS Az 7.1 - An Azure Bastion Host Does not Exist"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "The Azure Bastion service allows organizations a more secure means of accessing Azure Virtual Machines over the Internet without assigning public IP addresses to those Virtual Machines. The Azure Bastion service provides Remote Desktop Protocol (RDP) and Secure Shell (SSH) access to Virtual Machines using TLS within a web browser, thus preventing organizations from opening up 3389/TCP and 22/TCP to the Internet on Azure Virtual Machines. Additional benefits of the Bastion service includes Multi-Factor Authentication, Conditional Access Policies, and any other hardening measures configured within Azure Active Directory using a central point of access"
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'New-AzBastion -ResourceGroupName <resource group name> -Name <bastion name> -PublicIpAddress $publicip -VirtualNetwork $virtualNet -Sku "Standard" -ScaleUnit <integer>'
		DefaultValue	 = "By default, the Azure Bastion service is not configured."
		ExpectedValue    = "the Azure Bastion service is configured."
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'What is Azure Bastion?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/bastion/bastion-overview#sku' })
	}
	return $inspectorobject
}

function Audit-CISAz71
{
	try
	{
		
		$Violation = @()
		$AzResources = Get-AzResource | Select-Object ResourceGroupName -Unique
		foreach ($AzResource in $AzResources){
			$AzureBastions = Get-AzBastion -ResourceGroupName $AzResource.ResourceGroupName
			if (-not [String]::IsNullOrEmpty($AzureBastions)){
				foreach ($AzureBastion in $AzureBastions){

				}
			}else
			{
				$Violation += $AzResource.ResourceGroupName
			}

		}
		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz71($Violation)
			return $finalobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISAz71