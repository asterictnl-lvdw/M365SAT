# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that HTTP(S) access from the Internet is evaluated and restricted
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz74($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz74"
		FindingName	     = "CIS Az 7.4 - HTTP(S) access from the Internet is not evaluated and restricted"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "6"
		Description	     = "The potential security problem with using HTTP(S) over the Internet is that attackers can use various brute force techniques to gain access to Azure resources. Once the attackers gain access, they can use the resource as a launch point for compromising other resources within the Azure tenant."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = '-'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Disabled"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "2"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'NS-1: Establish network segmentation boundaries'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-1-establish-network-segmentation-boundaries' },
		@{ 'Name' = 'ExpressRoute documentation'; 'URL' = 'https://learn.microsoft.com/en-us/azure/expressroute/' },
		@{ 'Name' = 'Tutorial: Create a site-to-site VPN connection in the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/vpn-gateway/tutorial-site-to-site-portal' },
		@{ 'Name' = 'Configure server settings for P2S VPN Gateway certificate authentication'; 'URL' = 'https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-point-to-site-resource-manager-portal' })
	}
	return $inspectorobject
}

function Audit-CISAz74
{
	try
	{
		
		$Violation = @()
		$azNsgs = Get-AzNetworkSecurityGroup
		foreach ($azNsg in $azNsgs){
			$SecurityRuleConfig = Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $azNsg | Where-Object { 
				$_.Access -contains "Allow" -and
				($_.DestinationPortRange -contains 443 -or
				$_.DestinationPortRange -contains 80 -or
				$_.DestinationPortRange -contains '*') -and 
				$_.Direction -contains "Inbound" -and 
				($_.Protocol -contains "TCP" -or 
				$_.Protocol -contains '*') -and
				($_.SourceAddressPrefix -contains '*' -or 
				$_.SourceAddressPrefix -contains "0.0.0.0" -or 
				$_.SourceAddressPrefix -contains "<nw>/0" -or 
				$_.SourceAddressPrefix -contains "/0" -or 
				$_.SourceAddressPrefix -contains "internet" -or 
				$_.SourceAddressPrefix -contains "any")
				if (-not [string]::IsNullOrEmpty($SecurityRuleConfig)){
					$Violation += $azNsg.Name
				}
			}
		}
		
		
		if ($AffectedSettings.count -ne 0)
		{
			$finalobject = Build-CISAz74($Settings.enabled)
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
return Audit-CISAz74