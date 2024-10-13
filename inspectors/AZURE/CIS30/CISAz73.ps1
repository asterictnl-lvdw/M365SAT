# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that UDP access from the Internet is evaluated and restricted
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz73($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz73"
		FindingName	     = "CIS Az 7.3 - UDP access from the Internet is not evaluated and restricted"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "6"
		Description	     = "The potential security problem with broadly exposing UDP services over the Internet is that attackers can use DDoS amplification techniques to reflect spoofed UDP traffic from Azure Virtual Machines. The most common types of these attacks use exposed DNS, NTP, SSDP, SNMP, CLDAP and other UDP-based services as amplification sources for disrupting services of other machines on the Azure Virtual Network or even attack networked devices outside of Azure."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = '-'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Disabled"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "2"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Secure your critical Azure service resources to only your virtual networks'; 'URL' = 'https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices#secure-your-critical-azure-service-resources-to-only-your-virtual-networks' },
		@{ 'Name' = 'Azure DDoS Protection fundamental best practices'; 'URL' = 'https://learn.microsoft.com/en-us/azure/ddos-protection/fundamental-best-practices' },
		@{ 'Name' = 'NS-1: Establish network segmentation boundaries'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-1-establish-network-segmentation-boundaries' },
		@{ 'Name' = 'ExpressRoute documentation'; 'URL' = 'https://learn.microsoft.com/en-us/azure/expressroute/' },
		@{ 'Name' = 'Tutorial: Create a site-to-site VPN connection in the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/vpn-gateway/tutorial-site-to-site-portal' },
		@{ 'Name' = 'Configure server settings for P2S VPN Gateway certificate authentication'; 'URL' = 'https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-howto-point-to-site-resource-manager-portal' })
	}
	return $inspectorobject
}

function Audit-CISAz73
{
	try
	{
		
		$Violation = @()
		$azNsgs = Get-AzNetworkSecurityGroup
		$udpports = @(53,123,173,389,1900)
		$regexudp = [string]::Join('|',$udpports) 
		foreach ($azNsg in $azNsgs){
			$SecurityRuleConfig = Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $azNsg | Where-Object { 
				$_.Access -contains "Allow" -and
				($_.DestinationPortRange -match $regexudp -or
				$_.DestinationPortRange -contains '*') -and 
				$_.Direction -contains "Inbound" -and 
				($_.Protocol -contains "UDP" -or 
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
			$finalobject = Build-CISAz73($Settings.enabled)
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
return Audit-CISAz73