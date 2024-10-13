# M365SAT
## The Official Microsoft 365 Security Assessment Tool
Written in PowerShell 7 and 5.1

Current Version: v2.4 alpha

Next Major Scheduled Release: Q1 (January 2025)

Next Release Version: v3.0

<div>
  <p align="center">
    <b>The Open-Source, Automated Microsoft 365 Security Assessment Tool</b> </br></br>
    <img src=x width="800"> 
  </p>
</div>


[![OS](https://img.shields.io/badge/OS-Windows-blue?style=flat&logo=Windows)](https://www.microsoft.com/en-gb/windows/?r=1)
[![Docker](https://img.shields.io/badge/Docker-Coming_Soon-red.svg?style=flat&logo=docker)](https://github.com/asterictnl-lvdw/365Inspect)


## 1. Intro

Nearly 50% of people worldwide rely on Microsoft 365 for their office work. Recognizing the growing security challenges, we have developed a unique technical solution tailored to address these concerns. Leveraging our expertise in Microsoft 365 security, we offer a comprehensive auditing solution that outperforms other security suites in assessing Microsoft 365 environments.

Introducing M365SAT, our newly released solution for Microsoft 365 and Azure environments. M365SAT safeguards your organization's Microsoft 365 tenant by identifying misconfigurations and mitigating potential risks.

Elevate your Microsoft 365 environment to unprecedented levels of security with our all-encompassing solution. Designed to protect your digital assets, M365SAT offers unmatched defense against evolving cyber threats, ensuring the security of your Microsoft 365 environment.

Our solution surpasses conventional security measures by meticulously analyzing approximately 300 distinct settings across the entire Microsoft 365 suite. From Teams to Exchange, SharePoint to Azure, every aspect of your ecosystem is thoroughly examined to identify and neutralize potential vulnerabilities. With this exhaustive approach, you can be confident that your digital infrastructure is comprehensively fortified.

M365SAT also examines your Microsoft 365 cloud settings, identifying deviations from the recommended CIS Benchmark configurations. This allows your organization to swiftly address potential security vulnerabilities and adhere to industry best practices. Beyond simply identifying issues, our solution provides remediation guidance through PowerShell scripts, simplifying the process and saving your IT team valuable time and effort.

## 2. About M365SAT
M365SAT is the evolution of its predecessor, 365Inspect+, which was released in 2022. The goal of M365SAT is to enable Security and Compliance Administrators to easily measure their environment's security posture.

Our tool is completely free and open-source, utilizing PowerShell to assess Microsoft 365 and Azure security configurations. With approximately 300 inspection points, it helps administrators reduce risky configurations and enhance security.

The core features of M365SAT include:

- **Automated Scanning**: Allows administrators to easily initiate the scanning process multiple times with minimal interaction, simplifying the assessment of security configurations.
- **Detailed Reporting**: Generates comprehensive HTML reports that provide insights into risks and rationales, helping administrators understand and address potential vulnerabilities.
- **Modularity**: Supports the creation of new scan modules to extend auditing capabilities. Instructions for developing custom modules can be found in the Examples section.


## 3. Installation
M365SAT can be installed in the following ways:

1. ***Install-Module M365SAT**: This option will be available in the next release.
2. **Downloading the latest release and using Import-Module**: Download the latest release and use the Import-Module command on the .psd1 file.
3. **Downloading the latest release and using the M365SATTester.ps1 file**: Download the latest release and run the M365SATTester.ps1 file.

### 3.1 Modules Installation

The following modules need to be installed in order to make M365SAT work:
-	Az
-	ExchangeOnlineManagement
-	Microsoft.Online.SharePoint.PowerShell
-	Microsoft.Graph
-	MicrosoftTeams
-	PoShLog

#### 3.1.1 Installation PowerShell 7.x.x (Windows)
PowerShell 7.x works with all the latest modules.
```
Install-Module -Name Az
Install-Module -Name ExchangeOnlineManagement
Install-Module -Name Microsoft.Online.SharePoint.PowerShell
Install-Module -Name Microsoft.Graph -AllowClobber -Force
Install-Module -Name Microsoft.Graph.Beta -AllowClobber -Force
Install-Module -Name MicrosoftTeams
Install-Module -Name PoShLog
```

#### 3.1.2 Installation PowerShell 5.1 (Windows)
Note: *Microsoft PowerShell 5.1 does not work properly with Az.Accounts 3.x.x or later, due to the new mechanism of authentication it conflicts with the ExchangeOnlineManagement modules. 2.19.0 is the latest working version with PowerShell 5.1.*
```
Install-Module -Name Az
Install-Module -Name ExchangeOnlineManagement -AllowClobber -Force
Install-Module -Name Microsoft.Online.SharePoint.PowerShell
Install-Module -Name Microsoft.Graph -AllowClobber -Force
Install-Module -Name Microsoft.Graph.Beta -AllowClobber -Force
Install-Module -Name MicrosoftTeams
Install-Module -Name PoShLog
```
1. Remove from here the `3.x.x` folder `C:\Program Files\WindowsPowerShell\Modules\Az.Accounts`
2. Run `Install-Module -Name Az.Accounts -RequiredVersion 2.19.0` to install the working PowerShell 5.1 version.

#### 3.1.3 Installation PowerShell 7.x.x (Linux)
*Note: This only works starting from v3.0!!!*
PowerShell 7 works with Linux, the only module that is not working straightforward is Microsoft Sharepoint. Thus will be replaced with PnP when using a Linux environment. For Linux you must follow the instructions below:
1. Run `sudo pwsh`
2. In the PowerShell SuperUser session run: `Install-Module -Name PSWSMan`
3. After installation run the command: `Install-WSMan`
4. You will be prompted to restart the PowerShell Session. Close the SuperUser session
5. Install all the modules down below:
```
Install-Module -Name Az
Install-Module -Name ExchangeOnlineManagement -AllowClobber -Force
Install-Module -Name PnP.PowerShell
Install-Module -Name Microsoft.Graph -AllowClobber -Force
Install-Module -Name Microsoft.Graph.Beta -AllowClobber -Force
Install-Module -Name MicrosoftTeams
Install-Module -Name PoShLog
```
Please keep in mind that there might be things that are not working. Feel free to report any bugs if found.!

### 3.2 Method 1: Install-Module
This method is coming in the next major release

## 4. How-To-Use
M365SAT is very easy to use. There are two main ways of executing M365SAT:

1. Using the M365SATTester.ps1 script
2. Executing Get-M365SATReport after importing the M365SAT modules

### 4.1 Necessary Privileges to Run
M365SAT requires fewer permissions compared to its predecessor, 365Inspect+. The following permissions are sufficient to run a successful audit:

- **Application Administrator**
- **SharePoint Administrator**
- **Exchange Administrator**
- **Global Reader**

These permissions have been tested with the latest version of M365SAT and are confirmed to be working as of July 20, 2023.

While it is no longer necessary to use a Global Administrator account, we recommend using one for the most comprehensive results.

Why do we need SharePoint Administrator permissions instead of lesser permissions?
Some settings can only be accessed when you have Administrator privileges. For more information, refer to the [Microsoft documentation on permissions](https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-reader).

### 4.1 Method 2: Running M365SATTester.ps1 (Recommended)
Make sure you RUN PowerShell as Administrator.
1. Clone the github repository or download the latest release at the releases section
2. cd C:\M365SAT; Get-ChildItem -Path .\ -Recurse | Unblock-File to unblock all files
3. Edit the M365SATTester.ps1 and replace -Username value with the username containing at least Global Reader and SharePoint Admin permissions.
4. Run M365SATTester.ps1 as Administrator the M365SAT.psm1 will be automatically imported and the assessment will be started!

### 4.2 Method 3: Import-Module M365SAT.psd1
Only use this method if you already installed all additional modules. Else step 5 will return a lot of errors! Use method 4 to install the required modules and return to this.
1. Clone the github repository or download the latest release at the releases section
2. cd C:\M365SAT; Get-ChildItem -Path .\ -Recurse | Unblock-File
3. Import-Module .\M365SAT.psd1
4. Wait until the process is finished, there might be some errors, because of not implemented solutions, you can safely ignore them.
5. See 5.2 for the execution command

### 4.3 Execution Commands
The execution of M365SAT can be done as followed:
```
Get-M365SATReport -OutPath <value> -reportType <HTML/CSV/XML> -Username <username> (-Password <password> -SkipChecks -SkipLogin -UseCustomModules -AllowLogging <Verbose/Debug/Info/Warning/Error/Fatal> -Modules <All/MicrosoftAzure/MicrosoftExchange/MicrosoftOffice365/MicrosoftSharepoint/MicrosoftTeams> )
```

#### 4.3.1 Mandatory Parameters

`-OutPath`: Specifies the output path for the exported report.

`-Username`: Mandatory. Enter the administrator username.

`-EnvironmentType`: Mandatory. Choose the environment to audit. Options include:

- M365: Microsoft 365
- AZURE: Azure
- CUSTOM: Custom Scripts in the /CUSTOM folder
- ALL: All environments

`-BenchmarkVersion`: Choose the benchmark version. Options include:

- 3: Benchmark version 3
- 2: Benchmark version 2
- LATEST: Latest available benchmark version

`-Modules`: Choose the modules to audit. Options include:

- Azure: Azure
- Exchange: Exchange
- Office365: Office 365
- Sharepoint: SharePoint
- Teams: Teams
- All: All modules

`-reportType`: Choose the report format. Options include:
- HTML: HTML
- CSV: CSV
- XML: XML
- CSMS: CSMS

Note: Only HTML fully works at the moment!

#### 4.3.2 Optional Parameters

`-Environment`: Specifies the environment type. Options include:

- Default: Standard environment
- USGovGCCHigh: U.S. Government Cloud Computing High
- USGovDoD: U.S. Government Department of Defense
- Germany: Germany region
- China: China region

`-Password`: Enter the administrator password. (Non-MFA Account)

`-LicenseMode`: Choose the benchmark license mode. Options include:

- E3: E3 license
- E5: E5 license
- All: All license modes

`-LicenseLevel`: Choose the benchmark level. Options include:

- L1: Level 1
- L2: Level 2
- All: All levels

`-AllowLogging`: Specifies the log message level. Options include:

- Verbose: Verbose logging
- Debug: Debug logging
- Info: Informational logging
- Warning: Warning logging
- Error: Error logging
- Fatal: Fatal logging

`-SkipChecks`: Skips module updates (experimental).

`-ExpirimentalMode`: Uses the experimental multi-threaded scanner (not recommended).

`-LocalMode`: Enables using the /inspectors folder instead of downloading the inspectors from GitHub.

`-SkipLogin`: Skips login if already authenticated (Not-Recommended).


### 4.4 Execution Examples
When using the standard command to execute a security assessment, you will be prompted with graphical login screens where you must log in sequentially.

`.\M365SATTester.ps1`

You can add the desired parameters to this script and run it as needed.

The execution time for M365SAT varies depending on the size and complexity of your organization. For organizations with a small number of user accounts and minimal configuration, the assessment should take no longer than 30 minutes. However, for organizations with more than 100 user accounts and custom configurations, the process may take longer. The duration depends on the organization’s size, complexity, and the extent of configurations.

## 5. Development
Unlike its predecessor, 365Inspect+, M365SAT is much more modular. It is designed to be easily expanded, allowing additional modules to be added or troubleshooted with ease when problems occur. We have organized multiple modules into directories, so when a user builds a new module, they can simply create a new directory and develop the module there.

### 5.1 Developing Inspector Modules
All Inspector modules are stored in the .\inspectors folder. You can use any earlier created module as a template to create a new module. Most of the modules are called:

*CSTM-[ProductFamily][ID].ps1*

For ProductFamily we have the following options at the moment:
-	Az (Microsoft Azure)
-	Ex (Microsoft Exchange)
-	O365 (Microsoft 365)
-	Sp (Microsoft Sharepoint)
-	Tms (Microsoft Teams)

ID Should be XXX-format e.g. 001, 002, 003, etc.

#### 5.1.1 Example
The following example is a Azure Inspector:

````
# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.1.0
# Product Family: Microsoft Azure
# Purpose: 
# Author: 

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz5111($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5111"
		FindingName	     = "CISMAz 5.1.1.1 - The Security Defaults are enabled on Azure Active Directory Tenant"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "4"
		Description	     = "Security defaults in Azure Active Directory (Azure AD) make it easier to be secure and help protect your organization. Security defaults contain preconfigured security settings for common attacks."
		Remediation	     = "Use the PowerShell Script to disable Security Defaults on Microsoft Azure Active Directory"
		PowerShellScript = '$body = $body = (@{"isEnabled"="false"} | ConvertTo-Json) ;Invoke-MgGraphRequest -Method PATCH https://graph.microsoft.com/beta/policies/identitySecurityDefaultsEnforcementPolicy -Body $body'
		DefaultValue	 = "True for tenants created later than 2019, False for tenants created before 2019"
		ExpectedValue    = "False"
		ReturnedValue    = "$findings"
		Impact		     = "4"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Security defaults in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults' },
			@{ 'Name' = 'Introducing security defaults'; 'URL' = 'https://techcommunity.microsoft.com/t5/microsoft-entra-azure-ad-blog/introducing-security-defaults/ba-p/1061414' })
	}
	return $inspectorobject
}

function Audit-CISMAz5111
{
	try
	{
		# Actual Script
		$SecureDefaultsState = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
		
		# Validation
		if ($SecureDefaultsState.isEnabled -eq $true)
		{
			$SecureDefaultsState | Format-Table -AutoSize | Out-File "$path\CISMAz5111-SecureDefaultEnforcementPolicy.txt"
			$finalobject = Build-CISMAz5111($SecureDefaultsState.isEnabled)
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
return Audit-CISMAz5111
````

Explanation of the Code Above:
1. Description: This section includes metadata about the program, such as the author, purpose, and version.
2. Error Handling: The script imports the PoShLog module to handle errors effectively.
3. Log Exporting: The $path = @($OutPath) line is used to ensure logs are saved to the correct folder if the script outputs logs.
4. Build Function: This function, Build-CISMAz5111, creates a custom PSObject to be returned if a violation is found by the inspector. It includes all necessary details for reporting.
5. Audit Function: The Audit-CISMAz5111 function contains the actual script that checks for any violations. If a violation is found, it creates a final object using the build function and returns it. The $findings parameter is passed to populate the PSCustomObject with information that can be reported.

Coding Tips:
1. Use Try & Catch: Always use try and catch blocks to handle errors. If an inspector encounters a problem, it will either return null or throw an exception. Error logs are saved in the same directory in a separate log folder.
2. Keep Code Efficient: Write concise code to avoid performance delays and to shorten the security assessment duration.
3. PowerShell Formatting: For well-formatted PowerShell scripts, consider using SAPIEN PowerShell Studio. It has a Format-Script function that helps format the script into readable sections, saving time in identifying issues.

### 5.2 Developing Additional Modules
You can develop additional modules and place them in different directories based on their purpose:

- Pre-check Modules: If you create a module for pre-check purposes, place it in the .\modules directory.
- Core Modules: If the module is an addition to the core functionality of the program, place it in the .\core directory.
- Output Parsers: If you develop a new method to output a report into a different file format, place the parser in the .\output directory.

## 6. About M35SAT's Security
As a Cyber Security Specialist, I take security very seriously. Please be aware that this program can execute various inspector modules, which means that potentially malicious scripts could be run if not properly managed. I am not responsible for any damage or loss of files that may occur in such cases.

To maintain a secure environment, please follow these best practices:

- **Use Least Privilege**: Audit with an account that has only the necessary privileges for the audit. Avoid using accounts with excessive permissions.
- **Write-Protect the Inspector Folder**: Ensure that the inspector folder is write-protected to prevent unauthorized access and to safeguard against malicious code being inserted.
- **Avoid Untrusted Scripts**: Do not place any PowerShell scripts in the inspector folder unless they are from a trusted source.

## 7. License
M365SAT is an open-source and free software released under the [MIT License](https://github.com/asterictnl-lvdw/M365SAT/blob/main/LICENSE). All the additional plug-ins and frameworks are also accompanied by the same MIT Licence. 

## 8. Special Thanks To...
* [Soteria-Security](https://github.com/soteria-security/365Inspect): For allowing me to create the fork on the predecessor!
* [AsterICTNL](https://www.asterict.nl): For allowing me to additionally develop this further
* [CISSecurity](https://www.cisecurity.org/cis-benchmarks/): For providing the Azure and Microsoft 365 benchmarks to make the inspector modules
* [cammurray](https://github.com/cammurray/orca): For the reporting structure
* [OfficeDev](https://github.com/OfficeDev/MCCA): For the reporting structure

## 9. Donation
Donations are always welcome! Feel free to Donate to me through PayPal!

## 10. Follow me
* [LinkedIn](https://www.linkedin.com/in/leonardo-van-de-weteringh/)