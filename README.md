# M365SAT
## The Official Microsoft 365 Security Assessment Tool
Written in PowerShell 7 and 5.1

Current Version: v3.0 beta

Next Scheduled Release: May 2025

Next Release Version: v3.1

<div>
  <p align="center">
    <b>The Open-Source, Automated Microsoft 365 Security Assessment Tool</b> </br></br>
    <img src="https://github.com/CompliantSec/M365SAT/blob/alpha/modules/M365SAT-CMD-Logo.png" width="800"> 
  </p>
</div>
<br>

Compatible With:

[![Windows](https://custom-icon-badges.demolab.com/badge/Windows-0078D6?logo=windows11&logoColor=white)](https://www.microsoft.com/en-gb/windows/?r=1)
[![Linux](https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black)](https://linux.org/)
[![macOS](https://img.shields.io/badge/macOS-000000?logo=apple&logoColor=F0F0F0)](https://www.apple.com/)
[![Docker](https://img.shields.io/badge/Docker-Coming_Soon-red.svg?style=flat&logo=docker)](https://www.docker.com/)

## 0. Important Notice from CompliantSec

In the next upcoming version I will be releasing some bugfixes regarding issues with M365SAT. Another thing which is important to note is that I will remove the v4.0.0 Inspectors from the GitHub repository. This has been a hard decision as I want to keep the tool as up-to-date and accessible as possible, but the time I put in it does not reflect back to what I get in return. Thus, we have decided from starting from the next version we commercialize the inspectors (v4.0.0 and later) in the form of *As a Service* which CompliantSec can provide for their customers. In the meantime you can use the v4.0.0 of M365 free of charge. Thank you all for your support. 

You can visit our website here to view our services: [CompliantSec](https://compliantsec.nl/)

## 1. Intro

Nearly 50% of people worldwide rely on Microsoft 365 for their office work. Recognizing the growing security challenges, we have developed a unique technical solution tailored to address these concerns. Leveraging our expertise in Microsoft 365 security, we offer a comprehensive auditing solution that outperforms other security suites in assessing Microsoft 365 environments.

Introducing M365SAT, our newly released solution for Microsoft 365 and Azure environments. M365SAT safeguards your organization's Microsoft 365 tenant by identifying misconfigurations and mitigating potential risks.

Elevate your Microsoft 365 environment to unprecedented levels of security with our all-encompassing solution. Designed to protect your digital assets, M365SAT offers unmatched defense against evolving cyber threats, ensuring the security of your Microsoft 365 environment.

Our solution surpasses conventional security measures by meticulously analyzing approximately 300 distinct settings across the entire Microsoft 365 suite. From Teams to Exchange, SharePoint to Azure, every aspect of your ecosystem is thoroughly examined to identify and neutralize potential vulnerabilities. With this exhaustive approach, you can be confident that your digital infrastructure is comprehensively fortified.

M365SAT also examines your Microsoft 365 cloud settings, identifying deviations from the recommended CIS Benchmark configurations. This allows your organization to swiftly address potential security vulnerabilities and adhere to industry best practices. Beyond simply identifying issues, our solution provides remediation guidance through PowerShell scripts, simplifying the process and saving your IT team valuable time and effort.

## 2. About M365SAT
M365SAT is the evolution of its predecessor, 365Inspect+, which was released in 2022. The goal of M365SAT is to enable Security and Compliance Administrators to easily measure their environment's security posture. In 2025 the tool got commercialized by CompliantSec which is owned by the same person.

Our tool itself is completely free. The inspector scripts will require an additional charge to assess Microsoft 365 and Azure security configurations. CompliantSec can audit more than 200 inspection points on both Microsoft 365 and Azure environments, which helps administrators reduce risky configurations and enhance security.

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
-	Microsoft.Online.SharePoint.PowerShell (for PowerShell 5 ONLY!)
- PnP.PowerShell (for PowerShell 7 ONLY!)
-	Microsoft.Graph
- Microsoft.Graph.Beta
-	MicrosoftTeams
-	PoShLog

#### 3.1.1 Installation Windows (PowerShell 5/7)
Note 1: *It is required to replace the Az.Account module with version 2.19.0 in order to make ExchangeOnlineManagement work with Az PowerShell modules. Versions 2.19.0 or later do not work together and generate errors!*

Note 2: *Windows PowerShell 7 does not work properly with the latest ExchangeOnlineManagement cmdlet as it generate errors when authenticating. On PowerShell 5 it works fine, but on PowerShell 7 it returns that a module cannot be loaded, thus it is recommended to use version 3.6.0 until further notice.*

```
Install-Module -Name Az
Get-InstalledModule -Name Az.Accounts | Uninstall-Module
Install-Module -Name Az.Accounts -RequiredVersion 2.19.0
Install-Module -Name ExchangeOnlineManagement -RequiredVersion 3.6.0
Install-Module -Name PnP.PowerShell #PowerShell 7 Only
Install-Module -Name Microsoft.Online.SharePoint.PowerShell #PowerShell 5 Only
Install-Module -Name Microsoft.Graph -AllowClobber -Force
Install-Module -Name Microsoft.Graph.Beta -AllowClobber -Force
Install-Module -Name MicrosoftTeams
Install-Module -Name PoShLog
```

If you are using Microsoft PowerShell 5 you can replace `Install-Module -Name PnP.PowerShell` with `Install-Module -Name Microsoft.Online.SharePoint.PowerShell`

If you are not able to remove Az.Account due warnings or errors you can 
1. Close all PowerShell sessions
2. Remove the latest version from the folder `C:\Program Files\WindowsPowerShell\Modules\Az.Accounts`
3. Open a new Administrative PowerShell 5 session.
4. Run `Install-Module -Name Az.Accounts -RequiredVersion 2.19.0` to install the working PowerShell 5.1 version.
5. Try to run the M365SAT-Tester.ps1 to check if everything is working properly.


#### 3.1.3 Installation PowerShell 7.x.x (Linux/Unix)
PowerShell 7 works with Linux and MacOSX, For Linux or MacOSX must follow the instructions below:
1. Run `sudo pwsh`
2. In the PowerShell SuperUser session run: `Install-Module -Name PSWSMan`
3. After installation run the command: `Install-WSMan`
4. You will be prompted to restart the PowerShell Session. Close the SuperUser session
5. Install all the modules down below:

```
Install-Module -Name Az
Install-Module -Name ExchangeOnlineManagement
Install-Module -Name PnP.PowerShell
Install-Module -Name Microsoft.Graph -AllowClobber -Force
Install-Module -Name Microsoft.Graph.Beta -AllowClobber -Force
Install-Module -Name MicrosoftTeams
Install-Module -Name PoShLog
```
Linux has been fully tested and reported working with the latest modules available as stated March 7th 2025.

## 4. How-To-Use
M365SAT can be run the following ways

1. M365SATTester.ps1 (Recommended)
2. Get-M365SATReport (Not-Recommended)

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

### 4.1 Method 1: Running M365SATTester.ps1 (Recommended)
*This process is fully automated as you only need to change the within the M365SATTester.ps1*
1. Clone the GitHub repository by `git clone https://github.com/CompliantSec/M365SAT`
2. Edit the M365SATTester.ps1 and replace the *$ScriptConfig* values to your own preference.
3. Run M365SATTester.ps1 with Administrative privileges in PowerShell.

### 4.2 Method 2: Import-Module M365SAT.psd1 (Not Recommended)
*Note: This method has reported some issues as it is recommended to use the M365SATTester.ps1 and change the values there on what you wish to audit*
1. Clone the github repository or download the latest release at the releases section
2. Import-Module .\M365SAT.psd1.
3. Wait until the process is finished, there might be some errors, because of not implemented solutions, you can safely ignore them.
4. See 4.3 for the execution command.

### 4.3 Execution Commands Information
The execution of M365SAT can be done as followed:
```
Get-M365SATReport -OuthPath -Username "" -EnvironmentType <M365/AZURE/CUSTOM/ALL> -Modules <Azure/Exchange/Office365/Sharepoint/Teams/All> -LicenseMode <E3/E5/All> -LicenseLevel <L1/L2/All> -ReportType <CSV/HTML> -AllowLogging -LocalMode -SkipChecks
```

#### 4.3.1 Mandatory Parameters

`-OutPath`: Specifies the output path for the exported report. (Linux or Windows path required)

`-Username`: Mandatory. Enter the username containing the respective permissions (See 4.1 for required permissions).

`-EnvironmentType`: Mandatory. Choose the environment to audit. Options include:

- M365: Microsoft 365
- AZURE: Azure
- CUSTOM: Custom Scripts in the /CUSTOM folder
- ALL: All environments
*Default is All*

`-Modules`: Choose the modules to audit. Options include:

- Azure: Azure
- Exchange: Exchange
- Office365: Office 365
- Sharepoint: SharePoint
- Teams: Teams
- All: All modules
*Default is All*

`-reportType`: Choose the report format. Options include:
- HTML: HTML
- CSV: CSV
- XML: XML
- CSMS: CSMS
*Default is HTML*

`-LicenseMode`: Choose the benchmark license mode. Options include:

- E3: E3 license
- E5: E5 license
- All: All license modes
*Default is All*

`-LicenseLevel`: Choose the benchmark level. Options include:

- L1: Level 1
- L2: Level 2
- All: All levels
*Default is All*


*Note: Currently HTML and CSV are supported. XML and CSMS are implemented in the future!*

#### 4.3.2 Optional Parameters

`-Environment`: Specifies the environment type. Options include:

- Default: Standard environment
- USGovGCCHigh: U.S. Government Cloud Computing High
- USGovDoD: U.S. Government Department of Defense
- Germany: Germany region
- China: China region

`-AllowLogging`: Enables logging with PoSH Logger

`-SkipChecks`: Skips module updates and additional checks on duplicate modules and existing of the modules.

`-ExpirimentalMode`: Uses the experimental multi-threaded scanner (not recommended).

`-LocalMode`: Enables using the /inspectors folder instead of downloading the inspectors from GitHub.

`-SkipLogin`: Skips login if already authenticated (Not-Recommended).


### 4.4 Execution Examples
When using the standard command to execute a security assessment, you will be prompted with graphical login screens where you must log in sequentially.

`.\M365SATTester.ps1`

You can add the desired parameters to this script and run it as needed.

The execution time for M365SAT varies depending on the size and complexity of your organization. For organizations with a small number of user accounts and minimal configuration, the assessment should take no longer than 60 minutes. However, for organizations with more than 100 user accounts and custom configurations, the process may take longer. The duration depends on the organization’s size, complexity, and the extent of configurations.

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
The following example is usable to create your own Inspector:

````
# Benchmark:
# Author: 

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CIS0000
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz0000"
        ID               = "0.0.0.0"
        Title            = "(L1) TITLE"
        ProductFamily    = "Microsoft Azure / Microsoft Exchange / Microsoft Sharepoint / Microsoft Teams"
        DefaultValue     = "DEFAULTVALUEHERE"
        ExpectedValue    = "EXPECTEDVALUEHERE"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "DESCRIPTIONHERE"
        Impact           = "IMPACTWHENREMEDIATINGHERE"
        Remediation      = 'REMEDIATIONSCRIPTHERE'
        References       = @(
            @{ 'Name' = 'SOURCE1'; 'URL' = 'https://example.org' },
            @{ 'Name' = 'SOURCE2'; 'URL' = 'https://localhost' }
        )
    }
    return $inspectorobject
}

function Audit-CIS0000
{
	try
	{
		# The audit part should go here

		# The validation part should go here
		
		if (#validation of your ifstatement)
		{
			#If you found a violation
			$endobject = Build-CIS0000 -ReturnedValue (VALUEHERE) -Status "FAIL" -RiskScore "3" -RiskRating "Informational/Low/Medium/High/Critical"
			return $endobject
		}
		else
		{
			#If you did not found a violation
			$endobject = Build-CIS0000 -ReturnedValue (VALUEHERE) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CIS0000 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz0000
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
M365SAT is an open-source and free software released under the [MIT License](https://raw.githubusercontent.com/Karmakstylez/M365SAT/refs/heads/production/LICENSE). All the additional plug-ins and frameworks are also accompanied by the same MIT Licence. 

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