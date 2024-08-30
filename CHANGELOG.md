## Changelog

### Version 1.0.0beta (Released on 1-2-2023)
**Note:** This is a beta release. Some parts of the code may be unstable or not functioning correctly. We are aware of these issues and are working towards resolving them in the stable release.

#### What’s New?
- **Rebranding**: 365Inspect+ has been renamed to **M365SAT**.
- **New Reporting Engine**: Introduces a new reporting engine that provides a better overview of issues within your tenant, resulting in a more professional-looking report.
- **Module Import Option**: M365SAT can now be imported as a module or run traditionally by executing a `.ps1` script. Future releases will also be available through the PowerShell Gallery.
- **Reduced Permissions**: M365SAT now requires fewer sensitive permissions. Instead of Global Administrator, Global Reader, and SharePoint Administrator roles are sufficient. Note: SharePoint Administrator is still a sensitive permission due to its necessity for reading specific values for auditing SharePoint correctly.
- **Performance Optimizations**: Removed `.json` files and integrated their functions within `.ps1` scripts, improving performance by reducing the need for constant file imports.
- **General Code Optimizations**: Various code optimizations have been made within the engine to enhance performance.
- **Enhanced Console Output**: Added more console output to directly display if inspectors find any policy violations.
- **Modular Structure**: The structure of the modules has been updated, allowing additional modules to be easily added, enhancing the program's modularity.
- **Output Fixes**: Resolved issues where the remediation script was incorrectly displayed due to using double quotes instead of single quotes.
- **Expanded Remediation Scripts**: Added more PowerShell script options to facilitate automated remediation in future updates.
- **Module Categorization**: Modules are now categorized within the report by naming conventions such as `{category}-{check}`.
- **CVSS 3.1 Scores**: Added CVSS 3.1 scores based on potential impacts if a misconfiguration is exploited.
- **Unique Module IDs**: All modules now have unique IDs. A future release will provide a list of these IDs alongside their remediation steps.
- **Inspector Code Optimization**: Optimized the code for various inspectors.
- **Easier Authentication**: Improved user authentication by allowing username input.

#### Known Issues:
- **Error Log Issues**: The error log does not correctly capture messages when exceptions are thrown. This will be addressed in the next release.
- **Log Output Location**: Some logs are not saved in the correct location. This will be fixed in the next release.
- **Inspector Download Tool**: The online inspector download tool is not yet operational as the inspectors have not been published to the GitHub repository.
- **Health Index Calculation**: The health index is not rounded or calculated correctly, causing it to appear inconsistent. This will be fixed in the next release.
- **Duplicate Inspectors**: There may be duplicate inspectors in some cases. This will be reviewed and corrected in the next release.
- **PowerShell 7 Compatibility**: Partial compatibility with PowerShell 7, which may result in bugs and non-functional code. If issues are encountered, switch back to PowerShell 5.x for the audit.
- **Update Mechanism**: The update mechanism to check for M365SAT updates is not yet operational because the tool has not been published to GitHub. This will be tested in future releases.
- **Incomplete Documentation**: Some documentation may be added later.

#### To Implement:
- **Network Connection Check**: Adding functionality to check network connections using `Get-NetRoute | ? DestinationPrefix -eq '0.0.0.0/0' | Get-NetIPInterface | Where ConnectionState -eq 'Connected'`.

### Version 2.0
After extensive development, bug-fixing, and testing, version 2.0 of the Microsoft 365 Security Assessment Tool (M365SAT) is now available.

#### What’s New?
- **Updated CIS Benchmark**: Updated to the latest v2.0.0 for both Microsoft Azure and Microsoft 365.
- **Benchmark Selection Parameters**: Added parameters to select which benchmark to check. Future updates may include additional benchmarks based on user interest and requirements.
- **New Inspectors**: Introduced new inspectors that identify more findings in both Microsoft Azure and Microsoft 365 environments.
- **Removed Duplicates**: Eliminated duplicate inspectors across multiple product families.
- **Expanded Inspectors**: Increased the number of inspectors from 119 to 177, including custom inspectors.
- **New Login Mechanism**: Testing a new login mechanism for better management of login-related issues.
- **Custom API Caller**: Implemented a custom API caller to retrieve settings from Azure tenants and other portals.
- **M365SATTester Script**: Introduced the `M365SATTester.ps1` script for easy use of M365SAT.
- **Autodetection for SharePoint Domains**: Enabled autodetection for SharePoint domains, thanks to Soteria.
- **Remediation Script Copy Button**: Added a copy button for the remediation script to facilitate easy copying.
- **Improved PowerShell Scripts**: Enhanced the readability of PowerShell scripts, thanks to contributions from Soteria.
- **Updated Collapse Menus**: Updated collapse menus to a new style using Bootstrap 5 with responsive chevrons for a more professional look.
- **Additional Read Permissions**: Added more read permissions to Microsoft Graph to access further settings required for the CIS benchmark.
- **Inspector Updates**: All inspectors have been updated to their latest versions and will be retested upon future updates.
- **Partial PowerShell 7 Compatibility**: M365SAT now offers partial compatibility with PowerShell 7.
- **Reduced Permissions**: M365SAT can now be executed with fewer permissions than Global Administrator.

#### Fixed:
- **Health Index Calculation**: Corrected the health index calculation to ensure a rounded number that accurately reflects the score.
- **Priority Display**: Fixed issues with some priorities not displaying correctly due to incorrect sorting of informational notes.
- **Performance Improvements**: Addressed performance issues with Exchange cmdlets, reducing processing time by utilizing EXO cmdlets.
- **Logging Issues**: Fixed logging issues where logs were not saved in the correct location, causing errors if the directory was not created.
- **Email Verification**: Resolved issues with DMARC, DKIM, and SPF record verification, which is now fully handled by PowerShell commands instead of CMD commands.
- **HTML Report Resizing**: Fixed resizing issues in the HTML report by removing multiple flex classes. Now, objects resize appropriately when the screen size is adjusted.
- **CVS Sorting**: Corrected the sorting of the CVS.
- **Report Dates**: Fixed an issue with the start and end dates in the report to ensure accurate date entries.

#### Changed:
- **File Renaming**: Renamed multiple `.ps1` files for clarity.
- **Report Structure**: Reorganized the report structure and moved the inspector list to the end to prioritize necessary information.
- **Dependency Updates**: Updated all dependencies in the HTML report to their latest versions.
- **Exchange Commands Migration**: Migrated Exchange commands to the new EXO cmdlet commands (V3) for better stability and performance.
- **Authentication Order**: Changed the authentication order, with Security & Compliance preceding Exchange due to a REST Schema bug that prevents Exchange cmdlets from succeeding when connected before the S&C cmdlet.
- **Bootstrap and Libraries Update**: Migrated from Bootstrap 4 to Bootstrap 5, enhancing the report's appearance, and updated JQuery and FontAwesome dependencies to their latest versions.

#### Removed:
- **Deprecated Modules**: Phased out the PnP PowerShell modules to fully utilize SharePoint cmdlets, and removed AzureADPreview and MicrosoftOnline (MSOL) modules as they will be replaced by Microsoft Graph.
- **Microsoft InTune Module**: Removed and fully integrated into Microsoft Graph.
- **Legacy Logging**: Replaced `Write-ErrorLog.ps1` with PoSHLog for cleaner and more effective logging.

#### Known Issues and Bugs:
- **Log File Location**: Log files are not saved in the correct folder. A workaround is to manually open the corresponding text file. This will be fixed in the next release.
- **CVS Score Inaccuracies**: CVS scores may be incorrect. Scores will be updated based on CWE findings and a custom priority algorithm in future releases.
- **Manual Authentication Required**: Some modules require manual authentication due to cmdlets not supporting cached credential authentication.
- **PowerShell Warning**: In PowerShell 5.1, CISAz6000 issues a warning about 'Microsoft.Azure.PowerShell.Cmdlets.Network'. This can be safely ignored, and a fix will be explored in the next release.
- **Text File Naming**: Not all text files have correct naming. This will be fixed in the next release.
- **Duplicate Logs**: Some findings may have duplicate logs due to more than 10 objects stored in the array. This will be addressed to ensure correct output in the next release.
- **Clipboard Function**: The clipboard function does not work with all internet browsers. If issues arise, open the HTML file in a different browser, such as Microsoft Edge.
- **PowerShell 7 Inspector Issues**: Certain inspectors do not function correctly in PowerShell 7 due to issues with new EXO commands. Only Exchange is affected for now. We are considering reverting to normal commands in test releases to resolve this issue.

### Version 2.1

After extensive testing and implementation, version 2.1 of M365SAT is now available with several updates.

#### What’s New?
- **Updated CIS Benchmark**: The Microsoft 365 CIS benchmark has been updated to version 3.0.0.
- **Benchmark Selection Parameter**: Added a parameter to allow users to select the CIS v2.0 benchmark for those who wish to use it.
- **Experimental Multi-threading**: Introduced an experimental multi-threading mode using ThreadJobs for faster scanning. This mode is available in PowerShell 7+ and requires an additional module in PowerShell 5. This feature aims to speed up scanning by running inspectors in parallel within the same session.
- **RiskScore Calculation**: Added Likelihood and Priority objects to all inspectors for calculating RiskScore. The RiskScore, ranging from 0 to 25, is computed by multiplying impact and likelihood. Refer to the README.md on GitHub for detailed information.

#### Fixed:
- **Styling Issues**: Fixed styling and description issues in the report related to CIS misconfigurations.

#### Changed:
- **Risk Analysis Model**: Replaced the CVSS scoring with a risk analysis model based on impact x likelihood.
- **Priority Schema Update**: Modified the priority schema to use a 5x5 Risk Analysis Schema for better prioritization of findings.
- **Sorting Schema**: Updated sorting to be based on RiskScore.
- **README.md Update**: Enhanced the README.md for improved clarity.

#### Removed:
- **CVSS Score**: Removed CVSS scores as they were not accurately reflecting the significance of CIS findings.

#### Known Issues:
- **Object Sorting**: Sorting of objects based on RiskScore is not yet fixed. This will be addressed in the next release (v2.1.1).
- **Source Changes**: Potential changes in sources due to the new implementation. This will be addressed in the next release (v2.1.1).
- **CISMAz1111 Multi-threading Issue**: CISMAz1111 does not work in multi-threaded mode on PowerShell v5. Further investigation is needed.
- **Multi-threading with Exchange Cmdlets**: Issues with multi-threading when running Exchange cmdlets are being investigated. A workaround will be implemented to ensure compatibility.

### Version 2.1.1

Following thorough testing and additional updates, version 2.1.1 of M365SAT is now available.

#### What’s New?
- **Updated Azure Foundations CIS Benchmark**: Updated to version 2.1.0 and expanded coverage with additional checks.
- **Latest AuditType Parameter**: Added an option in the AuditType parameter to audit based on the latest checks (M365: v3.0.0 and AZ: v2.1.0). This is now the default option.
- **Inspector Updates**: Addressed issues with some inspectors and removed unnecessary warning messages to improve performance.

#### Fixed:
- **Timeout Issues**: Resolved timeout issues that were affecting performance in v3.0.0 and v2.1.0.

#### Changed:
- **No Major Changes**: No significant changes in this release.

#### Removed:
- **No Removals**: No modules or features were removed in this release.

### Version 2.2

#### Added:
- **E3/E5 Tags**: Added E3 Level 1, E3 Level 2, E5 Level 1, and E5 Level 2 tags, along with corresponding parameters.
- **EnvironmentType Parameter**: Introduced the 'EnvironmentType' parameter to differentiate between Microsoft 365 and Azure environments.
- **LicenseMode Parameter**: Added 'LicenseMode' parameter to distinguish between E3 and E5 audits or to audit both.
- **LicenseLevel Parameter**: Added 'LicenseLevel' to allow users to audit specific CIS levels (Level 1 or Level 2) or both.
- **Script Execution Options**: Enhanced `M365SATTester.ps1` to support multiple script execution options.

#### Fixed:
- **Sources and Descriptions**: Fixed issues with finding sources and updated descriptions to align with the latest version of the M365 Inspector list.

#### Changed:
- **Parameter Adjustments**: Removed several parameters and updated the `BenchmarkVersion` parameter for better processing.
- **Modules Parameter**: Modified the 'Modules' parameter and renamed 'CustomModules' to 'LocalMode'.
- **Connection Schema**: Updated connection schema to allow authentication for specific modules only.
- **TXT Output Experiment**: Experimented with outputting findings to `.txt` files. Future updates will assess its impact on performance.

#### Removed:
- **No Removals**: No features or modules were removed in this release.

### Version 2.3

For detailed changes, please refer to the Releases section.

### Version 3.0

**Coming Soon!**
