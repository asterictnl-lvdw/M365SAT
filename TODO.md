# TO-DO

## Things that are need to be done before the improved release:

- Implement checks voor CIS v2.0.0 (Azure + Microsoft 365)
- AIPService Connector Implementation
- Implement custom checks for newly implemented security features within both Azure and Microsoft 365 suite.
- Remove MSOnline (MSOnline) completely and migrate it to Azure CloudShell (Az) / Azure PowerShell (AzAccount) and Microsoft Graph
- Migrate all AzureAD and AzureADPreview to Azure CloudShell (Az) / Azure PowerShell (AzAccount) and Microsoft Graph
- Removing old powershell scripts that are not supported anymore
- Adding support to PowerShell 7 to make the program cross-platform supporting
- Implement Exchange V3 Module
- Implement PnP PowerShell Module
- Improve the HTML/CSS from the report
- Replace the Errorlogging with PoShLogger for better support of logging instead of pointing each time to a file. Users are then required to install PoShLogger
- Fixing some bugs within the report template such as HealthScore, and some buggy
- Fixing and improving the update checker, duplicate checker and powershell module existing scripts
- A switch parameter for auditing only specifically on the CIS Benchmark of Microsoft 365 and Azure
-	A switch parameter that allows you to choose if you want to audit all Microsoft 365 modules, or only specific modules

## Things for in the future:

- Aquire Token Authentication so MFA accounts do not have to prompt where possible for modules by using default enterprise applications within Azure to connect through
- Configure a SaaS solution / a GUI that enables an even simpler overview for end-users and a possible better experience.
- Enable multiple export possibilities for users who do not want their findings in HTML-style.
- Add a WebPortal or C# Application to execute the audit via the portal
- Adding a Docker-Container so the application could be used within a Dockerized Container
