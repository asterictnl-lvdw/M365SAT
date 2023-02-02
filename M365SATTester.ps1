function ExecuteM365SAT
{
	Import-Module .\M365SAT.psm1
	. .\M365SAT.psm1
	Get-M365SATReport -OrgName "Contoso" -OutPath "C:\out" -Username "example@contoso.org" -reportType HTML -SkipChecks -UseCustomModules
}
ExecuteM365SAT