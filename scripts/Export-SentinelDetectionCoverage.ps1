<#
.SYNOPSIS
    Exports what the Sentinel detection coverage review needs from one Microsoft Sentinel workspace. Read-only.

.DESCRIPTION
    Writes rules.csv, tables.csv, ingestion.csv, incidents.csv and health.csv to the output folder:
      - the analytics rules and the version of their templates, through the Microsoft.SecurityInsights REST API;
      - the tables each rule reads, found by matching the workspace's table names in the rule query;
      - the last record of every table the rules read or sources.csv expects, and daily ingestion from the Usage table;
      - the incidents of the period from SecurityIncident (its latest state), with the rule that raised each one;
      - every failed or partly failed run in SentinelHealth, plus the last run of each rule (the health feature must be on).
    sources.csv and priorities.csv are the organisation's own lists: write them once (start from sample_data/).
    Nothing is changed in the workspace. Needs Microsoft Sentinel Reader and Log Analytics Reader on the workspace.

.EXAMPLE
    .\Export-SentinelDetectionCoverage.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 -ResourceGroup rg-security `
        -Workspace law-sentinel -OutputFolder .\data -Days 30
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $SubscriptionId,
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [Parameter(Mandatory)] [string] $Workspace,
    [string] $OutputFolder = '.\data',
    [int] $Days = 30,
    [string] $ApiVersion = '2024-03-01'
)
$ErrorActionPreference = 'Stop'
Import-Module Az.Accounts, Az.OperationalInsights
if (-not (Get-AzContext)) { Connect-AzAccount | Out-Null }
Set-AzContext -Subscription $SubscriptionId | Out-Null
New-Item -ItemType Directory -Force -Path $OutputFolder | Out-Null

$ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup -Name $Workspace
$wsPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$Workspace"
$si = "$wsPath/providers/Microsoft.SecurityInsights"

function Get-All([string] $Path, [string] $Version) {
    $out = @()
    $uri = "${Path}?api-version=$Version"
    while ($uri) {
        $r = Invoke-AzRestMethod -Path $uri -Method GET
        if ($r.StatusCode -ne 200) { throw "GET $Path returned $($r.StatusCode): $($r.Content)" }
        $j = $r.Content | ConvertFrom-Json
        $out += @($j.value)
        $uri = if ($j.nextLink) { ([uri]$j.nextLink).PathAndQuery } else { $null }
    }
    $out
}

function Invoke-Kql([string] $Query) {
    @((Invoke-AzOperationalInsightsQuery -WorkspaceId $ws.CustomerId -Query $Query -Timespan (New-TimeSpan -Days ($Days + 1))).Results)
}

function Save([object[]] $Rows, [string] $Name) {
    $Rows | Export-Csv -Path (Join-Path $OutputFolder $Name) -NoTypeInformation -Encoding UTF8
    Write-Host ("{0,-14} {1} rows" -f $Name, @($Rows).Count)
}

# --- rules, their templates and the tables they read
$tableNames = @(Get-All "$wsPath/tables" '2022-10-01' | ForEach-Object { $_.name }) | Sort-Object { -$_.Length }
$templates = @{}
foreach ($t in Get-All "$si/alertRuleTemplates" $ApiVersion) {
    if ($t.properties.version) { $templates[$t.name] = $t.properties.version }
}
$rules = foreach ($r in Get-All "$si/alertRules" $ApiVersion) {
    $p = $r.properties
    $query = [string]$p.query
    $tables = @($tableNames | Where-Object { $query -match "(?<![\w.])$([regex]::Escape($_))(?![\w])" })
    $techniques = @($p.techniques) + @($p.subTechniques) | Where-Object { $_ }
    [pscustomobject]@{
        Rule            = $p.displayName
        Kind            = $r.kind
        Enabled         = [bool]$p.enabled
        Severity        = $p.severity
        Tactics         = (@($p.tactics) -join ';')
        Techniques      = ($techniques -join ';')
        Tables          = ($tables -join ';')
        Frequency       = $p.queryFrequency
        Source          = if ($r.kind -in 'Fusion', 'MicrosoftSecurityIncidentCreation', 'MLBehaviorAnalytics', 'ThreatIntelligence') { 'Microsoft' }
                          elseif ($p.alertRuleTemplateName) { 'Template' } else { 'Custom' }
        TemplateVersion = $p.templateVersion
        LatestVersion   = if ($p.alertRuleTemplateName) { $templates[$p.alertRuleTemplateName] } else { '' }
        Modified        = $p.lastModifiedUtc
        Id              = $r.name
    }
}
Save ($rules | Select-Object -Property * -ExcludeProperty Id) 'rules.csv'

# --- last record per table: every table a rule reads plus the ones sources.csv expects
$wanted = @($rules | ForEach-Object { $_.Tables -split ';' })
$expected = Join-Path $OutputFolder 'sources.csv'
if (Test-Path $expected) { $wanted += @(Import-Csv $expected | ForEach-Object { $_.Table }) }
$wanted = @($wanted | Where-Object { $_ } | Sort-Object -Unique)
if ($wanted) {
    $q = "union withsource=Table isfuzzy=true $($wanted -join ', ') | where TimeGenerated > ago(${Days}d) | summarize LastRecord = max(TimeGenerated) by Table"
    Save (Invoke-Kql $q | Select-Object Table, LastRecord) 'tables.csv'
}

# --- daily ingestion (Quantity is in MB)
Save (Invoke-Kql "Usage | where TimeGenerated > ago(${Days}d) | summarize GB = round(sum(Quantity) / 1024.0, 3) by Date = format_datetime(startofday(TimeGenerated), 'yyyy-MM-dd'), Table = DataType | order by Date asc") 'ingestion.csv'

# --- incidents of the period, latest state, with the rule that raised each one
$names = @{}
foreach ($r in $rules) { $names[$r.Id] = $r.Rule }
$q = @"
SecurityIncident
| where CreatedTime > ago(${Days}d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| project Incident = IncidentNumber, Title, Severity, Status, Classification, Owner = tostring(Owner.assignedTo),
          Created = CreatedTime, FirstModified = FirstModifiedTime, Closed = ClosedTime, RuleIds = tostring(RelatedAnalyticRuleIds)
"@
$incidents = foreach ($i in Invoke-Kql $q) {
    $ids = @(($i.RuleIds | ConvertFrom-Json) | ForEach-Object { ([string]$_).Split('/')[-1] })
    $rule = @($ids | ForEach-Object { $names[$_] } | Where-Object { $_ }) | Select-Object -First 1
    [pscustomobject]@{
        Incident = $i.Incident; Title = $i.Title; Rule = if ($rule) { $rule } else { $i.Title }; Severity = $i.Severity; Status = $i.Status
        Classification = $i.Classification; Owner = $i.Owner; Created = $i.Created; FirstModified = $i.FirstModified; Closed = $i.Closed
    }
}
Save $incidents 'incidents.csv'

# --- rule health: failures and partial failures, plus the last run of each rule
$q = @"
let runs = SentinelHealth | where TimeGenerated > ago(${Days}d) and SentinelResourceType == 'Analytics Rule';
union
    (runs | where Status != 'Success'),
    (runs | summarize arg_max(TimeGenerated, *) by SentinelResourceName)
| project Time = TimeGenerated, Rule = SentinelResourceName, Status, Reason = Description
| distinct Time, Rule, Status, Reason
| order by Time asc
"@
Save (Invoke-Kql $q) 'health.csv'

Write-Host "Done. Add sources.csv, priorities.csv and settings.json (see docs/data-format.md), then: python -m detcover review $OutputFolder"
