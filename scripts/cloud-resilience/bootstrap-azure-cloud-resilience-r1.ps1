& {
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version 2.0

    $ResourceGroup = 'rg-assurance-resilience-dev'
    $Location = 'eastus2'
    $CobitRepo = 'taiwoyusuf/cobit-chain'
    $RamatRepo = 'taiwoyusuf/ramat-vision'
    $CobitPr = 56
    $RamatPr = 2

    function Require-Command {
        param([Parameter(Mandatory=$true)][string]$Name)
        if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
            throw "Required command '$Name' was not found in PATH."
        }
    }

    function Invoke-External {
        param(
            [Parameter(Mandatory=$true)][string]$Exe,
            [Parameter(Mandatory=$true)][string[]]$Args
        )
        Write-Host ("> {0} {1}" -f $Exe, ($Args -join ' '))
        & $Exe @Args
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code $LASTEXITCODE: $Exe $($Args -join ' ')"
        }
    }

    Require-Command az
    Require-Command gh

    Write-Host '=== Azure authentication ==='
    & az account show --only-show-errors 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        Invoke-External -Exe 'az' -Args @('login')
    }

    $Account = (& az account show --only-show-errors -o json | ConvertFrom-Json)
    if (-not $Account.id -or -not $Account.tenantId) {
        throw 'Unable to resolve Azure subscription or tenant.'
    }
    $SubscriptionId = [string]$Account.id
    $TenantId = [string]$Account.tenantId
    Write-Host "Subscription: $($Account.name) [$SubscriptionId]"
    Write-Host "Tenant:       $TenantId"

    Write-Host '=== GitHub authentication ==='
    Invoke-External -Exe 'gh' -Args @('auth','status')

    Write-Host '=== Resource group ==='
    Invoke-External -Exe 'az' -Args @(
        'group','create',
        '--name',$ResourceGroup,
        '--location',$Location,
        '--only-show-errors','-o','none'
    )

    $SubCompact = ($SubscriptionId -replace '[^a-zA-Z0-9]','').ToLowerInvariant()
    $BaseStorageName = ('stcr' + $SubCompact.Substring(0,[Math]::Min(12,$SubCompact.Length)) + '01').ToLowerInvariant()
    if ($BaseStorageName.Length -gt 24) { $BaseStorageName = $BaseStorageName.Substring(0,24) }

    $StorageName = $BaseStorageName
    $Availability = (& az storage account check-name --name $StorageName --only-show-errors -o json | ConvertFrom-Json)
    if (-not $Availability.nameAvailable) {
        $Suffix = -join ((48..57) + (97..102) | Get-Random -Count 4 | ForEach-Object {[char]$_})
        $PrefixLength = 24 - $Suffix.Length
        $StorageName = ($BaseStorageName.Substring(0,[Math]::Min($PrefixLength,$BaseStorageName.Length)) + $Suffix).ToLowerInvariant()
    }

    Write-Host "=== Storage account: $StorageName ==="
    $ExistingStorage = & az storage account show --name $StorageName --resource-group $ResourceGroup --only-show-errors -o json 2>$null
    if ($LASTEXITCODE -ne 0) {
        Invoke-External -Exe 'az' -Args @(
            'storage','account','create',
            '--name',$StorageName,
            '--resource-group',$ResourceGroup,
            '--location',$Location,
            '--sku','Standard_GRS',
            '--kind','StorageV2',
            '--https-only','true',
            '--min-tls-version','TLS1_2',
            '--allow-blob-public-access','false',
            '--only-show-errors','-o','none'
        )
    }

    Invoke-External -Exe 'az' -Args @(
        'storage','account','blob-service-properties','update',
        '--account-name',$StorageName,
        '--resource-group',$ResourceGroup,
        '--enable-versioning','true',
        '--enable-delete-retention','true',
        '--delete-retention-days','30',
        '--enable-container-delete-retention','true',
        '--container-delete-retention-days','30',
        '--only-show-errors','-o','none'
    )

    $StorageKey = (& az storage account keys list --account-name $StorageName --resource-group $ResourceGroup --query '[0].value' -o tsv)
    if (-not $StorageKey) { throw 'Unable to obtain bootstrap storage key.' }

    foreach ($Container in @('cobit-chain','ramat-vision')) {
        Invoke-External -Exe 'az' -Args @(
            'storage','container','create',
            '--account-name',$StorageName,
            '--account-key',$StorageKey,
            '--name',$Container,
            '--public-access','off',
            '--only-show-errors','-o','none'
        )
    }

    $StorageId = (& az storage account show --name $StorageName --resource-group $ResourceGroup --query id -o tsv)
    if (-not $StorageId) { throw 'Unable to resolve storage resource ID.' }

    function Ensure-GitHubFederatedIdentity {
        param(
            [Parameter(Mandatory=$true)][string]$DisplayName,
            [Parameter(Mandatory=$true)][string]$Repo,
            [Parameter(Mandatory=$true)][string]$Container
        )

        Write-Host "=== Federated identity for $Repo ==="
        $AppRows = & az ad app list --display-name $DisplayName --only-show-errors -o json | ConvertFrom-Json
        $App = @($AppRows) | Select-Object -First 1
        if (-not $App) {
            $App = (& az ad app create --display-name $DisplayName --only-show-errors -o json | ConvertFrom-Json)
        }

        $AppId = [string]$App.appId
        $AppObjectId = [string]$App.id
        if (-not $AppId -or -not $AppObjectId) { throw "Unable to resolve app identity for $Repo." }

        $SpRows = & az ad sp list --filter "appId eq '$AppId'" --only-show-errors -o json | ConvertFrom-Json
        $Sp = @($SpRows) | Select-Object -First 1
        if (-not $Sp) {
            $Sp = (& az ad sp create --id $AppId --only-show-errors -o json | ConvertFrom-Json)
        }
        $SpObjectId = [string]$Sp.id

        $CredentialName = (($Repo -replace '[^A-Za-z0-9-]','-') + '-main-r1').ToLowerInvariant()
        $ExistingCreds = & az ad app federated-credential list --id $AppObjectId --only-show-errors -o json | ConvertFrom-Json
        $ExistingCred = @($ExistingCreds) | Where-Object { $_.name -eq $CredentialName } | Select-Object -First 1
        if (-not $ExistingCred) {
            $Federation = [ordered]@{
                name = $CredentialName
                issuer = 'https://token.actions.githubusercontent.com'
                subject = "repo:${Repo}:ref:refs/heads/main"
                description = "Cloud Resilience R1 GitHub Actions main-branch backup for $Repo"
                audiences = @('api://AzureADTokenExchange')
            }
            $TempFile = [System.IO.Path]::GetTempFileName()
            try {
                $Federation | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $TempFile -Encoding UTF8
                Invoke-External -Exe 'az' -Args @(
                    'ad','app','federated-credential','create',
                    '--id',$AppObjectId,
                    '--parameters','@' + $TempFile,
                    '--only-show-errors','-o','none'
                )
            }
            finally {
                Remove-Item -LiteralPath $TempFile -Force -ErrorAction SilentlyContinue
            }
        }

        $ContainerScope = "$StorageId/blobServices/default/containers/$Container"
        $ExistingRole = & az role assignment list --assignee-object-id $SpObjectId --scope $ContainerScope --role 'Storage Blob Data Contributor' --only-show-errors -o json | ConvertFrom-Json
        if (@($ExistingRole).Count -eq 0) {
            Invoke-External -Exe 'az' -Args @(
                'role','assignment','create',
                '--assignee-object-id',$SpObjectId,
                '--assignee-principal-type','ServicePrincipal',
                '--role','Storage Blob Data Contributor',
                '--scope',$ContainerScope,
                '--only-show-errors','-o','none'
            )
        }

        Invoke-External -Exe 'gh' -Args @('secret','set','AZURE_BACKUP_CLIENT_ID','--repo',$Repo,'--body',$AppId)
        Invoke-External -Exe 'gh' -Args @('secret','set','AZURE_BACKUP_TENANT_ID','--repo',$Repo,'--body',$TenantId)
        Invoke-External -Exe 'gh' -Args @('secret','set','AZURE_BACKUP_SUBSCRIPTION_ID','--repo',$Repo,'--body',$SubscriptionId)
        Invoke-External -Exe 'gh' -Args @('variable','set','AZURE_BACKUP_STORAGE_ACCOUNT','--repo',$Repo,'--body',$StorageName)

        return [pscustomobject]@{
            Repo = $Repo
            AppId = $AppId
            SpObjectId = $SpObjectId
            Container = $Container
        }
    }

    $CobitIdentity = Ensure-GitHubFederatedIdentity -DisplayName 'gh-cobit-chain-azure-backup-r1' -Repo $CobitRepo -Container 'cobit-chain'
    $RamatIdentity = Ensure-GitHubFederatedIdentity -DisplayName 'gh-ramat-vision-azure-backup-r1' -Repo $RamatRepo -Container 'ramat-vision'

    Write-Host '=== Activate dedicated backup PRs ==='
    foreach ($Item in @(
        [pscustomobject]@{ Repo = $CobitRepo; Pr = $CobitPr },
        [pscustomobject]@{ Repo = $RamatRepo; Pr = $RamatPr }
    )) {
        & gh pr ready $Item.Pr --repo $Item.Repo 1>$null 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Could not mark PR #$($Item.Pr) ready in $($Item.Repo). It may already be ready."
        }
        Invoke-External -Exe 'gh' -Args @('pr','merge',[string]$Item.Pr,'--repo',$Item.Repo,'--merge')
    }

    Write-Host '=== Allow GitHub/Azure role propagation ==='
    Start-Sleep -Seconds 20

    Write-Host '=== Trigger/verify backup workflows ==='
    foreach ($Repo in @($CobitRepo,$RamatRepo)) {
        & gh workflow run 'Cloud Resilience R1 - Azure Backup' --repo $Repo 1>$null 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Manual workflow dispatch did not start for $Repo; the merge push should still have triggered the workflow."
        }
        Start-Sleep -Seconds 5
        $RunJson = & gh run list --repo $Repo --workflow 'Cloud Resilience R1 - Azure Backup' --limit 1 --json databaseId,status,conclusion,headSha,url
        if ($LASTEXITCODE -eq 0 -and $RunJson) {
            $Run = @($RunJson | ConvertFrom-Json) | Select-Object -First 1
            if ($Run -and $Run.databaseId) {
                Write-Host "Watching $Repo backup run $($Run.databaseId)..."
                & gh run watch $Run.databaseId --repo $Repo --exit-status
                if ($LASTEXITCODE -ne 0) {
                    throw "Azure backup workflow failed for $Repo."
                }
            }
        }
    }

    Write-Host '=== Azure blob verification ==='
    foreach ($Container in @('cobit-chain','ramat-vision')) {
        $Count = & az storage blob list --account-name $StorageName --account-key $StorageKey --container-name $Container --query 'length(@)' -o tsv
        Write-Host "$Container blob count: $Count"
        if (-not $Count -or [int]$Count -lt 1) {
            throw "No Azure backup blobs were found in container '$Container'."
        }
    }

    Write-Host ''
    Write-Host 'CLOUD RESILIENCE R1: AZURE BACKUP ACTIVATED AND VERIFIED'
    Write-Host "Resource group : $ResourceGroup"
    Write-Host "Storage account: $StorageName"
    Write-Host 'Redundancy     : Standard_GRS'
    Write-Host 'Blob versioning: enabled'
    Write-Host 'Blob soft delete: 30 days'
    Write-Host 'Container soft delete: 30 days'
    Write-Host 'Repositories   : COBIT-Chain + RAMAT Vision'
}
