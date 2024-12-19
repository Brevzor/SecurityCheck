$configJson = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/Brevzor/SecurityCheck/refs/heads/main/cfg.json" 
$Astra = $configJson.Astra
$EntryPoint = $configJson.EntryPoint
$FilesizeH = $configJson.FilesizeH
$FilesizeL = $configJson.FilesizeL
$Hydro = $configJson.Hydro
$Leet = $configJson.Leet
$Skript = $configJson.Skript
$ThreatDetection = $configJson.Threat

$ErrorActionPreference = "SilentlyContinue" 
$dmppath = "C:\Temp\Dump"
$acpath = "C:\Temp\Dump\Timeline"
$dmppath = "C:\Temp\Dump"
$evtrawpath = "C:\Temp\Dump\Events\Raw"
$otherpath = "C:\Temp\Dump\Others"
$procpath = "C:\Temp\Dump\Processes"
$procpathfilt = "C:\Temp\Dump\Processes\Filtered"
$procpathraw = "C:\Temp\Dump\Processes\Raw"
$regpath = "C:\Temp\Dump\Registry"
$shellbagspath = "C:\Temp\Dump\Shellbags"
$shimcachepath = "C:\Temp\Dump\Shimcache"
$winsearchpath = "C:\Temp\Dump\Winsearch"
$scripttime = "Script-Run-Time: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')"
$directories = @('Timeline', 'Events\Raw', 'Journal', 'Others', 'Prefetch', 'Processes\Filtered', 'Processes\Raw', 'Registry', 'Shellbags', 'Shimcache', 'Winsearch')
foreach ($dir in $directories) {
    New-Item -Path "$dmppath\$dir" -ItemType Directory -Force | Out-Null
}
$cachePath = (Get-ChildItem -Path "$env:LOCALAPPDATA\ConnectedDevicesPlatform" -r -Filter "ActivitiesCache.db").FullName
Set-Location "$dmppath"
$l1 = & { "`n-------------------"; }
$l2 = & { "-------------------`n"; }
$l3 = & { "-------------------" }
$l4 = & { "`n-------------------`n" }
$h1 = & { $l1; "|      System     |"; $l2; }
$h2 = & { $l1; "|    Tampering    |"; $l2; }
$h3 = & { $l1; "|     Threats     |"; $l2; }
$h4 = & { $l1; "|      Events     |"; $l2; }
$h5 = & { $l1; "|   Executables   |"; $l2; }

$searchTerms = @("USBDEVIEW", "ro9an", "aimbot", "a!mbot", "almbot", "skrift", "zauberkasten")
$userProfile = [System.Environment]::GetFolderPath('UserProfile')
$pathsToSearch = @(
    [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\Recent'),
    [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\Explorer\Quick Access'),
    [System.IO.Path]::GetTempPath(),
    [System.IO.Path]::Combine($userProfile, 'Downloads'),
    [System.IO.Path]::Combine($userProfile, 'Documents'),
    [System.IO.Path]::Combine($userProfile, 'Desktop'),
    'C:\ProgramData',
    'C:\Windows\Temp'
)

$quickCheckFiles = @()

foreach ($path in $pathsToSearch) {
    if (Test-Path $path) {
        foreach ($searchTerm in $searchTerms) {
            $files = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$searchTerm*" }
            $quickCheckFiles += $files
        }
    }
}

if ($quickCheckFiles.Count -gt 0) {
    Write-Host "Suspicious files found in:"
    $quickCheckFiles | ForEach-Object { Write-Host $_.FullName }

    $response = Read-Host "Continue regardless? (Y / N / O)"
    
    switch ($response.ToUpper()) {
        'Y' {
            Write-Host "Continuing the script..."
        }
        'N' {
            Write-Host "Closing PowerShell in 5 seconds..."
            Start-Sleep -Seconds 5
            Exit
        }
        'O' {
            $foldersToOpen = $quickCheckFiles | Select-Object -ExpandProperty DirectoryName -Unique
            foreach ($folder in $foldersToOpen) {
                Start-Process explorer.exe $folder
            }

            $continueResponse = Read-Host "File-Paths opened. Do you want to continue? (Y / N)"
            switch ($continueResponse.ToUpper()) {
                'Y' {
                    Write-Host "Continuing the script..." -Foregroundcolor Green
                }
                'N' {
                    Write-Host "Closing PowerShell in 5 seconds..." -Foregroundcolor red
                    Start-Sleep -Seconds 5
                    Exit
                }
                default {
                    Write-Host "Invalid option. Exiting..."
                    Exit
                }
            }
        }
        default {
            Write-Host "Invalid option. Exiting..."
            Exit
        }
    }
}

Clear-Host
if ((Read-Host "`n`n`nThis program requires 1GB of free disk space on your System Disk.`n`n`nWe will be downloading the programs: `n`n- ESEDatabaseView by Nirsoft `n- strings2 by Geoff McDonald (more infos at split-code.com) `n- ACC Parser, PECmd, EvtxCmd, SBECmd, SQLECmd, RECmd and WxTCmd from Eric Zimmermans Tools (more infos at ericzimmerman.github.io).`n`nThis will be fully local, no data will be collected.`nIf Traces of Cheats are found, you are highly advised to reset your PC or you could face repercussions on other Servers.`nRunning PC Checking Programs, including this script, outside of PC Checks may have impact on the outcome.`nDo you agree to a PC Check and do you agree to download said tools? (Y/N)") -eq "Y") {
    Clear-Host
    Write-Host "`n`n`n-------------------------"-ForegroundColor yellow
    Write-Host "|    Download Assets    |" -ForegroundColor yellow
    Write-Host "|      Please Wait      |" -ForegroundColor yellow
    Write-Host "-------------------------`n"-ForegroundColor yellow
    Add-Type -AssemblyName 'System.IO.Compression.FileSystem'

    function ExtractZipFile {
        param (
            [string]$ZipFilePath,
            [string]$DestinationPath
        )
        [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipFilePath, $DestinationPath)
    }
    $files = @(
        @{url = "https://github.com/Brevzor/SecurityCheck/releases/download/v1.3.3.7/strings2.exe"; path = "C:\temp\dump\strings2.exe" }
        @{url = "https://github.com/Brevzor/SecurityCheck/releases/download/v1.3.3.7/esedatabaseview.zip"; path = "C:\temp\dump\esedatabaseview.zip" }
        @{url = "https://github.com/Brevzor/SecurityCheck/releases/download/v1.3.3.7/PECmd.zip"; path = "C:\temp\dump\PECmd.zip" }
        @{url = "https://github.com/Brevzor/SecurityCheck/releases/download/v1.3.3.7/EvtxECmd.zip"; path = "C:\temp\dump\EvtxECmd.zip" }
        @{url = "https://github.com/Brevzor/SecurityCheck/releases/download/v1.3.3.7/WxTCmd.zip"; path = "C:\temp\dump\WxTCmd.zip" }
        @{url = "https://github.com/Brevzor/SecurityCheck/releases/download/v1.3.3.7/SBECmd.zip"; path = "C:\temp\dump\SBECmd.zip" }
        @{url = "https://github.com/Brevzor/SecurityCheck/releases/download/v1.3.3.7/RECmd.zip"; path = "C:\temp\dump\RECmd.zip" }
        @{url = "https://github.com/Brevzor/SecurityCheck/releases/download/v1.3.3.7/AppCompatCacheParser.zip"; path = "C:\temp\dump\AppCompatCacheParser.zip" }
    )

    $webClients = @()
    foreach ($file in $files) {
        $wc = New-Object System.Net.WebClient
        $asyncResult = $wc.DownloadFileTaskAsync($file.url, $file.path)
        $webClients += [PSCustomObject]@{ WebClient = $wc; AsyncResult = $asyncResult; Path = $file.path }
    }

    $webClients | ForEach-Object {
        try {
            $_.AsyncResult.Wait()
            if ($_.WebClient.IsBusy) {
                $_.WebClient.CancelAsync()
                Write-Output "Failed to download $($_.Path)"
            }
        }
        catch {
            Write-Output "Error downloading $($_.Path): $_"
        }
    }

    foreach ($filePath in Get-ChildItem 'C:\temp\dump\*.zip') {
        ExtractZipFile -ZipFilePath $filePath.FullName -DestinationPath 'C:\temp\dump'
    }
}
else {
    Clear-Host
    Write-Host "`n`n`nPC Check aborted by Player.`nThis may lead to consequences up to your servers Administration.`n`n`n" -Foregroundcolor red
    return
}

Clear-Host
Write-Host "`n`n`n-------------------------"-ForegroundColor yellow
Write-Host "|   Script is Running   |" -ForegroundColor yellow
Write-Host "|      Please Wait      |" -ForegroundColor yellow
Write-Host "-------------------------`n"-ForegroundColor yellow
Write-Host "  This takes 5 Minutes`n`n`n"-ForegroundColor yellow

Write-Host "   Dumping System Logs"-ForegroundColor yellow
Start-Process -FilePath "C:\temp\dump\PECmd.exe" -ArgumentList '-d "C:\Windows\Prefetch" --vss --csv C:\temp\dump\Prefetch --csvf Prefetch.csv' -WindowStyle Hidden
Start-Process -FilePath "C:\temp\dump\EvtxECmd\EvtxECmd.exe" -ArgumentList '-f "C:\Windows\System32\winevt\Logs\Application.evtx" --inc 1001,1006,1007,3005,3079,5002 --csv "C:\temp\dump\Events\Raw" --csvf Application.csv' -WindowStyle Hidden
Start-Process -FilePath "C:\temp\dump\EvtxECmd\EvtxECmd.exe" -ArgumentList '-f "C:\Windows\System32\winevt\Logs\Security.evtx" --inc 1102,1116,1117,1121,1122,1123,4656,4660,4663,4670,5140,5145,11170,11171,11172 --csv "C:\temp\dump\Events\Raw" --csvf Security.csv' -WindowStyle Hidden
Start-Process -FilePath "C:\temp\dump\EvtxECmd\EvtxECmd.exe" -ArgumentList '-f "C:\Windows\System32\winevt\Logs\System.evtx" --inc 51,52,104,105,601,2010,6005,6006,6008,6013,7030,7031,7034,7040,7045,8194,8195,8196 --csv "C:\temp\dump\Events\Raw" --csvf System.csv' -WindowStyle Hidden
Start-Process -FilePath "C:\temp\dump\EvtxECmd\EvtxECmd.exe" -ArgumentList '-f "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx" --inc 4100,4103,4104 --csv "C:\temp\dump\Events\Raw" --csvf Powershell.csv' -WindowStyle Hidden
Start-Process -FilePath "C:\temp\dump\EvtxECmd\EvtxECmd.exe" -ArgumentList '-f "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Kernel-PnP%4Configuration.evtx" --inc 400,410,430 --csv "C:\temp\dump\Events\Raw" --csvf KernelPnp.csv' -WindowStyle Hidden
Start-Process -FilePath "C:\temp\dump\EvtxECmd\EvtxECmd.exe" -ArgumentList '-f "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx" --inc 1003,1116,1117,1150,2000,5000,5001,5007 --csv "C:\temp\dump\Events\Raw" --csvf Defender.csv' -WindowStyle Hidden
Start-Process -FilePath "C:\temp\dump\EvtxECmd\EvtxECmd.exe" -ArgumentList '-f "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Time-Service%4Operational.evtx" --inc 257,258,259,260,261,263,264,265,266,272 --csv "C:\temp\dump\Events\Raw" --csvf Timeservice.csv' -WindowStyle Hidden
Start-Process -Filepath "C:\temp\dump\AppCompatCacheParser.exe" -Argumentlist '-t --csv C:\temp\dump\shimcache --csvf Shimcache.csv' -WindowStyle Hidden
C:\temp\dump\wxtcmd.exe -f "$cachePath" --csv C:\temp\dump\Timeline | Out-Null
C:\Temp\Dump\RECmd\RECmd.exe -d "C:\windows\system32\config\" --csv C:\temp\dump\registry --details TRUE --bn C:\Temp\Dump\RECmd\batchexamples\kroll_batch.reb | Out-Null
C:\Temp\Dump\SBECmd.exe -d "$env:LocalAppData\Microsoft\Windows" --csv C:\temp\dump\Shellbags | Out-Null
C:\temp\dump\SQLECmd\SQLECmd.exe --sync | Out-Null

Write-Host "   Dumping Systeminformation"-ForegroundColor yellow
$o1 = & {
    $scripttime
    "Connected Drives: $(Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3 -or $_.DriveType -eq 2} | ForEach-Object { "$($_.DeviceID)\" })" -join ', '
    "Volumes in Registry: $(if ($regvolumes = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows Search\VolumeInfoCache' | ForEach-Object { $_ -replace '^.*\\([^\\]+)$', '$1' }) { $regvolumes -join ', ' } else { 'Registry Volume Cache Manipulated' })"
    "Windows Version: $((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName, CurrentBuild).ProductName), $((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName, CurrentBuild).CurrentBuild)"
    "Windows Installation: $([Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem).InstallDate).ToString('dd/MM/yyyy'))"
    "Last Boot up Time: $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" 
    "Last Recycle Bin Clear: $((Get-PSDrive -PSProvider FileSystem | ForEach-Object { Get-ChildItem -Path (Join-Path -Path $_.Root -ChildPath '$Recycle.Bin') -Force -ErrorAction SilentlyContinue } | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime.ToString('dd/MM/yyyy HH:mm:ss'))"
    if ((Get-Item "C:\Windows\Prefetch\taskkill.exe*").LastWriteTime ) { "Last Taskkill: $((Get-Item "C:\Windows\Prefetch\taskkill.exe*").LastWriteTime)" }
    if ((Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=1102) and TimeCreated[timediff(@SystemTime) <= 604800000]]]")) { "Possible Event Log Clearing:"; Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=1102) and TimeCreated[timediff(@SystemTime) <= 604800000]]]" | Select-Object TimeCreated, Message }
}
$sysUptime = "System-Uptime: $((New-TimeSpan -Start (Get-CimInstance Win32_OperatingSystem).LastBootUpTime -End (Get-Date)) | ForEach-Object { "$($_.Days) Days, {0:D2}:{1:D2}:{2:D2}" -f $_.Hours, $_.Minutes, $_.Seconds })"

$documentspath = [System.Environment]::GetFolderPath('MyDocuments')
$settingsxml = Get-Content "$documentspath\Rockstar Games\GTA V\settings.xml"
$linesToCheck = $settingsxml[1..($settingsxml.Length - 1)]
$minusLines = $linesToCheck | Where-Object { $_ -match "-" }
$lodScaleLines = $linesToCheck | Where-Object { $_ -match '<LodScale' -and ([float]($_ -replace '.*value="([0-9.]+)".*', '$1')) -lt 1.0 }
$minusResults = ($minusLines + $lodScaleLines) -join "`n"

$minusSettings = if ($minusResults) {
    "Minus-Settings found in settings.xml:"
    $minusResults
}


Write-Host "   Dumping Process Memory"-ForegroundColor yellow
function Get-ProcessID {
    param(
        [string]$ServiceName
    )
    $processID = (Get-CimInstance -Query "SELECT ProcessId FROM Win32_Service WHERE Name='$ServiceName'").ProcessId
    return $processID
}
$processList1 = @{
    "DPS"       = Get-ProcessID -ServiceName "DPS"
    "DiagTrack" = Get-ProcessID -ServiceName "DiagTrack"
    "WSearch"   = Get-ProcessID -ServiceName "WSearch"
}
$processList2 = @{
    "PcaSvc"   = Get-ProcessID -ServiceName "PcaSvc"
    "explorer" = (Get-Process explorer).Id
    "dwm"      = (Get-Process dwm).Id
}
$processList3 = @{
    "dnscache" = Get-ProcessID -ServiceName "Dnscache"
    "sysmain"  = Get-ProcessID -ServiceName "Sysmain"
    "lsass"    = (Get-Process lsass).Id
}
$processList4 = @{
    "dusmsvc"  = Get-ProcessID -ServiceName "Dnscache"
    "eventlog" = Get-ProcessID -ServiceName "Sysmain"
}
$processList = $processList1 + $processList2 + $processlist3

$uptime = foreach ($entry in $processList.GetEnumerator()) {
    $service = $entry.Key
    $pidVal = $entry.Value

    if ($pidVal -eq 0) {
        [PSCustomObject]@{ Service = $service; Uptime = 'Stopped' }
    }
    elseif ($null -ne $pidVal) {
        $process = Get-Process -Id $pidVal -ErrorAction SilentlyContinue
        if ($process) {
            $uptime = (Get-Date) - $process.StartTime
            $uptimeFormatted = '{0} days, {1:D2}:{2:D2}:{3:D2}' -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds
            [PSCustomObject]@{ Service = $service; Uptime = $uptimeFormatted }
        }
        else {
            [PSCustomObject]@{ Service = $service; Uptime = 'Stopped' }
        }
    }
    else {
        [PSCustomObject]@{ Service = $service; Uptime = 'Stopped' }
    }
}

$sUptime = $uptime | Sort-Object Service | Format-Table -AutoSize -HideTableHeaders | Out-String

foreach ($entry in $processList1.GetEnumerator()) {
    $service = $entry.Key
    $pidVal = $entry.Value
    if ($null -ne $pidVal) {
        & "$dmppath\strings2.exe" -s -a -t -l 5 -pid $pidVal | Select-String -Pattern "\.exe|\.bat|\.ps1|\.rar|\.zip|\.7z|\.dll" | Set-Content -Path "$procpathraw\$service.txt" -Encoding UTF8
    }
}

foreach ($entry in $processList2.GetEnumerator()) {
    $service = $entry.Key
    $pidVal = $entry.Value
    if ($null -ne $pidVal) {
        & "$dmppath\strings2.exe" -l 5 -pid $pidVal | Select-String -Pattern "\.exe|\.bat|\.ps1|\.rar|\.zip|\.7z|\.dll|file:///" | Set-Content -Path "$procpathraw\$service.txt" -Encoding UTF8
    }
}

foreach ($entry in $processList3.GetEnumerator()) {
    $service = $entry.Key
    $pidVal = $entry.Value
    if ($null -ne $pidVal) {
        & "$dmppath\strings2.exe" -s -a -t -l 5 -pid $pidVal | Set-Content -Path "$procpathraw\$service.txt" -Encoding UTF8
    }
}

$prepaths = "$procpathraw\dps.txt", "$procpathraw\diagtrack.txt", "$procpathraw\wsearch.txt", "$procpathraw\lsass.txt", "$procpathraw\sysmain.txt", "$procpathraw\dnscache.txt"

foreach ($lines in $prepaths) {
    $content = Get-Content $lines | ForEach-Object { $_.Split(',')[-1].Trim() }
    $content | Set-Content $lines
}

Write-Host "   Dumping USN Journal"-ForegroundColor yellow
Set-Location "$dmppath\Journal"
$usnjournal = & fsutil usn readjournal c: csv 
$usnjournal | Out-File 0_FullRawDump.csv
$usnjournal |
Select-Object -Skip 8 |
ConvertFrom-Csv -Header a, FileName, c, Reason#, Reason, Time, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u |
Where-Object { $_.'FileName' -match '\.exe.*|\.rar|\.zip|\.7z|\.bat|\.ps1|\.pf' } |
Select-Object 'FileName', 'Time', 'Reason', 'Reason#' |
Export-Csv -Path "0_RawDump.csv" -Encoding utf8 -NoTypeInformation
$dmp = Import-Csv "0_RawDump.csv"
$dmp | Where-Object { $_.'FileName' -match "\.pf" -and ($_.'Reason#' -match "0x00001000|0x00002000") } | Select-Object 'FileName', 'Time' | Sort-Object 'Time' -Descending -Unique | Out-File DeletedPF.txt -Append
$dmp | Where-Object { $_.'FileName' -like "*.exe*" -and $_.'Reason#' -eq '0x00000100' -and $_.'Filename' -notlike '*.pf' } | Select-Object 'FileName', 'Time' | Sort-Object 'Time' -Descending -Unique | Out-String -Width 1000 | Format-Table -HideTableHeaders | Out-File CreatedFiles.txt -Append
$dmp | Where-Object { $_.'FileName' -like "*.exe*" -and $_.'Reason#' -eq '0x80000200' } | Select-Object 'FileName', 'Time' | Out-String -Width 1000 | Out-File DeletedFiles.txt -Append
$dmp | Where-Object { '0x00001000', '0x00002000' -contains $_.'Reason#' } | Sort-Object -Property Time -Descending | Group-Object "Time" | Format-Table -AutoSize @{l = "Timestamp"; e = { $_.Name } }, @{l = "Old Name"; e = { $_.Group.'FileName'[0] } }, @{l = "New Name"; e = { $_.Group.'FileName'[1] } } | Out-File -FilePath Renamed_Files.txt -Append
$dmp | Where-Object { $_.'FileName' -match '\.rpf' -and $_.'Reason#' -match '0x80000200|0x00000004|0x00000006|0x80000006' } | Select-Object 'FileName', 'Time' | Sort-Object 'Time' -Descending -Unique | Out-File Deletedrpf.txt -Append
$dmp | Where-Object { $_.'FileName' -match '\.rar|\.zip|\.7z' } | Select-Object 'FileName', 'Time' | Sort-Object 'Time' -Descending -Unique | Out-File Compressed.txt -Append
$dmp | Where-Object { $_.'FileName' -match "\.bat" -and $_.'Reason#' -match "0x00001000|0x80000200" } | Select-Object 'FileName', 'Time' | Sort-Object 'Time' -Descending -Unique | Out-File ModifiedBats.txt -Append
$dmp | Where-Object { $_.'FileName' -match "\.exe" -and $_.'Reason#' -match "0x00080000" } | Select-Object 'FileName', 'Time' | Sort-Object 'Time' -Descending -Unique | Out-File ObjectIDChange.txt -Append
$dmp | Where-Object { $_.'Reason' -match "Data Truncation" -and $_.'FileName' -match "\.exe" -and $_.'Filename' -notlike '*.pf' } | Select-Object 'FileName', 'Time' | Sort-Object 'Time' -Descending -Unique | Out-File ReplacedExe.txt -Append
$dmp | Where-Object { $_.'Reason#' -match "\?" } | Select-Object 'FileName', 'Time' | Sort-Object 'Time' -Descending -Unique | Out-File EmptyCharacter.txt -Append
$o2 = Get-Content "$dmppath\Journal\0_RawDump.csv" | Select-String -Pattern "1337|skript|usbdeview|loader_64|abby|ro9an|hitbox|gouhl|revolver|w32|vds|systeminformer|hacker" | Select-Object -ExpandProperty Line | Sort-Object -Unique
$o2 | Out-File Keywordsearch.txt
$susJournal = if ($o2) { "Suspicious Files found in Journal" }
Set-Location "$dmppath\prefetch"

Write-Host "   Checking Dumping-File Integrity"-ForegroundColor yellow
$files = @("$dmppath\prefetch\Prefetch.csv", "$shellbagspath\*Usrclass.csv", "$evtrawpath\Application.csv", "$evtrawpath\Security.csv", "$evtrawpath\System.csv", "$evtrawpath\Powershell.csv", "$evtrawpath\KernelPnp.csv", "$evtrawpath\Defender.csv", "$evtrawpath\Timeservice.csv")
$missing = $files | Where-Object { -not (Test-Path $_) }
if ($missing) { "Missing Files - Dump Failed:"; $missing }

$prefpath = "C:\temp\dump\prefetch\prefetch.csv"
$prefcol = "ExecutableName", "SourceCreated", "SourceModified", "LastRun", "RunCount", "Hash", "PreviousRun0", "PreviousRun1", "PreviousRun2", "PreviousRun3", "PreviousRun4", "PreviousRun5", "PreviousRun6", "Volume0Serial", "FilesLoaded"
$prefkey = "*Anydesk*", "*Brave*", "*Chrome*", "CMD*", "*CODE*", "*Conhost*", "*Consent*", "*Discord*", "*DLLHost*", "*Explorer*", "*Firefox*", "*mpcmdrun*", "*msedge*", "*Openwith*", "*Opera*", "*Powershell*", "*processhacker*", "reg*", "regedit*", "*REGSVR32*", "rundll32", "Smartscreen", "*systeminformer*", "*Taskkill*", "*usbdeview*", "*Winrar*", "*WMIC*", "*VSSVC*"
$preffilter = Import-Csv -Path $prefpath
$preffiltered = $preffilter | Where-Object {
    $prefmatch = $false
    foreach ($key in $prefkey) {
        if ($_.ExecutableName -like $key) {
            $prefmatch = $true
            break
        }
    }
    $prefmatch
} | Select-Object $prefcol | Sort-Object ExecutableName
$preffiltered | Export-Csv -Path "C:\temp\dump\prefetch\Prefetch_Filtered.csv" -NoTypeInformation

Write-Host "   Dumping Threat Information"-ForegroundColor yellow
$dStatus = Get-MpComputerStatus
if ($dStatus.AntivirusEnabled) {
    $DefenderStatus = "Windows Defender is running.`n"
}
else {
    $DefenderStatus = "Windows Defender is not running.`n"
}
$threats1 = "Detection History Logs:`n"
$threats1 += (Get-ChildItem "C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service" | Select-Object LastWriteTime, Name | Out-String)
$threats2 = "Exclusions:`n" + ((Get-MpPreference).ExclusionPath -join "`n")
$threats3 = "`nThreats:`n" + ((Get-MpThreatDetection | Select-Object -ExpandProperty Resources) -join "`n")

Write-Host "   Dumping WinsearchDB"-ForegroundColor yellow
Stop-Service wsearch -Force
Copy-Item C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb $winsearchpath\Windows.edb -Force
C:\temp\dump\SQLECmd\SQLECmd.exe -f "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows-gather.db" --csv "C:\temp\dump\Winsearch" --csvf Winsearch.csv | Out-Null
C:\temp\dump\ESEDatabaseView.exe /table "$winsearchpath\Windows.edb" "SystemIndex_PropertyStore" /scomma $winsearchpath\WinSearchDB.csv /Columns "4565-System_ParsingName,4562-System_OriginalFileName,4443-System_ItemNameDisplay,4183-System_Company,4106-System_ThumbnailCahceID,4431-System_IsEntrypted,4447-System_ItemPathDisplay"
(Get-Date).ToString("MMMM d, yyyy HH:mm:ss") | Out-File -FilePath "C:\Windows\System32\Info.txt" -Append

Write-Host "   Dumping SystemTask and Program Information Logs"-ForegroundColor yellow
$taskpaths = "$otherpath\Tasks.txt"
"`nScheduled Tasks: $l4" | Out-File -FilePath $taskpaths -Append
(Get-ScheduledTask | Format-Table -AutoSize | Out-String) | Out-File -FilePath $taskpaths -Append
"`nScheduled Jobs: $l4" | Out-File -FilePath $taskpaths -Append
(Get-ScheduledJob | Format-Table -AutoSize | Out-String) | Out-File -FilePath $taskpaths -Append
Get-WmiObject -class Win32_Share | Out-File -FilePath "$otherpath\SharedFolders.txt"
$progrpaths = "$otherpath\Programs.txt"
"`nInstalled Programs: $l4" | Out-File -FilePath $progrpaths -Append
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher | Out-File -FilePath $progrpaths
$o6 = (Get-Content -Path $progrpaths | Where-Object { $_ -match "informer|hacker" }) -join "`n"; if ($o6) { $o6 = "Suspicious Installs:`n$o6" }
$o7 = (Get-DnsClientCache | Where-Object { $_ -match "skript|leet-cheats|hydrogen|astra|sellix|octo|reselling|wannacry|rosereselling|para|para.casino" }) -join "`n"; if ($o7) { $o7 = "Suspicious Local-DNS Entries:`n$o7" }
$dnssus = ($dns | Sort-Object -Unique) -join "`n"; if ($dns) { $dnssus = "Suspicious Process-DNS Entries:$l4$dnssus" }

Write-Host "   Sorting and Filtering Logs"-ForegroundColor yellow
$evtfiles = @(
    "$evtrawpath\Application.csv",
    "$evtrawpath\Security.csv",
    "$evtrawpath\System.csv",
    "$evtrawpath\Powershell.csv",
    "$evtrawpath\KernelPnp.csv",
    "$evtrawpath\Defender.csv",
    "$evtrawpath\Timeservice.csv"
)

$events = $evtfiles | ForEach-Object { Import-Csv $_ } | Export-Csv "$evtrawpath\Eventlog.csv" -NoTypeInformation

$events = Import-Csv "$evtrawpath\Eventlog.csv"
$events | ForEach-Object {
    $_.TimeCreated = [datetime]::Parse($_.TimeCreated).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
}

$events | Select-Object EventId, TimeCreated, Level, Provider, MapDescription, ExecutableInfo, PayloadData1, PayloadData2, PayloadData3, PayloadData4 |
Sort-Object TimeCreated -Descending |
Export-Csv -Path "$evtrawpath\Eventlog.csv" -NoTypeInformation
$events = Import-Csv "$evtrawpath\Eventlog.csv"

$filteredEvents = @{
    "Tampering_Events"        = { $_.EventId -match '\b(51|52|104|257|258|259|260|261|263|264|265|266|272|601|1102|3079|4100|4103|4104|4670|6005|6006|6008|6013|8194|8195|8196)\b' }
    "Defender_Events"         = { $_.EventId -match '\b(1003|1006|1007|1116|1117|1121|1122|1123|1150|2000|2010|5000|5001|5002|5007|11170|11171|11172)\b' }
    "Application_Events"      = { $_.EventId -match '\b(1001|1102|4656|4660|4663)\b' }
    "USB_Events"              = { $_.EventId -match '\b(400|410|420|430|1006)\b' }
    "Network_Events"          = { $_.EventId -match '\b(104|105|5140|5145)\b' }
    "Service_Events"          = { $_.EventId -match '\b(7030|7031|7034|7040|7045)\b' }
    "Thread_Detection_Events" = { $_.EventId -match '\b(1116|1117)\b' }
}

foreach ($filterName in $filteredEvents.Keys) {
    $filter = $filteredEvents[$filterName]
    $outputPath = "$dmppath\events\$filterName.csv"

    $events | Where-Object $filter | 
    Select-Object "TimeCreated", "EventId", "Level", "MapDescription", "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6", "Provider", "HiddenRecord" |
    Export-Csv $outputPath -NoTypeInformation -Force
}

$EventPaths = @(
    "$dmppath\events\Thread_Detection_Events.csv",
    "$dmppath\events\Service_Events.csv"
    "$dmppath\events\USB_Events.csv",
    "$dmppath\events\Application_Events.csv"
    "$dmppath\events\Tampering_Events.csv"  
)
$OutEvents = "$dmppath\events\0_Event_Results.txt"
New-Item -Path $OutEvents -ItemType File -Force > $null

foreach ($path in $EventPaths) {
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($path)
    Add-Content -Path $OutEvents -Value "$fileName`n" | Out-Null

    $csvData = Import-Csv -Path $path | Select-Object -First 10
    $csvData | ForEach-Object {
        $line = $_ | ConvertTo-Csv -NoTypeInformation | Select-Object -Last 1
        $truncatedLine = $line.Substring(0, [Math]::Min(100, $line.Length))
        Add-Content -Path $OutEvents -Value $truncatedLine | Out-Null
    }

    Add-Content -Path $OutEvents -Value "`n" | Out-Null
}

$eventResults = Get-Content "$dmppath\events\0_Event_Results.txt"
$threats5 = Get-Content "$dmppath\events\Thread_Detection_Events.csv"

$volumeDict = @{}

foreach ($row in $preffiltered) {
    if ($row.Volume0Serial.Length -gt 2) {
        if (-not $volumeDict.ContainsKey($row.ExecutableName)) {
            $volumeDict[$row.ExecutableName] = @()
        }
        $volumeDict[$row.ExecutableName] += $row.Volume0Serial
    }
}
$PrefMismatch = $volumeDict.Keys | Where-Object {
    ($volumeDict[$_] | Select-Object -Unique | Measure-Object).Count -gt 1
} | ForEach-Object {
    "Volume Mismatch found in: $_"
}
$PrefMismatch | Out-File "$dmppath\Prefetch\Prefetch_VolumeMismatch.txt"
$PrefLowRun = $preffiltered | 
Where-Object { [int]$_.RunCount -lt 10 } | 
Select-Object ExecutableName, RunCount, Size
$PrefLowRun | Out-File "$dmppath\Prefetch\Prefetch_RunCount.txt"

$PrefFilesLoaded = @()
foreach ($item in $preffiltered) {
    $fileMatches = [regex]::Matches($item.FilesLoaded, '\\([^\\]+\.(exe|bat|ps1))', 'IgnoreCase')
    foreach ($match in $fileMatches) {
        $loadedfileName = $match.Groups[1].Value
        if ($loadedfileName -ne $item.ExecutableName) {
            $PrefFilesLoaded += "$loadedfileName found in $($item.ExecutableName)"
        }
    }
}
$PrefFilesLoaded | Out-File "$dmppath\Prefetch\Prefetch_FilesLoaded.txt"

$userclass = Get-Item "C:\temp\dump\shellbags\*usrclass.csv"
$shellbagsRaw = Import-Csv $userclass.FullName

$shellbagsDrive = ($shellbagsRaw | Where-Object { $_.ShellType -like "*Drive*" } | Select-Object -Unique ShellType, Value | ForEach-Object { "$($_.ShellType): $($_.Value)" }) -join "`r`n"
$shellbagsDir = ($shellbagsRaw | Where-Object { $_.ShellType -eq "Directory" } | Select-Object -Unique AbsolutePath | ForEach-Object { "$($_.AbsolutePath)" }) -join "`r`n"

$driveResults = "Drives found in Shellbags$l4$shellbagsDrive"
$dirResults = "Directories found in Shellbags$l4$shellbagsDir"

$driveResults + "`r`n`r`n" + $dirResults | Out-File "C:\temp\dump\shellbags\Shellbags_Result.txt"

"Compressed Files in Activities Cache$l4" + (Get-ChildItem -Path $acpath -Filter "*Activity.csv" | ForEach-Object { Import-Csv $_.FullName | Where-Object { $_.DisplayText -match '^[a-zA-Z0-9_-]+\.(rar|zip|7z)' } | ForEach-Object { $_.DisplayText -replace '\s*\(.*\)$' } } | Out-String) | Set-Content -Path "$acpath\Compressed_Timeline.txt" -Force
"`nOpened compressed Files in Activities Cache$l4" + (Get-ChildItem -Path $acpath -Filter "*PackageIDs.csv" | ForEach-Object { Import-Csv $_.FullName | Where-Object { $_.Name -match '\\temp\\' -and $_.Name -match 'rar|zip|7z|tar|gz' } | ForEach-Object { $_.Name } } | Out-String) | Add-Content -Path "$acpath\Compressed_Timeline.txt"
"Executable Files in Activities Cache$l4" + (Get-ChildItem -Path $acpath -Filter "*Activity.csv" | ForEach-Object { Import-Csv $_.FullName | Where-Object { $_.DisplayText -match '^[a-zA-Z0-9_-]+\.(.exe)' } | ForEach-Object { $_.DisplayText -replace '\s*\(.*\)$' } } | Out-String) | Set-Content -Path "$acpath\Executables_Timeline.txt" -Force
"`nOpened Executable Files in Activities Cache$l4" + (Get-ChildItem -Path $acpath -Filter "*PackageIDs.csv" | ForEach-Object { Import-Csv $_.FullName | Where-Object { $_.Name -match '\\temp\\' -and $_.Name -match '.exe' } | ForEach-Object { $_.Name } } | Out-String) | Add-Content -Path "$acpath\Executables_Timeline.txt"
$activityFile = Get-ChildItem -Path "$acpath\*Activity.csv" | Select-Object -First 1
$packageFile = Get-ChildItem -Path "$acpath\*PackageIDs.csv" | Select-Object -First 1

$activityData = Import-Csv $activityFile.FullName | Where-Object { $_.Executable -match '^[a-zA-Z]:\\' } | Group-Object Executable | ForEach-Object { $_.Group | Sort-Object StartTime -Descending | Select-Object -First 1 } | ForEach-Object { $_.Executable }
$packageData = Import-Csv $packageFile.FullName | Where-Object { $_.Path -match '^[A-Za-z]:\\.*\.exe$' } | ForEach-Object { $_.Path }
$TLpaths = $activityData + $packageData
$activityData = Import-Csv -Path $activityFile.FullName | Select-Object LastModifiedTime, Executable, Displaytext, ContentInfo, ExpirationTime, StartTime, LastModifiedOnClient, Payload, PackageIdHash
$packageData = Import-Csv -Path $packageFile.FullName | Select-Object Expires, Name, AdditionalInformation
$activityData | Export-Csv -Path $activityFile.FullName -NoTypeInformation
$packageData | Export-Csv -Path $packageFile.FullName -NoTypeInformation

$shimtemp = "$shimcachepath\Shimcache_temp.csv"; Import-Csv "$shimcachepath\Shimcache.csv" | Select-Object Path, LastModifiedTimeUTC, Executed | Export-Csv $shimtemp -NoTypeInformation; Move-Item -Path $shimtemp -Destination "$shimcachepath\Shimcache.csv" -Force
$shimPaths = Import-Csv "$shimcachepath\Shimcache.csv" | Where-Object { $_.Path -match '^[A-Za-z]:\\.*\.exe$' } | Select-Object Path

Set-Location "$procpathraw"
$procpaths = Get-Content explorer.txt, pcasvc.txt, wsearch.txt | Where-Object { $_ -match "^[A-Za-z]:\\.+\.exe$" }

$displaytxt = Get-Content explorer.txt | Where-Object { $_ -match '"displayText"' }
$displaytxt | Sort-Object -Unique -Descending | Out-File "$procpath\Displaytext.txt"

$dll = Get-Content wsearch.txt, explorer.txt | Where-Object { $_ -match "^[A-Za-z]:\\.*\.dll$" }
$dll | Sort-Object -Unique -Descending | Out-File "$procpath\DLL.txt"

$dns = Get-Content lsass.txt, dnscache.txt | Where-Object { $_ -match "skript|leet|cheats|sellix|hydrogen|astra|reselling|vanish" }
$dns | Sort-Object -Unique | Out-File "$procpath\DNS_Cache.txt"

$DPSString = "$Astra|$Hydro|$Leet|$Skript"
$dps1 = (Get-Content dps.txt | Where-Object { $_ -match '\.exe' -and $_ -match '!0!' } | Sort-Object) -join "`n"
$predps2 = Get-Content dps.txt | Where-Object { $_ -match '!!.*2024' } | Sort-Object
$dps2grouped = ($predps2 | ForEach-Object { $_ -replace '!!(.+?)!.*', '$1' } | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Group } | Select-Object -Unique)
$dps2 = $predps2 | Where-Object { $_ -match ('!!' + ($dps2grouped -join '|') + '!') }
$dps2 = $dps2 -join "`n"
$dps3 = (Get-Content dps.txt | Where-Object { $_ -match '!!.*2024' } | Sort-Object) -join "`n"
$dps4 = (Get-Content dps.txt | Where-Object { $_ -match '!!' -and $_ -match 'exe' } | Sort-Object -Unique) -join "`n"
$dps4 | Where-Object { $_ -match $DPSString } | Add-Content -Path "DPS_Cheat.txt"
$dps = "DPS Null`n$dps1`n`nDPS Doubles`n$dps2`n`nDPS Dates`n$dps3`n`nDPS Executables`n$dps4"
$dps | Out-File "$procpath\DPS_Filtered.txt"

$dwm1 = (Get-Content dwm.txt | Where-Object { $_ -match "\)\s\(0x" }) -join "`n"
$dwm2 = (Get-Content dwm.txt | Where-Object { $_ -match "(shrink [A-Za-z]:)|(Extend Volume)|(Verkleinern von)|(Erweitern von)" }) -join "`n"
$dwm3 = (Get-Content dwm.txt | Where-Object { $_ -match "Console -|\[Event|\[Ereignis" }) -join "`n"
$dwm = "Possible String Manipulation Detected`n$dwm1`n`nPossible Volume Manipulation Detected`n$dwm2`n`nPossible Eventlog Manipulation Detected`n$dwm3"
$dwm | Out-File "$procpath\DWM_Manipulation.txt"

$fileSlash = Get-Content wsearch.txt, explorer.txt | Where-Object { $_ -match "file:///" } | ForEach-Object { $_ -replace "file:///", "" }
$fileSlash | Out-File "$procpath\Files_Visited.txt"

$hdv = Get-Content explorer.txt, diagtrack.txt | Where-Object { $_ -match "HarddiskVolume" } | ForEach-Object { if ($_ -match "HarddiskVolume(\d+)") { [PSCustomObject]@{ Line = $_; Number = $matches[1] } } } | Group-Object Number | Sort-Object Count | ForEach-Object { $_.Group.Line } | Select-Object -Unique
$hdv | Out-File "$procpath\Harddiskvolumes.txt"

$invis = Get-Content explorer.txt | Where-Object { $_ -match "[A-Z]:\\.*[^\x00-\x7F].*\.exe" }
$invis | Out-File "$procpath\Invisible_Chars.txt"

$modext1 = Get-Content dps.txt | Where-Object { $_ -match "^!![A-Z]((?!Exe).)*$" }
$modext2 = Get-Content diagtrack.txt | Where-Object { $_ -match "^\\device\\harddiskvolume((?!Exe|dll).)*$" }
$modext = "Possible Modification of Extensions in DPS$l4$modext1 `nPossible Modification of Extensions in Diagtrack$l4$modext2"
$modext | Out-File "$procpath\Modified_Extensions.txt"

$pca1 = Get-Content explorer.txt | Where-Object { $_ -match "pcaclient" } | ForEach-Object { if ($_ -match "[A-Z]:\\.*?\.exe") { $matches[0] } }
$pca1 | Sort-Object -Unique -Descending | Out-File "$procpath\PcaClient.txt"

$pca2 = Get-Content pcasvc.txt | Where-Object { $_ -match "TRACE," }
$pca2 | Sort-Object -Unique -Descending | Out-File "$procpathraw\Pca_Extended_Raw.txt"
$pca3 = $pca2 | ForEach-Object { if ($_ -match "[A-Z]:\\.*?\.exe") { $matches[0] } }
$pca3 | Sort-Object -Unique -Descending | Out-File "$procpath\Pca_Extended.txt"

$procADS = Get-Content explorer.txt, wsearch.txt | Where-Object { $_ -match "^([A-Za-z]:\\.+)\\?$" }
$procADS | Out-File "$procpath\ADS.txt"

$proccomp2 = Get-Content explorer.txt, pcasvc.txt, diagtrack.txt | Where-Object { $_ -match "^[a-zA-Z0-9_-]+\.(rar|zip|7z)$" }
$proccomp2 | Out-File "$procpath\Compressed_Processes.txt"

$procexes = Get-Content explorer.txt | Where-Object { $_ -match "^\b(?!C:)[A-Z]:\\.*" }
$procexes | Sort-Object -Unique -Descending | Out-File "$procpath\Drive_Executables.txt"

$procscripts = Get-Content explorer.txt | Where-Object { $_ -match "^[a-zA-Z0-9_-]+\.(bat|ps1)$" }
$procscripts | Sort-Object -Unique -Descending | Out-File "$procpath\Scripts.txt"

$sysmain = Get-Content sysmain.txt | Where-Object { $_ -match "C:\\windows\\prefetch" }
$sysmain | Sort-Object -Unique -Descending | Out-File "$procpath\Sysmain_Mod_Ext.txt"
$sysmainext = Get-Content sysmain.txt | Where-Object { $_ -match "C:\\windows\\prefetch((?!Exe).)*$" }
$sysmainext | Sort-Object -Unique -Descending | Out-File "$procpath\Sysmain_Mod_Ext.txt"

$tempComp = Get-Content wsearch.txt, explorer.txt | Where-Object { $_ -match "Local\\Temp.*\.exe" }
$tempComp | Sort-Object -Unique -Descending | Out-File "$procpath\Compressed_Temp.txt"

if (Test-Path "C:\windows\appcompat\pca\PcaAppLaunchDic.txt") { Copy-Item "C:\windows\appcompat\pca\PcaAppLaunchDic.txt" -Destination "C:\temp\dump\processes\raw" }
$pca4 = (Get-Content "C:\temp\dump\processes\raw\PcaAppLaunchDic.txt" | ForEach-Object { ($_ -replace '\|.*') } | Where-Object { $_ -match '^[A-Za-z]:\\' })
$pca4 | Out-File "$procpath\Pca_Extended2.txt"

@($TLpaths; $procpaths; $pca1; $pca3; $pca4; $shimPaths) | Sort-Object -Unique | Add-Content -Path "$dmppath\Paths.txt" -Encoding UTF8

Get-Content "$dmppath\Paths.txt" | ForEach-Object { if (Test-Path $_) { $signature = Get-AuthenticodeSignature -FilePath $_; if ($signature.Status -ne 'Valid') { $_ } } } | Out-File "$dmppath\Unsigned.txt"

$paths = Get-Content $dmppath\Paths.txt

$filesizeFound = @()
$noFilesFound = @()
Get-Content "$dmppath\Paths.txt" | ForEach-Object {
    $fPa = $_
    if (Test-Path $fPa) {
        $fSi = (Get-Item $fPa).Length
        if ($fSi -ge ($filesizeL) -and $fSi -le ($filesizeH)) {
            $filesizeFound += $fPa
        }
    }
    else {
        $noFilesFound += "File Deleted: $fPa"
    }
}
$filesizeFound | Out-File "$dmppath\Filesize.txt"
$noFilesFound | Out-File "$dmppath\Deletedfile.txt"

$programPaths = "C:\temp\dump\Unsigned.txt"
$peOutput = "C:\temp\dump\PE_Headers.csv"

function Get-PEHeaders {
    param (
        [string]$FilePath
    )

    $headers = @{
        FilePath = $FilePath
        EntryPoint = $null
        DebugDirectoryRVA = $null
        IsDosExecutable = $false
        CannotRunInDosMode = $false
    }

    if (-Not (Test-Path -Path $FilePath)) {
        return [PSCustomObject]$headers
    }

    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $dosHeader = [System.BitConverter]::ToUInt16($fileBytes, 0)
        $isDosExecutable = $dosHeader -eq 0x5A4D

        $headers.IsDosExecutable = $isDosExecutable

        if ($isDosExecutable) {
            $peHeaderOffset = [System.BitConverter]::ToInt32($fileBytes, 60)
            $peHeaderSignature = [System.Text.Encoding]::ASCII.GetString($fileBytes, $peHeaderOffset, 4)
            if ($peHeaderSignature -ne "PE`0`0") {
                throw "Invalid PE header signature"
            }

            $optionalHeaderOffset = $peHeaderOffset + 24
            $entryPoint = [System.BitConverter]::ToUInt32($fileBytes, $optionalHeaderOffset + 16)
            $headers.EntryPoint = "0x" + [System.String]::Format("{0:X}", $entryPoint)

            $debugDirectoryRVA = [System.BitConverter]::ToUInt32($fileBytes, $optionalHeaderOffset + 92)
            $headers.DebugDirectoryRVA = "0x" + [System.String]::Format("{0:X}", $debugDirectoryRVA)
        }

        $cannotRunInDosMode = [System.IO.File]::ReadAllText($FilePath) -match '!This program cannot be run in DOS mode.'
        $headers.CannotRunInDosMode = $cannotRunInDosMode
    }
    catch {
        return [PSCustomObject]$headers
    }

    return [PSCustomObject]$headers
}

$filePaths = Get-Content -Path $programPaths

$peHeaders = foreach ($filePath in $filePaths) {
    Get-PEHeaders -FilePath $filePath
}
$peHeaders | Export-Csv -Path $peOutput -NoTypeInformation
$peHeaders | Where-Object { -not $_.DebugDirectoryRVA -or $_.DebugDirectoryRVA -eq "0x0" } | ForEach-Object { $_.FilePath } | Set-Content -Path "$dmppath\Debug.txt"

Get-Content "$dmppath\Paths.txt" | ForEach-Object { if (Test-Path $_) { $signature = Get-AuthenticodeSignature -FilePath $_; if ($signature.Status -ne 'Valid') { $_ } } } | Out-File "$dmppath\Unsigned.txt"

(Get-Content "$dmppath\Dps.txt" | Where-Object { $_ -match '!!(.*?)!$' } | Sort-Object -Unique) | Set-Content "$dmppath\Dps.txt"

Get-Content "$dmppath\Unsigned.txt" | ForEach-Object { $_ | Where-Object { ($_ -in (Get-Content "$dmppath\Debug.txt")) -and ($_ -in (Get-Content "$dmppath\Filesize.txt")) } } | Set-Content "$procpath\Combined.txt"

$r = Import-Csv '$dmppath\prefetch\prefetch.csv' | Group-Object ExecutableName | ForEach-Object { $g = $_; $u = $g.Group | Select-Object -u Volume0Name; if ($u.Count -gt 1) { $g.Group | Select-Object ExecutableName, Volume0Name, LastRun } } | Format-Table -AutoSize -HideTableHeaders | Sort-Object -Unique | Out-String; if ($r -ne "") { $r | Out-File '$dmppath\Prefetch\Prefetch_Sus.txt' }

$combine = Get-Content "$procpath\Combined.txt"

Write-Host "   Checking for Tamperings"-ForegroundColor yellow
$usnTampering = if ($usnjournal.Length -lt 94491) { "`nPotential Manipulation in USNJournal Detected - Filesize: $($usnjournal.Length)" }
$usnTampering2 = if ($usnjournal.Count -lt 150000) { "`nPotential Manipulation in USNJournal Detected - RowCount: $($usnjournal.Count)" }

$evtTampering = ("`nEventvwr Registration: $((Get-Item ""$env:APPDATA\Microsoft\MMC\eventvwr"").LastWriteTime)")
$evtTampering2 = ("`nEventvwr Settings: $((Get-Item ""$env:LOCALAPPDATA\Microsoft\Event Viewer\Settings.Xml"").LastWriteTime)")
$evtlogFolderPath = "C:\Windows\System32\winevt\Logs"
$evtlogFiles = @("Microsoft-Windows-Windows Defender%4Operational.evtx", "Application.evtx", "Security.evtx", "System.evtx", "Windows PowerShell.evtx", "Microsoft-Windows-Kernel-PnP%4Configuration.evtx", "Microsoft-Windows-PowerShell%4Operational.evtx")
$evtTampering3 = $evtlogFiles | ForEach-Object {
    $path = Join-Path $evtlogFolderPath $_
    if (Test-Path $path) {
        $info = Get-Item $path
        if ($info.LastAccessTime -gt $info.LastWriteTime) {
            "`n$($info.Name -replace '\.evtx$') potentially manipulated"
        }
    }
}

$filesToCheck = @("Discord.exe", "VSSVC.exe", "reg.exe", "cmd.exe", "MpCmdRun.exe", "msedge.exe")
$missingFiles = $filesToCheck | Where-Object { -not ($preffiltered.executablename -contains $_) }
$prefTampering = if ($missingFiles) { 
    "`nPotential Manipulation in Prefetch Detected - Missing Files: $($missingFiles -join ', ')"
}
$prefhideTampering = (Get-ChildItem -Force "C:\Windows\Prefetch" | ForEach-Object {
        $attributes = $_.Attributes
        if ($attributes -band [System.IO.FileAttributes]::Hidden -or $attributes -band [System.IO.FileAttributes]::ReadOnly) {
            "`nPotential File Manipulation Detected (Hidden or Read-Only): $_"
        }
    }) -join "`n"

$volTampering = (Get-ChildItem -Path "C:\Windows\Prefetch" -Filter "vds*.exe*.pf" | ForEach-Object { "Potential Virtual Disk Manipulation - $($_.LastWriteTime)" }) -join "`n"
$volTampering2 = if (-not (Test-Path "C:\windows\inf\setupapi.dev.log") -or ((Get-Item "C:\windows\inf\setupapi.dev.log").LastWriteTime -lt (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime)) { 
    "`nPotential Volume Manipulation - SetupAPI Manipulated" 
}
elseif (Get-Content "C:\windows\inf\setupapi.dev.log" -Force | Select-String "vds.exe") { 
    "Potential Volume Manipulation found in Setupapi" 
}

$unicodeTpath1 = "$dmppath\Journal\0_RawDump.csv"
$unicodeTpath2 = "$dmppath\Paths.txt"
$unicodeTdata1 = Import-Csv $unicodeTpath1 | Where-Object { $_.FILENAME -match '\?.exe' -or $_.FILENAME -match '\?.dll' -or $_.FILENAME -match '(?![äöüß])[^\x00-\x7F]' }
$unicodeTdata2 = Get-Content $unicodeTpath2 | Where-Object { $_ -match '\?.exe' -or $_ -match '\?.dll' -or $_ -match '(?![äöüß])[^\x00-\x7F]' }
$unicodeTampering = $unicodeTdata1 + $unicodeTdata2
if ($unicodeTampering) { $unicodeTampering = $unicodeTampering | ForEach-Object { "Possible Unicode Manipulation found in Journal or Process - $_" } }

$bamTampering = if ($susreg = @('HKLM\SYSTEM\ControlSet001\Services\bam\State\UserSettings', 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched', 'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache', 'HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store') | ForEach-Object { (reg query $_ /s | Select-String -Pattern 'usbdeview|explorer.exe|.*[a-z0-9]{20}\.exe' | ForEach-Object { if ($_.Line -match '(.*?\.exe)\b') { $_.Matches.Groups[1].Value } } | Sort-Object -Unique) }) { "Registry Keys with Suspicious Names:"; $susreg }
$timeTampering = if (Get-WinEvent -FilterHashtable @{LogName = 'System'; ProviderName = 'Microsoft-Windows-Time-Service'; Level = 3 } -MaxEvents 1) { "Possible Time Tampering found in Eventlogs" }

$hideTampering = ($paths | Where-Object { Test-Path $_ } | ForEach-Object { if ((Get-ChildItem -Force $_).Attributes -match "Hidden") { "Potential Hidden File Manipulation Detected: $_" } }) -join "`n"

$wmicTampering = if (Select-String -Path "C:\Temp\Dump\Processes\Raw\explorer.txt" -Pattern "Process call|call create") { "Potential WMIC bypassing found in Explorer" }

$processList += $processList4
function Get-LoadedDlls {
    param (
        [int]$processId,
        [hashtable]$dllPatterns
    )

    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if (-not $process) { return $false }

    $dllsInProcess = $process.Modules | Select-Object -ExpandProperty FileName

    $notLoaded = $dllPatterns.GetEnumerator() | Where-Object {
        $pattern = $_.Value
        -not ($dllsInProcess | Where-Object { [System.IO.Path]::GetFileName($_) -like $pattern })
    }

    $notLoaded.Count -gt 0
}

$processDllMapping = @{
    "SysMain"  = "sechost.dll*"
    "DPS"      = "dps.dll*"
    "PcaSvc"   = "pcasvc.dll*"
    "eventlog" = "wevtsvc.dll*"
    "DusmSvc"  = "wlanapi.dll*"
}

$threadTampering = @()

foreach ($process in $processList) {
    $processName = $process.Key
    $processId = $process.Value

    if ($processDllMapping.ContainsKey($processName)) {
        $dllPatterns = @{ $processName = $processDllMapping[$processName] }

        if (Get-LoadedDlls -processId $processId -dllPatterns $dllPatterns) {
            $threadTampering += "Possible Thread Manipulation found in - $processName"
        }
    }
}

$regFiles = Get-ChildItem -Path $regpath -Filter *.csv -File
$regTampering = ""

foreach ($regFile in $regFiles) {
    $csvContent = Import-Csv -Path $regFile.FullName
    $deletedKeys = $csvContent | Where-Object { $_.Deleted -eq $true }
    
    if ($deletedKeys) {
        $regTampering += "Deleted Keys found in Registry:$l4"
        foreach ($key in $deletedKeys) {
            $regTampering += "$($key.Keypath) deleted at $($key.LastWriteTimestamp)`n"
        }
    }
}

$Tamperings = @(
    $usnTampering
    $usnTampering2
    $evtTampering
    $evtTampering2
    $evtTampering3
    $prefTampering
    $prefhideTampering
    $volTampering
    $volTampering2
    $hideTampering
    $wmicTampering
    $unicodeTampering
    $threadTampering
    $bamTampering
    $timeTampering 
    $regTampering
)

Write-Host "   Outputting and Finishing"-ForegroundColor yellow
$t1 = "`nSuspicious Files on System `r$l3"
$t2 = "`nSuspicious Files in Instance `r$l3"
$t3 = "`nProcess Uptime `r$l3"
$t4 = "`nDeleted Files `r$l3"

$regRenames = Get-ChildItem -Path "$dmppath\Registry" -Filter "*.csv" -Recurse
foreach ($file in $regRenames) {
    $newName = $file.Name -replace '^\d+_', ''
    if ($file.Name -ne $newName) {
        Rename-Item -Path $file.FullName -NewName $newName
    }
}

Rename-Item -Path (Get-ChildItem -Path $regpath -Filter *.csv).FullName -NewName "Full_Registry.csv"
Rename-Item -Path (Get-ChildItem -Path $regpath -Directory).FullName -NewName "Filtered"
Get-ChildItem -Path 'C:\Temp\Dump' | Where-Object { $_.Name -match '\.(zip|exe|chm|dll)$|^readme\.txt$|^(EvtxECmd|RECmd|SQLECmd)$' } | Remove-Item -Recurse -Force
Move-Item -Path "$procpath\*.txt" -Destination "$procpathfilt"
Move-Item -Path "$dmppath\*.txt" -Destination "$procpath"
Move-Item -Path "$dmppath\*.csv" -Destination "$procpath"
Start-Service wsearch
Remove-MpPreference -ExclusionPath 'C:\Temp\Dump'

Set-Clipboard -Value $null
cd\
Clear-Host

$cheats1 = if ($dps4 -match "($Skript|$Hydro|$Astra|$Leet)") {
    "Severe Traces of Cheats found in Instance"
}

$cheats2 = if ($threats2 -match $ThreatDetection -or $threats5 -match $ThreatDetection) {
    "Severe Traces of Cheats found in Threat-Protection"
}

$cheats3 = $null
$peRows = $peHeaders | Where-Object { $_.EntryPoint -match $entryPoint }
if ($peRows) {
    foreach ($row in $peRows) {
        $cheats3 += "Cheat Execution found in $($row.FilePath)`n"
    }
}

$cheats1
$cheats2
$cheats3

@($cheats1; $cheats2; $cheats3; $h1; $o1; $susJournal; $o6; $o7; $dnssus; $minusSettings; $t3; $sUptime; $sysUptime; $h2; $Tamperings; $h3; $Defenderstatus; $threats1; $threats2; $threats3; $h4; $eventResults; $h5; $t1; $combine; $t2; $dps1; $r; $t4; $noFilesFound) | Add-Content c:\temp\Results.txt


Write-Host "Done! Results are in C:\Temp"