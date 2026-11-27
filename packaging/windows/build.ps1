[CmdletBinding()]
param(
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $RepositoryRoot "dist\windows-client"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$WorkDirectory = Join-Path $RepositoryRoot "build\windows-client"
$InstallerScript = Join-Path $PSScriptRoot "BaseSentinel.iss"

if ($env:OS -ne "Windows_NT") {
    throw "The BaseSentinel Windows installer must be built on Windows."
}

$Python = (Get-Command python -ErrorAction Stop).Source

& $Python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "Could not upgrade pip." }
& $Python -m pip install -e "$($RepositoryRoot)[build]"
if ($LASTEXITCODE -ne 0) { throw "Could not install BaseSentinel build dependencies." }

if (Test-Path $OutputDirectory) {
    Remove-Item $OutputDirectory -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
if (Test-Path $WorkDirectory) {
    Remove-Item $WorkDirectory -Recurse -Force
}
New-Item -ItemType Directory -Path $WorkDirectory -Force | Out-Null

function Invoke-PyInstaller {
    param(
        [string]$Name,
        [string]$EntryPoint,
        [switch]$Windowed,
        [string[]]$ExtraArguments = @()
    )

    $Arguments = @(
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name", $Name,
        "--paths", (Join-Path $RepositoryRoot "src"),
        "--distpath", $OutputDirectory,
        "--workpath", (Join-Path $WorkDirectory $Name),
        "--specpath", (Join-Path $WorkDirectory "spec")
    )
    if ($Windowed) {
        $Arguments += "--windowed"
    } else {
        $Arguments += "--console"
    }
    $Arguments += $ExtraArguments
    $Arguments += $EntryPoint

    & $Python -m PyInstaller @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed while building $Name."
    }
}

$LogoPath = Join-Path $RepositoryRoot "assets\Logo.png"
if (-not (Test-Path $LogoPath)) {
    throw "BaseSentinel logo was not found at $LogoPath."
}
$IconPath = Join-Path $WorkDirectory "BaseSentinel.ico"
$IconGenerator = "from PIL import Image; import sys; Image.open(sys.argv[1]).convert('RGBA').save(sys.argv[2], format='ICO', sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])"
& $Python -c $IconGenerator $LogoPath $IconPath
if ($LASTEXITCODE -ne 0) { throw "Could not generate the BaseSentinel application icon." }
Copy-Item $IconPath (Join-Path $OutputDirectory "BaseSentinel.ico") -Force

$SpecDirectory = Join-Path $WorkDirectory "spec"
New-Item -ItemType Directory -Path $SpecDirectory -Force | Out-Null

Invoke-PyInstaller -Name "BaseSentinelAgent" -EntryPoint (Join-Path $RepositoryRoot "src\basesentinel_agent\cli.py")
Invoke-PyInstaller -Name "BaseSentinelAgentWorker" -EntryPoint (Join-Path $PSScriptRoot "agent_worker.py")
Invoke-PyInstaller -Name "BaseSentinelEndpoint" -EntryPoint (Join-Path $RepositoryRoot "src\basesentinel_agent\gui.py") -Windowed -ExtraArguments @("--icon", $IconPath, "--add-data", "$LogoPath;assets")
Invoke-PyInstaller -Name "BaseSentinelTray" -EntryPoint (Join-Path $RepositoryRoot "src\basesentinel_agent\tray.py") -Windowed -ExtraArguments @("--collect-all", "pystray", "--collect-all", "PIL")

$Iscc = Get-Command ISCC.exe -ErrorAction SilentlyContinue
if ($Iscc) {
    $IsccPath = $Iscc.Source
} else {
    $Candidates = @(
        (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
        (Join-Path ([Environment]::GetFolderPath("ProgramFilesX86")) "Inno Setup 6\ISCC.exe")
    )
    $IsccPath = $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $IsccPath) {
    throw "Inno Setup 6 was not found. Install Inno Setup 6 and run this script again."
}

$InstallerOutput = Join-Path $OutputDirectory "installer"
New-Item -ItemType Directory -Path $InstallerOutput -Force | Out-Null
& $IsccPath "/DAppPayloadDir=$OutputDirectory" "/O$InstallerOutput" $InstallerScript
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup failed to create the installer."
}

Write-Host ""
Write-Host "BaseSentinel client installer created:"
Write-Host (Join-Path $InstallerOutput "BaseSentinel-Client-Setup.exe")
