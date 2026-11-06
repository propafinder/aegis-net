param(
  [string]$RepoRoot = '',
  [string]$ArtifactRoot = ''
)

# Refuse before path queries, artifact writes, signing or any service operation.
throw "Legacy WFP driver installer is retired because artifact-directory staging does not establish machine-owned ACL, hash and signature custody before kernel-service start. No driver or service was changed. There is currently no supported protected Rust WFP driver staging/load entry point; preserve existing installations and consult scripts/windows/README.md. Do not relax ACLs or use automatic signing to bypass this refusal."

$ErrorActionPreference = 'Stop'

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
if ([IO.Path]::IsPathRooted($ArtifactRoot)) {
  $ArtifactRoot = [IO.Path]::GetFullPath($ArtifactRoot)
} else {
  $ArtifactRoot = [IO.Path]::GetFullPath((Join-Path (Get-Location) $ArtifactRoot))
}

$driverProject = Join-Path $RepoRoot 'drivers\windows\aegis-wfp\aegis-wfp.vcxproj'
$ctlSource = Join-Path $RepoRoot 'tools\windows\aegis-wfpctl\aegis_wfpctl.c'
$buildRoot = Join-Path $ArtifactRoot 'aegis-wfp-build'
$driverBuildLog = Join-Path $ArtifactRoot 'driver-build.log'
$driverInstallLog = Join-Path $ArtifactRoot 'driver-install.log'
$vsDevCmd = 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat'
$signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'

New-Item -ItemType Directory -Force -Path $buildRoot | Out-Null

function Invoke-LoggedCmd {
  param([string]$Command, [string]$LogPath)

  "COMMAND: $Command" | Add-Content -Path $LogPath
  cmd.exe /d /s /c $Command *>> $LogPath
  $code = $LASTEXITCODE
  "EXIT: $code" | Add-Content -Path $LogPath
  if ($code -ne 0) {
    throw "Command failed with exit $code; see $LogPath"
  }
}

Set-Content -Path $driverBuildLog -Value "AEGIS WFP build started $(Get-Date -Format o)"

Set-Content -Path $driverInstallLog -Value "AEGIS WFP preinstall cleanup started $(Get-Date -Format o)"
sc.exe stop AegisWfp *>> $driverInstallLog
sc.exe delete AegisWfp *>> $driverInstallLog
Start-Sleep -Seconds 1

$cleanEnv = 'set PATH=& set Path=C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem'
$userEnv = 'set USERPROFILE=C:\Users\who&& set LOCALAPPDATA=C:\Users\who\AppData\Local&& set APPDATA=C:\Users\who\AppData\Roaming'
$msbuildCmd = "$cleanEnv&& $userEnv&& call ""$vsDevCmd"" -arch=x64 && msbuild ""$driverProject"" /t:Build /p:Configuration=Debug /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.26100.0 /p:Driver_SpectreMitigation=false /p:SignMode=Off /v:minimal"
Invoke-LoggedCmd -Command $msbuildCmd -LogPath $driverBuildLog

$driverSys = Join-Path $RepoRoot 'drivers\windows\aegis-wfp\build\x64\Debug\aegis_wfp.sys'
$driverInf = Join-Path $RepoRoot 'drivers\windows\aegis-wfp\build\x64\Debug\aegis_wfp\aegis_wfp.inf'
if (!(Test-Path $driverSys)) {
  $driverSys = Get-ChildItem -Path (Join-Path $RepoRoot 'drivers\windows\aegis-wfp') -Recurse -Filter aegis_wfp.sys | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (!(Test-Path $driverInf)) {
  $driverInf = Join-Path $RepoRoot 'drivers\windows\aegis-wfp\aegis_wfp.inf'
}

$ctlExe = Join-Path $buildRoot 'aegis-wfpctl.exe'
$clCmd = "$cleanEnv&& $userEnv&& call ""$vsDevCmd"" -arch=x64 && cl.exe /nologo /W4 /WX /EHsc /Fe:""$ctlExe"" ""$ctlSource"" fwpuclnt.lib rpcrt4.lib ws2_32.lib"
Invoke-LoggedCmd -Command $clCmd -LogPath $driverBuildLog

if (Test-Path $signtool) {
  $signCmd = """$signtool"" sign /v /fd SHA256 /a ""$driverSys"" ""$ctlExe"""
  Invoke-LoggedCmd -Command $signCmd -LogPath $driverBuildLog
}

Copy-Item -Force $driverSys (Join-Path $buildRoot 'aegis_wfp.sys')
Copy-Item -Force $driverInf (Join-Path $buildRoot 'aegis_wfp.inf')

Add-Content -Path $driverInstallLog -Value "AEGIS WFP install started $(Get-Date -Format o)"
sc.exe stop AegisWfp *>> $driverInstallLog
sc.exe delete AegisWfp *>> $driverInstallLog
Start-Sleep -Milliseconds 500
sc.exe create AegisWfp type= kernel start= demand error= normal binPath= "$buildRoot\aegis_wfp.sys" DisplayName= AegisWfp *>> $driverInstallLog
if ($LASTEXITCODE -ne 0) {
  throw "sc create AegisWfp failed; see $driverInstallLog"
}
sc.exe start AegisWfp *>> $driverInstallLog
if ($LASTEXITCODE -ne 0) {
  throw "sc start AegisWfp failed; see $driverInstallLog"
}
sc.exe query AegisWfp *>> $driverInstallLog

[pscustomobject]@{
  DriverSys = (Join-Path $buildRoot 'aegis_wfp.sys')
  Controller = $ctlExe
  BuildLog = $driverBuildLog
  InstallLog = $driverInstallLog
} | ConvertTo-Json -Depth 3
