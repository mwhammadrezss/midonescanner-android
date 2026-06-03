# Download xray-core into assets/xray for local Flutter builds.
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path "assets\xray" | Out-Null

$winZip = "xray-win.zip"
Invoke-WebRequest -Uri "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip" -OutFile $winZip
Expand-Archive $winZip -DestinationPath "xray_tmp_win" -Force
Copy-Item (Get-ChildItem xray_tmp_win -Recurse -Filter "xray.exe" | Select-Object -First 1).FullName `
  "assets\xray\xray-windows-amd64.exe" -Force
Write-Host "OK: assets/xray/xray-windows-amd64.exe"

# Android arm64 (for APK bundle)
$andZip = "xray-android.zip"
Invoke-WebRequest -Uri "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-android-arm64-v8a.zip" -OutFile $andZip
Expand-Archive $andZip -DestinationPath "xray_tmp_and" -Force
$andBin = Get-ChildItem xray_tmp_and -Recurse -Filter "xray" | Where-Object { -not $_.Extension } | Select-Object -First 1
Copy-Item $andBin.FullName "assets\xray\xray-android-arm64" -Force
Write-Host "OK: assets/xray/xray-android-arm64"

Write-Host "Done. Add geo/ipcountry.bin and icons before release build."
