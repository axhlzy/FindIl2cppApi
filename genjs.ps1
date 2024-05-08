$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

Get-Content $scriptPath/log.txt | Select-String "Find LookupSymbol @ 0x[0-9a-f]+" | ForEach-Object {
    $address = $_.Matches[0].Value -replace "Find LookupSymbol @ ", ""
    Write-Host "Address: $address"
  
}

Get-Content $scriptPath/find_il2cpp_api.js.in | ForEach-Object {
    $_ -replace "0x00000000", $address
} | Set-Content $scriptPath/find_il2cpp_api.js

$cmd = Read-Host "Do you want to start app? (y/n)"

if ($cmd -eq "y") {

    $packageName = Read-Host "Enter package name"
    & frida -U -f $packageName -l $scriptPath/find_il2cpp_api.js

}