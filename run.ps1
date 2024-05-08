& buildv8a 

if (Test-Path $scriptPath/log.txt) {
    Remove-Item $scriptPath/log.txt
}

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
adb push $scriptPath/findApi /data/local/tmp/
adb shell su -c chmod +x /data/local/tmp/findApi
adb shell su -c /data/local/tmp/findApi /data/local/tmp/libunity.so | Tee-Object -FilePath $scriptPath/log.txt