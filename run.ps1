& buildv8a 

if (Test-Path $scriptPath/log.txt) {
    Remove-Item $scriptPath/log.txt
}

# $target = "/data/local/tmp/libunity.so"
$target = "/data/app/com.iewagaicho.paintthecube-iuRVg2DZtY4tabhurappMA==/lib/arm64/libunity.so"

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
adb push $scriptPath/findApi /data/local/tmp/
adb shell su -c chmod +x /data/local/tmp/findApi
adb shell su -c /data/local/tmp/findApi $target | Tee-Object -FilePath $scriptPath/log.txt