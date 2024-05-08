param(
    [string]$pkgName = ""
)

if ($pkgName -eq "") {
    adb shell su -c find /data/app -name libunity.so
} 
else 
{
    adb shell su -c find /data/app -name libunity.so | Select-String $pkgName
}