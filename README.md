看 [frida-find-il2cpp-api](https://github.com/feilongzaitia/frida-find-il2cpp-api) 
发现挺有意思的，就顺带优化一下

1. 先build (build后会在根目录生成findApi)
2. 再run (run会将可执行文件push到手机上，然后用它去解析到LookupSymbol，会生成log.txt)
3. 再genjs (使用log.txt中找到的地址，修改模板js)
4. 然后快速启动frida注入修改好的js脚本获取导出函数
