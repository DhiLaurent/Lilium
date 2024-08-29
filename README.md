# Lilium

![](/lucy.png?raw=true)

[!] Save lilium with pyw extension

# Download upx packer
````
https://github.com/upx/upx
````

````
python -m PyInstaller --onefile lilium.pyw --windowed
````

# Compact exe with upx packer
````
upx --best --lzma --force lilium.exe
````
