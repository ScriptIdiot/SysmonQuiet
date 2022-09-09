# SysmonQuiet Reflective DLL

Most of the codes come from SEKTOR7 - Windows Evasion Course. This RDLL (requires *SeDebugPrivilege* privilege) will automatically locate sysmon process and patch its EtwEventWrite API, causing sysmon malfunctioning while the process and its threads are still running.

*The effect lasts until next reboot / service restart*

## Update
**Version 1.1 (20220909)**
- Adopted the RDLL from rapid7 to remove RWX section and apply section Characteristics

## Usage - Cobalt Strike
Load SysmonQuiet.cna
```
beacon> SysmonQuiet
```

![image](https://user-images.githubusercontent.com/21979646/178285876-d7e39505-dd6c-4d69-9d37-46ba67cdeda2.png)


## Credits
* SEKTOR7 - Windows Evasion Course
* https://github.com/stephenfewer/ReflectiveDLLInjection
* https://github.com/rapid7/ReflectiveDLLInjection
