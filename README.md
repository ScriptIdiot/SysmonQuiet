# SysmonQuiet Reflective DLL

Most of the codes come from SEKTOR7 - Windows Evasion Course. This RDLL (requires *SeDebugPrivilege* privilege) will automatically locate sysmon process and patch its EtwEventWrite API, causing sysmon malfunctioning while the process and its threads are still running.


## Usage - Cobalt Strike
Load SysmonQuiet.cna
```
beacon> SysmonQuiet
```

![image](https://user-images.githubusercontent.com/21979646/178285876-d7e39505-dd6c-4d69-9d37-46ba67cdeda2.png)


## Credits
* SEKTOR7 - Windows Evasion Course
* https://github.com/stephenfewer/ReflectiveDLLInjection
