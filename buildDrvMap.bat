@ECHO OFF
cl.exe /EHsc /GS- /std:c++17 main.cpp drv_image.cpp util.cpp /link /SAFESEH:NO kernel32.lib user32.lib ntdll.lib Advapi32.lib Shlwapi.lib