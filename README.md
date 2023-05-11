# Giga-byte Hardware UAC elevation and Persistence DLL side-loading Exploit

Giga-byte Control Center (GCC) is a software package designed for improved user 
experience of Gigabyte hardware, often found in gaming and performance PC's.
A UAC elevation vulnerability exists that can be used for persistence in a
novel fashion. The GCC software installs a scheduled task which is executed
on login by all users with Administrative rights in the context of the default
Administrator. The task launches "GraphicsCardEngine.exe" with high integrity
privileges in the Administrator users context, which is vulnerable to a DLL
side loading attack. By writing either "atiadlxx.dll" or "atiadlxy.dll" DLL 
into the Administrator %LOCALAPPDATA% path, the application will load the DLL's 
on future user logins with Administrator rights. This allows for UAC elevation 
bypass and also a persistence mechanism for Administrator rights on each
successful login that triggers the vulnerable scheduled task. This exploit should
be run from a user with Administrator privileges to bypass UAC elevation prompt
and facilitate persistence mechanism on future login by any local user, note the
scheduled task will not run if the local Administrator is not logged in. The 
scheduled task is added by the "Gigabyte VGA tool", a sub-component of GCC.

* Tested against GCC_23.04.13.01 on Windows 11 x64 (Version 10.0.22621.1702)

These files are available under a Attribution-NonCommercial-NoDerivatives 4.0 International license.