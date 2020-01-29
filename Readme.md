![Compile pvk2pfxcore](https://github.com/andreasbotsikas/pvk2pfxcore/workflows/Compile%20pvk2pfxcore/badge.svg)
# pvk2pfxcore

A .net core 3.1 application to merge .cer and .pvk files into a .pfx file. 

This solution is using the deprecated [CryptImportKey function](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptimportkey).

It obviously runs on windows only and is targeting x86.

Useful links:
- [PVK file format](http://justsolve.archiveteam.org/wiki/PVK)
- [Seclib source](http://www.mentalis.org/soft/projects/seclib/) which contains the DllImport declarations and all the PVK file handling. Some minor modifications (alias HMAC) had to be done in the source code in order to compile in .net core.
