; Inno Setup script for the X-Secure installer.
; Build:  python tools/build_release.py   (it calls ISCC with the right paths when Inno Setup 6 is installed)
; Manual: ISCC /DAppVersion=1.0.0 /DSourceDir=..\dist\X-Secure /DOutputDir=..\release installer\xsecure.iss
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\X-Secure"
#endif
#ifndef OutputDir
  #define OutputDir "..\release"
#endif

[Setup]
AppId={{6B0A3E1C-5C47-4D2B-9E58-7A1F2D0C9B11}
AppName=X-Secure
AppVersion={#AppVersion}
AppVerName=X-Secure {#AppVersion}
AppPublisher=X-Secure
DefaultDirName={autopf}\X-Secure
DefaultGroupName=X-Secure
DisableProgramGroupPage=yes
OutputDir={#OutputDir}
OutputBaseFilename=X-Secure-{#AppVersion}-setup
SetupIconFile=..\assets\xsecure.ico
UninstallDisplayIcon={app}\X-Secure.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
; No administrator rights needed: by default the app installs for the current user only.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
LicenseFile=..\LICENSE
CloseApplications=yes
VersionInfoVersion={#AppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\X-Secure"; Filename: "{app}\X-Secure.exe"
Name: "{autodesktop}\X-Secure"; Filename: "{app}\X-Secure.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\X-Secure.exe"; Description: "Launch X-Secure"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Remove the scheduled scan task if the user created one, so nothing keeps pointing at a deleted program.
Filename: "schtasks"; Parameters: "/Delete /TN ""X-Secure\Scheduled Scan"" /F"; Flags: runhidden; RunOnceId: "RemoveScheduledScan"

; Settings, the quarantine and logs live in %USERPROFILE%\.x-secure and are deliberately NOT removed on uninstall:
; quarantined files are encrypted for the current Windows account and the user may want to restore them later.
