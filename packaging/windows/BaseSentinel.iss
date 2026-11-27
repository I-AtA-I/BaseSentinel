#ifndef AppPayloadDir
  #define AppPayloadDir "..\..\dist\windows-client"
#endif

#define AppName "BaseSentinel"
#define AppVersion "0.1.0"
#define AppPublisher "BaseSentinel"
#define AppExe "BaseSentinelEndpoint.exe"

[Setup]
AppId={{B7E4B91B-5F6C-4C9C-9E4B-5B6A9F4C2D10}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\BaseSentinel
DefaultGroupName=BaseSentinel
UninstallDisplayIcon={app}\{#AppExe}
OutputBaseFilename=BaseSentinel-Client-Setup
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
MinVersion=10.0.19041
WizardStyle=modern
SetupIconFile={#AppPayloadDir}\BaseSentinel.ico
Compression=lzma2
SolidCompression=yes
CloseApplications=yes
RestartApplications=no

[Files]
Source: "{#AppPayloadDir}\BaseSentinelAgent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#AppPayloadDir}\BaseSentinelAgentWorker.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#AppPayloadDir}\BaseSentinelEndpoint.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#AppPayloadDir}\BaseSentinelTray.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\BaseSentinel Endpoint"; Filename: "{app}\BaseSentinelEndpoint.exe"
Name: "{group}\BaseSentinel Tray"; Filename: "{app}\BaseSentinelTray.exe"
Name: "{group}\Install system-wide collector"; Filename: "{app}\BaseSentinelAgent.exe"; Parameters: "startup-install"
Name: "{group}\Uninstall BaseSentinel"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\BaseSentinelEndpoint.exe"; Description: "Open BaseSentinel Endpoint"; Flags: postinstall nowait skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{app}\BaseSentinelAgent.exe"; Parameters: "startup-remove"; Flags: runhidden waituntilterminated; RunOnceId: "BaseSentinelStartupCleanup"
