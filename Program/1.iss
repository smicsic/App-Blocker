; ===============================
; 🧱 App Blocker Installer Script
; Автор: smics_play (Вова)
; ===============================

[Setup]
OutputDir=.
OutputBaseFilename=AppBlocker_Setup
AppName=App Blocker
AppVersion=2.3.0
AppPublisher=smics_play
DefaultDirName={pf}\AppBlocker
DefaultGroupName=App Blocker
UninstallDisplayIcon={app}\icon.ico
SetupIconFile=icon.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
DisableDirPage=no
DisableProgramGroupPage=no
DisableReadyPage=no
DisableFinishedPage=no
DisableWelcomePage=no

[Files]
Source: "AppBlocker.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "SecureSystem.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\App Blocker"; Filename: "{app}\AppBlocker.exe"; IconFilename: "{app}\icon.ico"
Name: "{commondesktop}\App Blocker"; Filename: "{app}\AppBlocker.exe"; IconFilename: "{app}\icon.ico"

[Run]
Filename: "{app}\AppBlocker.exe"; Description: "Запустить App Blocker"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
