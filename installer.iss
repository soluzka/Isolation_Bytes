; Inno Setup installer for the Antivirus Server onedir package.
; Requires Inno Setup 6 or later.
; Compile with:  iscc installer.iss  (or run build_installer.bat)

#define MyAppName "Antivirus Server"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Antivirus"
#define MyAppExeName "antivirus_server.exe"
#define MyAdminHelperExeName "AntivirusServer_AdminHelper.exe"

[Setup]
AppId={{B3A0C0F1-2E5D-4F3E-9A1B-2C3D4E5F6A7B}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=dist
OutputBaseFilename=AntivirusServer_Setup
SetupIconFile=static\favicon.ico
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
DisableProgramGroupPage=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\antivirus_server\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Start Conditional Antivirus (Administrator)"; Filename: "{app}\{#MyAdminHelperExeName}"
Name: "{group}\Start YARA Scanner (Administrator)"; Filename: "{app}\{#MyAdminHelperExeName}"; Parameters: "--open-yara"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{autodesktop}\Start Conditional Antivirus (Administrator)"; Filename: "{app}\{#MyAdminHelperExeName}"; Tasks: desktopicon
Name: "{autodesktop}\Start YARA Scanner (Administrator)"; Filename: "{app}\{#MyAdminHelperExeName}"; Parameters: "--open-yara"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent
