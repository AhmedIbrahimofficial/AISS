; AISS Windows Installer Script
; Requires: Inno Setup 6+ from https://jrsoftware.org/isdl.php
; Build: ISCC aiss_setup.iss

#define MyAppName "AISS"
#define MyAppFullName "AISS - AI Integrated Security System"
#define MyAppVersion "2.0.0"
#define MyAppPublisher "Ahmed Ibrahim"
#define MyAppURL "https://github.com/AhmedIbrahimofficial/AISS"
#define MyAppExeName "AISS.exe"
#define MyAppDescription "AI-powered cybersecurity monitoring and threat response platform"

[Setup]
AppId={{A1S2S3-AISS-2024-SECURITY-PLATFORM}}
AppName={#MyAppFullName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\AISS
DefaultGroupName={#MyAppFullName}
AllowNoIcons=yes
LicenseFile=..\aiss backend\LICENSE
OutputDir=.\output
OutputBaseFilename=AISS_Setup_v{#MyAppVersion}_Windows
SetupIconFile=..\aiss backend\static\favicon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardImageFile=banner.bmp
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayIcon={app}\AISS.exe
UninstallDisplayName={#MyAppFullName}
VersionInfoVersion={#MyAppVersion}
VersionInfoDescription={#MyAppDescription}
VersionInfoCompany={#MyAppPublisher}

; Minimum requirements
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";     Description: "{cm:CreateDesktopIcon}";     GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; OnlyBelowVersion: 6.1; Check: not IsAdminInstallMode
Name: "autostart";       Description: "Start AISS automatically with Windows"; GroupDescription: "Startup:"; Flags: unchecked

[Files]
; Main application (PyInstaller output)
Source: "..\aiss backend\dist\AISS\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Node.js portable (downloaded by build script)
Source: ".\node\*"; DestDir: "{app}\node"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: NodeExists

; Frontend build
Source: "..\frontend\.output\*"; DestDir: "{app}\frontend\.output"; Flags: ignoreversion recursesubdirs createallsubdirs

; Config template
Source: "..\aiss backend\.env.example"; DestDir: "{app}"; DestName: ".env.example"; Flags: ignoreversion
Source: ".\aiss.bat"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{app}\logs";    Permissions: everyone-full
Name: "{app}\data";    Permissions: everyone-full
Name: "{app}\rules"

[Icons]
Name: "{group}\{#MyAppFullName}";         Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{group}\Open Dashboard";           Filename: "http://localhost:8081";  IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\API Documentation";        Filename: "http://localhost:8000/docs"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppFullName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppFullName}";   Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; WorkingDir: "{app}"

[Registry]
; Add to autostart if selected
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "AISS"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue; Tasks: autostart

; Register as installed application
Root: HKLM; Subkey: "Software\AISS"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\AISS"; ValueType: string; ValueName: "Version"; ValueData: "{#MyAppVersion}"

[Run]
; Copy .env template if no .env exists
Filename: "{cmd}"; Parameters: "/c if not exist ""{app}\.env"" copy ""{app}\.env.example"" ""{app}\.env"""; Flags: runhidden

; Launch after install
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppFullName}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Kill running processes on uninstall
Filename: "taskkill"; Parameters: "/F /IM AISS.exe /T"; Flags: runhidden; RunOnceId: "KillAISS"
Filename: "taskkill"; Parameters: "/F /IM node.exe /T"; Flags: runhidden; RunOnceId: "KillNode"

[Code]
function NodeExists: Boolean;
begin
  Result := FileExists(ExpandConstant('{src}\node\node.exe'));
end;
