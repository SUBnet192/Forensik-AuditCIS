# Requirements MS Internet Explorer 10 DISA STIG V1R15 

@{
	RegistrySettings = @(
		@{
			Id    = "DTBI320"
			Task  = "Internet Explorer must be configured to use machine settings."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
			Name  = "Security_HKLM_only"
			Value = 1
		}
		@{
			Id    = "DTBI319"
			Task  = "Internet Explorer must be configured to disallow users to change policies."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
			Name  = "Security_options_edit"
			Value = 1
		}
		@{
			Id    = "DTBI318"
			Task  = "Internet Explorer must be set to disallow users to add/delete sites."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
			Name  = "Security_zones_map_edit"
			Value = 1
		}
		@{
			Id    = "DTBI367"
			Task  = "Internet Explorer must be configured to make proxy settings per user."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
			Name  = "ProxySettingsPerUser"
			Value = 1
		}
		@{
			Id    = "DTBI015"
			Task  = "The Internet Explorer warning about certificate address mismatch must be enforced."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
			Name  = "WarnOnBadCertRecving"
			Value = 1
		}
		@{
			Id    = "DTBI022"
			Task  = "The Download signed ActiveX controls property must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1001"
			Value = 3
		}
		@{
			Id    = "DTBI023"
			Task  = "The Download unsigned ActiveX controls property must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1004"
			Value = 3
		}
		@{
			Id    = "DTBI024"
			Task  = "The Initialize and script ActiveX controls not marked as safe property must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1201"
			Value = 3
		}
		@{
			Id    = "DTBI030"
			Task  = "Font downloads must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1604"
			Value = 3
		}
		@{
			Id    = "DTBI031"
			Task  = "The Java permissions must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1C00"
			Value = 0
		}
		@{
			Id    = "DTBI032"
			Task  = "Accessing data sources across domains must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1406"
			Value = 3
		}
		@{
			Id    = "DTBI036"
			Task  = "Functionality to drag and drop or copy and paste files must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1802"
			Value = 3
		}
		@{
			Id    = "DTBI038"
			Task  = "Launching programs and files in IFRAME must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1804"
			Value = 3
		}
		@{
			Id    = "DTBI039"
			Task  = "Navigating windows and frames across different domains must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\InternetSettings\Zones\3"
			Name  = "1607"
			Value = 3
		}
		@{
			Id    = "DTBI042"
			Task  = "Userdata persistence must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1606"
			Value = 3
		}
		@{
			Id    = "DTBI044"
			Task  = "Clipboard operations via script must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1407"
			Value = 3
		}
		@{
			Id    = "DTBI046"
			Task  = "Logon options must be configured to prompt (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1A00"
			Value = 65536
		}
		@{
			Id    = "DTBI061"
			Task  = "Java permissions must be configured with High Safety (Intranet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"
			Name  = "1C00"
			Value = 65536
		}
		@{
			Id    = "DTBI091"
			Task  = "Java permissions must be configured with High Safety (Trusted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"
			Name  = "1C00"
			Value = 65536
		}
		@{
			Id    = "DTBI112"
			Task  = "The Download signed ActiveX controls property must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1001"
			Value = 3
		}
		@{
			Id    = "DTBI113"
			Task  = "The Download unsigned ActiveX controls property must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1004"
			Value = 3
		}
		@{
			Id    = "DTBI114"
			Task  = "The Initialize and script ActiveX controls not marked as safe property must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1201"
			Value = 3
		}
		@{
			Id    = "DTBI115"
			Task  = "ActiveX controls and plug-ins must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1200"
			Value = 3
		}
		@{
			Id    = "DTBI116"
			Task  = "ActiveX controls marked safe for scripting must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1405"
			Value = 3
		}
		@{
			Id    = "DTBI119"
			Task  = "File downloads must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1803"
			Value = 3
		}
		@{
			Id    = "DTBI120"
			Task  = "Font downloads must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1604"
			Value = 3
		}
		@{
			Id    = "DTBI122"
			Task  = "Accessing data sources across domains must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1406"
			Value = 3
		}
		@{
			Id    = "DTBI123"
			Task  = "The Allow META REFRESH property must be disallowed (Restricted Sites zone).
"
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1608"
			Value = 3
		}
		@{
			Id    = "DTBI126"
			Task  = "Functionality to drag and drop or copy and paste files must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1802"
			Value = 3
		}
		@{
			Id    = "DTBI127"
			Task  = "Installation of desktop items must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1800"
			Value = 3
		}
		@{
			Id    = "DTBI128"
			Task  = "Launching programs and files in IFRAME must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1804"
			Value = 3
		}
		@{
			Id    = "DTBI129"
			Task  = "Navigating windows and frames across different domains must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1607"
			Value = 3
		}
		@{
			Id    = "DTBI132"
			Task  = "Rule Title: Userdata persistence must be disallowed (Restricted Sites zone).
"
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1606"
			Value = 3
		}
		@{
			Id    = "DTBI133"
			Task  = "Active scripting must be disallowed (Restricted Sites Zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1400"
			Value = 3
		}
		@{
			Id    = "DTBI134"
			Task  = "Clipboard operations via script must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1407"
			Value = 3
		}
		@{
			Id    = "DTBI136"
			Task  = "Logon options must be configured and enforced (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1A00"
			Value = 196608
		}
		@{
			Id    = "DTBI121"
			Task  = "Java permissions must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1C00"
			Value = 0
		}
		@{
			Id    = "DTBI305"
			Task  = "Automatic configuration of Internet Explorer connections must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel"
			Name  = "Autoconfig"
			Value = 1
		}
		@{
			Id    = "DTBI315"
			Task  = "Participation in the Customer Experience Improvement Program must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\SQM"
			Name  = "DisableCustomerImprovementProgram"
			Value = 0
		}
		@{
			Id    = "DTBI325"
			Task  = "Security checking features must be enforced."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Security"
			Name  = "DisableSecuritySettingsCheck"
			Value = 0
		}
		@{
			Id    = "DTBI340"
			Task  = "Active content from CDs must be disallowed to run on user machines."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings"
			Name  = "LOCALMACHINE_CD_UNLOCK"
			Value = 0
		}
		@{
			Id    = "DTBI350"
			Task  = "Software must be disallowed to run or install with invalid signatures."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Download"
			Name  = "RunInvalidSignatures"
			Value = 0
		}
		@{
			Id    = "DTBI355"
			Task  = "Third-party browser extensions must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "Enable Browser Extensions"
			Value = "no"
		}
		@{
			Id    = "DTBI365"
			Task  = "Checking for server certificate revocation must be enforced."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
			Name  = "CertificateRevocation"
			Value = 1
		}
		@{
			Id    = "DTBI370"
			Task  = "Checking for signatures on downloaded programs must be enforced."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Download"
			Name  = "CheckExeSignatures"
			Value = "yes"
		}
		@{
			Id    = "DTBI375"
			Task  = "All network paths (UNCs) for Intranet sites must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap"
			Name  = "UNCAsIntranet"
			Value = 0
		}
		@{
			Id    = "DTBI385"
			Task  = "Script-initiated windows without size or position constraints must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2102"
			Value = 3
		}
		@{
			Id    = "DTBI390"
			Task  = "Script-initiated windows without size or position constraints must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2102"
			Value = 3
		}
		@{
			Id    = "DTBI395"
			Task  = "Scriptlets must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1209"
			Value = 3
		}
		@{
			Id    = "DTBI415"
			Task  = "Automatic prompting for file downloads must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2200"
			Value = 3
		}
		@{
			Id    = "DTBI455"
			Task  = "XAML files must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2402"
			Value = 3
		}
		@{
			Id    = "DTBI460"
			Task  = "XAML files must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2402"
			Value = 3
		}
		@{
			Id    = "DTBI465"
			Task  = "MIME sniffing must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2100"
			Value = 3
		}
		@{
			Id    = "DTBI470"
			Task  = "MIME sniffing must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2100"
			Value = 3
		}
		@{
			Id    = "DTBI475"
			Task  = "First-Run prompt ability must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1208"
			Value = 3
		}
		@{
			Id    = "DTBI480"
			Task  = "First-Run prompt ability must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1208"
			Value = 3
		}
		@{
			Id    = "DTBI485"
			Task  = "Protected Mode must be enforced (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2500"
			Value = 0
		}
		@{
			Id    = "DTBI490"
			Task  = "Protected Mode must be enforced (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2500"
			Value = 0
		}
		@{
			Id    = "DTBI495"
			Task  = "Pop-up Blocker must be enforced (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1809"
			Value = 0
		}
		@{
			Id    = "DTBI500"
			Task  = "Pop-up Blocker must be enforced (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1809"
			Value = 0
		}
		@{
			Id    = "DTBI515"
			Task  = "Websites in less privileged web content zones must be prevented from navigating into the Internet zone."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2101"
			Value = 3
		}
		@{
			Id    = "DTBI520"
			Task  = "Websites in less privileged web content zones must be prevented from navigating into the Restricted Sites zone."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2101"
			Value = 3
		}
		@{
			Id    = "DTBI575"
			Task  = "Allow binary and script behaviors must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2000"
			Value = 3
		}
		@{
			Id    = "DTBI580"
			Task  = "Automatic prompting for file downloads must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2200"
			Value = 3
		}
		@{
			Id    = "DTBI590"
			Task  = "Internet Explorer Processes for MIME handling is not enabled. (Reserved)"
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI595"
			Task  = "Internet Explorer Processes for MIME sniffing must be enforced (Reserved).
"
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI600"
			Task  = "Internet Explorer Processes for MK protocol must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL"
			Name  = "explorer.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI605"
			Task  = "Internet Explorer Processes for MK protocol must be enforced (IExplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI610"
			Task  = "Internet Explorer Processes for Zone Elevation must be enforced (Reserved)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI630"
			Task  = "Internet Explorer Processes for Restrict File Download must be enforced (Reserved)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI635"
			Task  = "Internet Explorer Processes for Restrict File Download must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"
			Name  = "explorer.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI640"
			Task  = "Internet Explorer Processes for Restrict File Download must be enforced (IExplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI645"
			Task  = "Internet Explorer Processes for restricting pop-up windows must be enforced (Reserved)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI650"
			Task  = ".NET Framework-reliant components not signed with Authenticode must be disallowed to run (Restricted Sites Zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2004"
			Value = 3
		}
		@{
			Id    = "DTBI655"
			Task  = ".NET Framework-reliant components signed with Authenticode must be disallowed to run (Restricted Sites Zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2001"
			Value = 3
		}
		@{
			Id    = "DTBI670"
			Task  = "Scripting of Java applets must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1402"
			Value = 3
		}<#
		@{
			Id    = "DTBI675"
			Task  = "The URL to be displayed for checking updates to Internet Explorer and Internet Tools must be a blank page."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "Update_Check_Page"
			Value = 
		}#>
		@{
			Id    = "DTBI680"
			Task  = "The update check interval must be configured and set to 30 days."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "Update_Check_Interval"
			Value = 30
		}
		@{
			Id    = "DTBI592"
			Task  = "Internet Explorer Processes for MIME handling must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING"
			Name  = "explorer.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI594"
			Task  = "Internet Explorer Processes for MIME handling must be enforced (IExplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI599"
			Task  = "Internet Explorer Processes for MK protocol must be enforced (Reserved)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI612"
			Task  = "Internet Explorer Processes for Zone Elevation must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"
			Name  = "explorer.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI614"
			Task  = "Internet Explorer Processes for Zone Elevation must be enforced (IExplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI647"
			Task  = "Internet Explorer Processes for restricting pop-up windows must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"
			Name  = "explorer.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI649"
			Task  = "Internet Explorer Processes for restricting pop-up windows must be enforced (IExplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI690"
			Task  = "AutoComplete feature for forms must be disallowed."
			Path  = "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "Use FormSuggest"
			Value = "no"
		}
		@{
			Id    = "DTBI725"
			Task  = "Turn on the auto-complete feature for user names and passwords on forms are not disabled."
			Path  = "HKCU:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "FormSuggest PW Ask"
			Value = "no"
		}
		@{
			Id    = "DTBI596"
			Task  = "Internet Explorer Processes for MIME sniffing must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING"
			Name  = "explorer.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI597"
			Task  = "Internet Explorer Processes for MIME sniffing must be enforced (IExplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI010"
			Task  = "First Run Wizard settings must be established for a home page."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "DisableFirstRunCustomize"
			Value = 1
		}
		@{
			Id    = "DTBI300"
			Task  = "Configuring History setting must be set to 40 days."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History"
			Name  = "DaysToKeep"
			Value = 40
		}
		@{
			Id    = "DTBI740"
			Task  = "Managing SmartScreen Filter use must be enforced.
"
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter"
			Name  = "EnabledV9"
			Value = 1
		}
		@{
			Id    = "DTBI750"
			Task  = "Updates to website lists from Microsoft must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\BrowserEmulation"
			Name  = "MSCompatibilityMode"
			Value = 0
		}
		@{
			Id    = "DTBI760"
			Task  = "Browser must retain history on exit."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy"
			Name  = "ClearBrowsingHistoryOnExit"
			Value = 0
		}
		@{
			Id    = "DTBI770"
			Task  = "Deleting websites that the user has visited must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy"
			Name  = "CleanHistory"
			Value = 0
		}
		@{
			Id    = "DTBI780"
			Task  = "InPrivate Browsing must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy"
			Name  = "EnableInPrivateBrowsing"
			Value = 0
		}
		@{
			Id    = "DTBI800"
			Task  = "Scripting of Internet Explorer WebBrowser control property must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1206"
			Value = 3
		}
		@{
			Id    = "DTBI810"
			Task  = "When uploading files to a server, the local directory path must be excluded (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "160A"
			Value = 3
		}
		@{
			Id    = "DTBI820"
			Task  = "Security Warning for unsafe files must be set to prompt (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1806"
			Value = 1
		}
		@{
			Id    = "DTBI830"
			Task  = "ActiveX controls without prompt property must be used in approved domains only (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "120b"
			Value = 3
		}
		@{
			Id    = "DTBI840"
			Task  = "Cross-Site Scripting (XSS) Filter must be enforced (Internet zone).
"
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "1409"
			Value = 0
		}
		@{
			Id    = "DTBI850"
			Task  = "Scripting of Internet Explorer WebBrowser control must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1206"
			Value = 3
		}
		@{
			Id    = "DTBI860"
			Task  = "When uploading files to a server, the local directory path must be excluded (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "160A"
			Value = 3
		}
		@{
			Id    = "DTBI870"
			Task  = "Security Warning for unsafe files must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1806"
			Value = 3
		}
		@{
			Id    = "DTBI880"
			Task  = "ActiveX controls without prompt property must be used in approved domains only (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "120b"
			Value = 3
		}
		@{
			Id    = "DTBI890"
			Task  = "Cross-Site Scripting (XSS) Filter property must be enforced (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1409"
			Value = 0
		}
		@{
			Id    = "DTBI900"
			Task  = "Internet Explorer Processes Restrict ActiveX Install must be enforced (Reserved)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI910"
			Task  = "Status bar updates via script must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2103"
			Value = 3
		}
		@{
			Id    = "DTBI920"
			Task  = ".NET Framework-reliant components not signed with Authenticode must be disallowed to run (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2004"
			Value = 3
		}
		@{
			Id    = "DTBI930"
			Task  = ".NET Framework-reliant components signed with Authenticode must be disallowed to run (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2001"
			Value = 3
		}
		@{
			Id    = "DTBI940"
			Task  = "Scriptlets must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "1209"
			Value = 3
		}
		@{
			Id    = "DTBI950"
			Task  = "Status bar updates via script must be disallowed (Restricted Sites zone).
"
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2103"
			Value = 3
		}
		@{
			Id    = "DTBI1010"
			Task  = "Internet Explorer Processes Restrict ActiveX Install must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
			Name  = "explorer.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI1020"
			Task  = "Internet Explorer Processes Restrict ActiveX Install must be enforced (IExplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI745"
			Task  = "Add-on performance notifications must be disallowed."
			Path  = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext"
			Name  = "DisableAddonLoadTimePerformanceNotifications"
			Value = 1
		}
		@{
			Id    = "DTBI755"
			Task  = "Browser Geolocation functionality must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Geolocation"
			Name  = "PolicyDisableGeolocation"
			Value = 1
		}
		@{
			Id    = "DTBI765"
			Task  = "Suggested Sites functionality must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Suggested Sites"
			Name  = "Enabled"
			Value = 0
		}
		@{
			Id    = "DTBI775"
			Task  = "Automatic checking for Internet Explorer updates must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "NoUpdateCheck"
			Value = 1
		}
		@{
			Id    = "DTBI805"
			Task  = "ActiveX opt-in prompt must be disallowed."
			Path  = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext"
			Name  = "NoFirsttimeprompt"
			Value = 1
		}
		@{
			Id    = "DTBI815"
			Task  = "Internet Explorer Processes for Notification Bars must be enforced (Reserved)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND"
			Name  = "(Reserved)"
			Value = "1"
		}
		@{
			Id    = "DTBI825"
			Task  = "Internet Explorer Processes for Notification Bars must be enforced (Explorer)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND"
			Name  = "explorer.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI835"
			Task  = "Internet Explorer Processes for Notification Bars must be enforced (IExplore)."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND"
			Name  = "iexplore.exe"
			Value = "1"
		}
		@{
			Id    = "DTBI018"
			Task  = "Check for publishers certificate revocation must be enforced."
			Path  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"
			Name  = "State"
			Value = "23C00"
		}
		@{
			Id    = "DTBI1040"
			Task  = "Do Not Track header must be sent."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "DoNotTrack"
			Value = 1
		}
		@{
			Id    = "DTBI980"
			Task  = "Ability to install new versions of Internet Explorer automatically must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "EnableAutoUpgrade"
			Value = 0
		}
		@{
			Id    = "DTBI1035"
			Task  = "Displaying of the reveal password button must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "DisablePasswordReveal"
			Value = 1
		}
		@{
			Id    = "DTBI1005"
			Task  = "Dragging of content from different domains across windows must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2709"
			Value = 3
		}
		@{
			Id    = "DTBI1000"
			Task  = "Dragging of content from different domains within a window must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "2708"
			Value = 3
		}
		@{
			Id    = "DTBI1025"
			Task  = "Dragging of content from different domains within a window must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "2708"
			Value = 3
		}
		@{
			Id    = "DTBI995"
			Task  = "Enhanced protected mode functionality must be enforced."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "Isolation"
			Value = "PMEM"
		}
		@{
			Id    = "DTBI1055"
			Task  = "Internet Explorer accelerator functionality must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Activities"
			Name  = "NoActivities"
			Value = 1
		}
		@{
			Id    = "DTBI1045"
			Task  = "Legacy filter functionality must be disallowed (Internet zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
			Name  = "270B"
			Value = 3
		}
		@{
			Id    = "DTBI1050"
			Task  = "Legacy filter functionality must be disallowed (Restricted Sites zone)."
			Path  = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"
			Name  = "270B"
			Value = 3
		}
		@{
			Id    = "DTBI1030"
			Task  = "URL Suggestions must be disallowed."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\DomainSuggestion"
			Name  = "Enabled"
			Value = 0
		}
		@{
			Id    = "DTBI985"
			Task  = "When enhanced protected mode is enabled, ActiveX controls must be disallowed to run in protected mode."
			Path  = "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main"
			Name  = "DisableEPMCompat"
			Value = 1
		}
	)
}
