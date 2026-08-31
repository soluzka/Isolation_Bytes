rule Disable_Defender
{
	meta:
		author = "iam-py-test"
		description = "Detect files disabling or modifying Windows Defender, Windows Firewall, or Microsoft Smartscreen"
		// Yarahub data
		yarahub_uuid = "1fcd3702-cf5b-47b4-919d-6372c5412151"
		date = "2022-11-19"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "799a7f1507e5e7328081a038987e9a6f"
		yarahub_author_twitter = "@iam_py_test"
	strings:
		// Windows Defender
		$defender_policies_reg_key = "\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide
		$defender_powershell_pupprotection_Force = "Set-MpPreference -Force -PUAProtection" ascii wide
		$defender_powershell_pupprotection = "Set-MpPreference -PUAProtection" ascii wide
		$defender_reg_key = "\\SOFTWARE\\Microsoft\\Windows Defender" ascii wide
		$defender_disable_autoexclusions_powershell_force = "Set-MpPreference -Force -DisableAutoExclusions" ascii wide
		$defender_disable_autoexclusions_powershell = "Set-MpPreference -DisableAutoExclusions" ascii wide
		$defender_disable_MAPS_reporting_force = "Set-MpPreference -Force -MAPSReporting" ascii wide
		$defender_disable_MAPS_reporting = "Set-MpPreference -MAPSReporting" ascii wide
		$defender_disable_submit_samples_force = "Set-MpPreference -Force -SubmitSamplesConsent" ascii wide
		$defender_disable_submit_samples = "Set-MpPreference -SubmitSamplesConsent" ascii wide
		$defender_disable_realtime_force = "Set-MpPreference -Force -DisableRealtimeMonitoring" ascii wide
		$defender_disable_realtime = "Set-MpPreference -DisableRealtimeMonitoring" ascii wide
		$defender_disable_IPS_force = "Set-MpPreference -Force -DisableIntrusionPreventionSystem" ascii wide
		$defender_disable_IPS = "Set-MpPreference -DisableIntrusionPreventionSystem" ascii wide
		$defender_wd_filter_driver = "%SystemRoot%\\System32\\drivers\\WdFilter.sys" ascii wide
		$defender_wdboot_driver = "%SystemRoot%\\System32\\drivers\\WdBoot.sys" ascii wide
		$defender_wdboot_driver_noenv = "C:\\Windows\\System32\\drivers\\WdBoot.sys" ascii wide
		$defender_net_stop_windefend = "net stop windefend" nocase ascii wide
		$defender_net_stop_SecurityHealthService = "net stop SecurityHealthService" nocase ascii wide
		$defender_powershell_exclusionpath = "Add-MpPreference -ExclusionPath" xor ascii wide
		$defender_powershell_exclusionpath_base64 = "Add-MpPreference -ExclusionPath" base64
		$defender_powershell_exclusionext = "Add-MpPreference -ExclusionExtension" ascii wide
		$defender_powershell_exclusionprocess = "Add-MpPreference -ExclusionProcess" ascii wide
		$defender_powershell_exclusionip = "Add-MpPreference -ExclusionIpAddress" ascii wide
		$defender_uilockdown = "Set-MpPreference -UILockdown" ascii wide
		$defender_uilockdown_force = "Set-MpPreference -Force -UILockdown" ascii wide
		$defender_securitycenter = "\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\" ascii wide
		$defender_location = "C:\\Program Files (x86)\\Windows Defender\\" ascii wide
		$defender_clsid = "{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}" nocase ascii wide
		$defender_powershell_checksigsscan = "Set-MpPreference -CheckForSignaturesBeforeRunningScan" ascii wide
		$defender_powershell_noscanarchive = "Set-MpPreference -DisableArchiveScanning" ascii wide
		$defender_powershell_nobmon = "Set-MpPreference -DisableBehaviorMonitoring" ascii wide
		$defender_powershell_noemail = "Set-MpPreference -DisableEmailScanning" ascii wide
		$defender_powershell_ioav = "Set-MpPreference -DisableIOAVProtection" ascii wide
		$defender_powershell_privacymode = "Set-MpPreference -DisablePrivacyMode" ascii wide
		$defender_powershell_sigschday = "Set-MpPreference -SignatureScheduleDay" ascii wide
		$defender_powershell_noremovescan = "Set-MpPreference -DisableRemovableDriveScanning" ascii wide
		$defender_powershell_changewindefend = "Set-Service -Name windefend -StartupType " nocase ascii wide
		$defender_powershell_changesecurityhealth = "Set-Service -Name securityhealthservice -StartupType " nocase ascii wide
		$defender_protocol_key = "HKEY_CLASSES_ROOT\\windowsdefender" nocase ascii wide
		$defender_powershell_controlledfolder_replace = "Set-MpPreference -ControlledFolderAccessAllowedApplications" nocase ascii wide
		$defender_powershell_controlledfolder_replace_force = "Set-MpPreference -Force -ControlledFolderAccessAllowedApplications" nocase ascii wide
		$defender_powershell_controlledfolder_add = "Add-MpPreference -ControlledFolderAccessAllowedApplications" nocase ascii wide
		$defender_powershell_controlledfolder_add_force = "Add-MpPreference -Force -ControlledFolderAccessAllowedApplications" nocase ascii wide
		$defender_powershell_DisableScanningMappedNetworkDrivesForFullScan = "Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan" nocase ascii wide
		
		// Windows firewall
		$firewall_netsh_disable = "netsh advfirewall set allprofiles state off" ascii wide
		$firewall_reg_key = "\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\" ascii wide
		$firewall_sharedaccess_reg_key = "\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\" ascii wide
		$firewall_allow = "netsh firewall add allowedprogram" ascii wide
		
		// Microsoft Windows Malicious Software Removal Tool
		$MRT_reg_key = "\\SOFTWARE\\Policies\\Microsoft\\MRT" ascii wide
		$MRT_reg_key_wow64 = "\\SOFTWARE\\WOW6432NODE\\POLICIES\\MICROSOFT\\MRT" ascii wide
		
		// Edge
		$edge_phishing_filter = "\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter" ascii wide
		
		// Internet Explorer
		$ie_phishing_filter = "\\SOFTWARE\\Microsoft\\Internet Explorer\\PhishingFilter" ascii wide

	condition:
		any of them
}