from wafford.ui.screens.attack_menu import AttackMenu
from wafford.ui.screens.autopwn_menu import AutoPWNMenu
from wafford.ui.screens.bluetooth_menu import BluetoothMenu
from wafford.ui.screens.captive_portal_menu import CaptivePortalMenu
from wafford.ui.screens.crack_menu import CrackMenu
from wafford.ui.screens.deauth_menu import DeauthMenu
from wafford.ui.screens.dep_manager import DepManager
from wafford.ui.screens.dos_menu import DoSMenu
from wafford.ui.screens.enterprise_menu import EnterpriseMenu
from wafford.ui.screens.evil_twin_menu import EvilTwinMenu
from wafford.ui.screens.interface_menu import InterfaceMenu
from wafford.ui.screens.karma_menu import KarmaMenu
from wafford.ui.screens.log_viewer import LogViewer
from wafford.ui.screens.main_menu import MainMenu
from wafford.ui.screens.plugin_menu import PluginMenu
from wafford.ui.screens.pmkid_menu import PMKIDMenu
from wafford.ui.screens.report_menu import ReportMenu
from wafford.ui.screens.scan_menu import ScanMenu
from wafford.ui.screens.settings_menu import SettingsMenu
from wafford.ui.screens.update_menu import UpdateMenu
from wafford.ui.screens.wep_menu import WEPMenu
from wafford.ui.screens.wifi_direct_menu import WiFiDirectMenu
from wafford.ui.screens.wordlist_menu import WordlistMenu
from wafford.ui.screens.wpa_menu import WPAMenu
from wafford.ui.screens.wps_menu import WPSMenu

SCREEN_CLASSES = {
    "MainMenu": MainMenu,
    "InterfaceMgmt": InterfaceMenu,
    "NetworkScan": ScanMenu,
    "AttackMenu": AttackMenu,
    "AutoPWN": AutoPWNMenu,
    "WPSAttack": WPSMenu,
    "WPAAttacks": WPAMenu,
    "WEPAttacks": WEPMenu,
    "EvilTwin": EvilTwinMenu,
    "CaptivePortal": CaptivePortalMenu,
    "DeauthDoS": DeauthMenu,
    "PMKIDAttack": PMKIDMenu,
    "KarmaMana": KarmaMenu,
    "Enterprise802X": EnterpriseMenu,
    "WiFiDirect": WiFiDirectMenu,
    "DoSAttack": DoSMenu,
    "BluetoothRecon": BluetoothMenu,
    "Wordlists": WordlistMenu,
    "PasswordCrack": CrackMenu,
    "Reports": ReportMenu,
    "Plugins": PluginMenu,
    "Settings": SettingsMenu,
    "LogViewer": LogViewer,
    "UpdateMenu": UpdateMenu,
    "DepManager": DepManager,
}

__all__ = [
    "SCREEN_CLASSES",
    "MainMenu",
    "InterfaceMenu",
    "ScanMenu",
    "AttackMenu",
    "AutoPWNMenu",
    "WPSMenu",
    "WPAMenu",
    "WEPMenu",
    "EvilTwinMenu",
    "CaptivePortalMenu",
    "DeauthMenu",
    "PMKIDMenu",
    "KarmaMenu",
    "EnterpriseMenu",
    "WiFiDirectMenu",
    "DoSMenu",
    "BluetoothMenu",
    "WordlistMenu",
    "CrackMenu",
    "ReportMenu",
    "PluginMenu",
    "SettingsMenu",
    "LogViewer",
    "UpdateMenu",
    "DepManager",
]
