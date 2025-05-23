from cmath import e
import os, gc, sys, time, json, atexit
import ctypes, ctypes.wintypes
from PYAS_Engine import YRScan, DLScan
from PYAS_Suffixes import file_types
from PYAS_Language import translate_dict
from PYAS_Interface import Ui_MainWindow
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from subprocess import *
from threading import *
from Engine.PYAS_TrayMenu import create_tray_icon

class PROCESSENTRY32(ctypes.Structure): # 初始化定義
    _fields_ = [
    ("dwSize", ctypes.wintypes.DWORD),
    ("cntUsage", ctypes.wintypes.DWORD),
    ("th32ProcessID", ctypes.wintypes.DWORD),
    ("th32DefaultHeapID", ctypes.wintypes.LPVOID),
    ("th32ModuleID", ctypes.wintypes.DWORD),
    ("cntThreads", ctypes.wintypes.DWORD),
    ("th32ParentProcessID", ctypes.wintypes.DWORD),
    ("dwFlags", ctypes.wintypes.DWORD),
    ("szExeFile", ctypes.wintypes.CHAR * 260)]

class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
    ("dwState", ctypes.wintypes.DWORD),
    ("dwLocalAddr", ctypes.wintypes.DWORD),
    ("dwLocalPort", ctypes.wintypes.DWORD),
    ("dwRemoteAddr", ctypes.wintypes.DWORD),
    ("dwRemotePort", ctypes.wintypes.DWORD),
    ("dwOwningPid", ctypes.wintypes.DWORD)]

class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
    ("dwNumEntries", ctypes.wintypes.DWORD),
    ("table", MIB_TCPROW_OWNER_PID * 1)]

class FILE_NOTIFY_INFORMATION(ctypes.Structure):
    _fields_ = [
    ("NextEntryOffset", ctypes.wintypes.DWORD),
    ("Action", ctypes.wintypes.DWORD),
    ("FileNameLength", ctypes.wintypes.DWORD),
    ("FileName", ctypes.wintypes.WCHAR * 1024)]

class MainWindow_Controller(QMainWindow): # 初始化主程式
    def __init__(self): # 初始化調用
        super(MainWindow_Controller, self).__init__()
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.init_config_pyas() # 初始化程式

    def init_config_pyas(self):
        self.init_config_vars() # 初始化變數
        self.init_config_path() # 初始化路徑
        self.init_config_read() # 初始化配置
        self.init_config_wdll() # 初始化系統
        self.init_config_boot() # 初始化引導
        self.init_config_list() # 初始化列表
        self.init_config_data() # 初始化引擎
        self.init_config_icon() # 初始化圖標
        self.init_config_qtui() # 初始化介面
        self.init_config_color() # 初始化顏色
        self.init_config_conn() # 初始化交互
        self.init_config_lang() # 初始化語言
        self.init_config_func() # 初始化功能
        self.init_config_done() # 初始化完畢
        self.init_config_theme() # 初始化主題

    def init_config_vars(self): # 初始化變數
        self.pyae_version = "AI Engine"
        self.pyas_version = "3.3.0"
        self.mbr_value = None
        self.track_proc = None
        self.first_startup = 1
        self.pyas_opacity = 0
        self.gc_collect = 0
        self.block_window = 0
        self.total_scan = 0
        self.scan_time = 0
        self.virus_lock = {}
        self.Process_quantity = 0
        self.Process_list_all_pid = []
        self.default_json = {
        "language_ui": "en_US",  # "en_US", "zh_TW", "zh_CN"
        "theme_color": "White",  # "Solid color" or "./Theme/Path"
        "product_key": "None",   # "None" or "XXXXX-X..."
        "service_url": "None",   # "None" or "http://..."
        "proc_protect": 1, # "0" (Close), "1" (Open)
        "file_protect": 1, # "0" (Close), "1" (Open)
        "sys_protect": 1,  # "0" (Close), "1" (Open)
        "net_protect": 1,  # "0" (Close), "1" (Open)
        "cus_protect": 0,  # "0" (Close), "1" (Open)
        "sensitivity": 0,  # "0" (Medium), "1" (High)
        "extend_mode": 0,  # "0" (False), "1" (True)
        "white_lists": [],
        "block_lists": []}
        self.pass_windows = [
        {'': ''}, {'PYAS': 'Qt5152QWindowIcon'},
        {'': 'Shell_TrayWnd'}, {'': 'WorkerW'}]

    def init_config_path(self): # 初始化路徑
        try:
            self.path_conf = r"C:/ProgramData/PYAS"
            self.path_pyas = sys.argv[0].replace("\\", "/")
            self.path_dirs = os.path.dirname(self.path_pyas)
            self.file_conf = os.path.join(self.path_conf, "PYAS.json")
            self.path_model = os.path.join(self.path_dirs, "Engine/Model")
            self.path_rules = os.path.join(self.path_dirs, "Engine/Rules")
            self.path_driver = os.path.join(self.path_dirs, "Driver/Protect")
        except Exception as e:
            print(e)

    def reset_options(self): # 重置所有設定
        if self.question_event("您確定要重置所有設定嗎?"):
            self.clean_function()
            self.config_json = self.default_json
            self.init_config_write(self.config_json)
            self.init_config_pyas()

    def clean_function(self): # 清理運行函數
        self.first_startup = 1
        self.block_window = 0
        self.config_json["proc_protect"] = 0
        self.config_json["file_protect"] = 0
        self.config_json["sys_protect"] = 0
        self.config_json["net_protect"] = 0
        self.virus_scan_break()
        self.protect_drv_init()
        self.gc_collect = 0

    def init_config_read(self): # 初始化配置
        try:
            self.config_json = {}
            if not os.path.exists(self.path_conf): 
                os.makedirs(self.path_conf)
            if not os.path.exists(self.file_conf):
                self.init_config_write(self.config_json)
            with open(self.file_conf, "r") as f: 
                self.config_json = json.load(f)
            self.config_json["language_ui"] = self.config_json.get("language_ui", "en_US")
            self.config_json["theme_color"] = self.config_json.get("theme_color", "White")
            self.config_json["product_key"] = self.config_json.get("product_key", "None")
            self.config_json["service_url"] = self.config_json.get("service_url", "None")
            self.config_json["proc_protect"] = self.config_json.get("proc_protect", 1)
            self.config_json["file_protect"] = self.config_json.get("file_protect", 1)
            self.config_json["sys_protect"] = self.config_json.get("sys_protect", 1)
            self.config_json["net_protect"] = self.config_json.get("net_protect", 1)
            self.config_json["sensitivity"] = self.config_json.get("sensitivity", 0)
            self.config_json["extend_mode"] = self.config_json.get("extend_mode", 0)
            self.config_json["white_lists"] = self.config_json.get("white_lists", [])
            self.config_json["block_lists"] = self.config_json.get("block_lists", [])
        except Exception as e:
            print(e)

    def init_config_write(self, config): # 寫入配置
        try:
            with open(self.file_conf, "w") as f:
                f.write(json.dumps(config, indent=4, ensure_ascii=False))
        except Exception as e:
            print(e)

    def init_config_wdll(self): # 初始化系統
        try:
            self.ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
            self.psapi = ctypes.WinDLL('Psapi', use_last_error=True)
            self.user32 = ctypes.WinDLL('user32', use_last_error=True)
            self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            self.advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
            self.iphlpapi = ctypes.WinDLL('iphlpapi', use_last_error=True)
        except Exception as e:
            print(e)

    def init_config_boot(self): # 初始化引導
        try:
            # 多开检测
            self.lock_file_path = os.path.join(self.path_conf, "PYAS.lock")
            try:
                self.lock_file = open(self.lock_file_path, 'x')
            except FileExistsError:
                print("PYAS is already running.")
                sys.exit()

            # 注册清理函数以在程序退出时删除锁文件
            atexit.register(self._cleanup_lock_file)

            # 创建隔离区目录
            self.path_quarantine = os.path.join(self.path_conf, "Quarantine")
            if not os.path.exists(self.path_quarantine):
                os.makedirs(self.path_quarantine)

            # with open(r"\\.\PhysicalDrive0", "r+b") as f:
            #     self.mbr_value = f.read(512)
            # if self.mbr_value[510:512] != b'\x55\xAA':
            #     self.mbr_value = None
        except Exception as e:
            print(e)

    def _cleanup_lock_file(self): # 清理锁文件
        if hasattr(self, 'lock_file') and self.lock_file and hasattr(self.lock_file, 'close'):
            try:
                self.lock_file.close()
            except Exception as e:
                print(f"Error closing lock file: {e}")
        if hasattr(self, 'lock_file_path') and os.path.exists(self.lock_file_path):
            try:
                os.remove(self.lock_file_path)
            except OSError as e:
                print(f"Error removing lock file: {e}")

    def init_config_list(self): # 初始化列表
        try:
            self.exist_process = self.get_process_list()
            self.exist_connections = self.get_connections_list()
        except Exception as e:
            print(e)

    def init_config_data(self): # 初始化引擎
        try:
            self.model = DLScan()
            for root, dirs, files in os.walk(self.path_model):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.model.load_model(file_path)
        except Exception as e:
            print(e)
        try:
            self.rules = YRScan()
            for root, dirs, files in os.walk(self.path_rules):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.rules.load_rules(file_path)
        except Exception as e:
            print(e)

    def quarantine_file(self, file_path): # 隔離文件
        from Engine.PYAS_Quarantine import quarantine_file
        return quarantine_file(self, file_path)

    def init_config_icon(self): # 初始化圖標
        # 创建系统托盘图标和菜单
        self.tray_icon = create_tray_icon(self, self.trans)

    def on_tray_icon_activated(self, reason): # 处理系统托盘图标激活事件
        if reason == QSystemTrayIcon.Trigger or reason == QSystemTrayIcon.DoubleClick:
            self.init_config_show() # 双击或单击显示主界面

    def init_config_qtui(self): # 初始化介面
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.Process_sim = QStringListModel()
        self.Process_Timer = QTimer()
        self.Process_Timer.timeout.connect(self.process_list)
        self.ui.widget_2.lower()
        self.ui.Navigation_Bar.raise_()
        self.ui.Window_widget.raise_()
        self.ui.Virus_Scan_choose_widget.raise_()
        self.effect_shadow = QGraphicsDropShadowEffect(self)
        self.effect_shadow.setOffset(0,0)
        self.effect_shadow.setBlurRadius(10)
        self.effect_shadow.setColor(Qt.gray)
        self.ui.widget_2.setGraphicsEffect(self.effect_shadow)
        self.effect_shadow2 = QGraphicsDropShadowEffect(self)
        self.effect_shadow2.setOffset(0,0)
        self.effect_shadow2.setBlurRadius(10)
        self.effect_shadow2.setColor(Qt.gray) 
        self.ui.Navigation_Bar.setGraphicsEffect(self.effect_shadow2)
        self.effect_shadow3 = QGraphicsDropShadowEffect(self)
        self.effect_shadow3.setOffset(0,0)
        self.effect_shadow3.setBlurRadius(7)
        self.effect_shadow3.setColor(Qt.gray) 
        self.ui.Window_widget.setGraphicsEffect(self.effect_shadow3)
        self.ui.Virus_Scan_choose_widget.hide()
        self.ui.Virus_Scan_widget.hide()
        self.ui.Tools_widget.hide()
        self.ui.Protection_widget.hide()
        self.ui.Virus_Scan_Solve_Button.hide()
        self.ui.Virus_Scan_Break_Button.hide()
        self.ui.Process_widget.hide()
        self.ui.Setting_widget.hide()
        self.ui.About_widget.hide()
        self.ui.State_output.style().polish(self.ui.State_output.verticalScrollBar())
        self.ui.Virus_Scan_output.style().polish(self.ui.Virus_Scan_output.verticalScrollBar())
        self.ui.License_terms.setText('''MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.''')

    def init_config_conn(self): # 初始化交互
        self.ui.Close_Button.clicked.connect(self.minimize_to_tray)
        self.ui.Minimize_Button.clicked.connect(self.minimize_to_taskbar)
        self.ui.Menu_Button.clicked.connect(self.show_menu)
        self.ui.State_Button.clicked.connect(self.change_state_widget)
        self.ui.Tools_Button.clicked.connect(self.change_tools_widget)    
        self.ui.Virus_Scan_Button.clicked.connect(self.change_scan_widget)
        self.ui.Protection_Button.clicked.connect(self.change_protect_widget)
        self.ui.Setting_Button.clicked.connect(self.change_setting_widget)
        self.ui.Virus_Scan_output.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.Virus_Scan_output.customContextMenuRequested.connect(self.Virus_Scan_output_menu)
        self.ui.Virus_Scan_Solve_Button.clicked.connect(self.virus_solve)
        self.ui.Virus_Scan_choose_Button.clicked.connect(self.virus_scan_menu)
        self.ui.Virus_Scan_Break_Button.clicked.connect(self.virus_scan_break)
        self.ui.File_Scan_Button.clicked.connect(self.file_scan)
        self.ui.Path_Scan_Button.clicked.connect(self.path_scan)
        self.ui.Disk_Scan_Button.clicked.connect(self.disk_scan)
        self.ui.System_Process_Manage_Button.clicked.connect(lambda:self.change_tools(self.ui.Process_widget))
        self.ui.Repair_System_Files_Button.clicked.connect(self.repair_system)
        self.ui.Clean_System_Files_Button.clicked.connect(self.clean_system)
        self.ui.Window_Block_Button.clicked.connect(self.add_software_window)
        self.ui.Window_Block_Button_2.clicked.connect(self.remove_software_window)
        self.ui.Repair_System_Network_Button.clicked.connect(self.repair_network)
        self.ui.Reset_Options_Button.clicked.connect(self.reset_options)
        self.ui.Process_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ui.Process_list.customContextMenuRequested.connect(self.process_list_menu)
        self.ui.Protection_switch_Button.clicked.connect(self.protect_proc_init)
        self.ui.Protection_switch_Button_2.clicked.connect(self.protect_file_init)
        self.ui.Protection_switch_Button_3.clicked.connect(self.protect_sys_init)
        self.ui.Protection_switch_Button_4.clicked.connect(self.protect_drv_init)
        self.ui.Protection_switch_Button_5.clicked.connect(self.protect_net_init)
        self.ui.Protection_switch_Button_8.clicked.connect(self.protect_cus_init)
        self.ui.high_sensitivity_switch_Button.clicked.connect(self.change_sensitive)
        self.ui.extension_kit_switch_Button.clicked.connect(self.extension_kit)
        self.ui.cloud_services_switch_Button.clicked.connect(self.cloud_services)
        self.ui.Add_White_list_Button.clicked.connect(self.add_white_list)
        self.ui.Add_White_list_Button_3.clicked.connect(self.remove_white_list)
        self.ui.Language_Traditional_Chinese.clicked.connect(self.init_change_lang)
        self.ui.Language_Simplified_Chinese.clicked.connect(self.init_change_lang)
        self.ui.Language_English.clicked.connect(self.init_change_lang)
        self.ui.Theme_White.clicked.connect(self.init_change_theme)
        self.ui.Theme_Customize.clicked.connect(self.init_change_theme)
        self.ui.Theme_Green.clicked.connect(self.init_change_theme)
        self.ui.Theme_Yellow.clicked.connect(self.init_change_theme)
        self.ui.Theme_Blue.clicked.connect(self.init_change_theme)
        self.ui.Theme_Red.clicked.connect(self.init_change_theme)

    def minimize_to_taskbar(self): # 最小化到任务栏
        self.showMinimized()

    def minimize_to_tray(self): # 最小化到系统托盘
        self.hide()

    def quit_application(self): # 退出应用程序
        self.tray_icon.hide()
        QCoreApplication.quit()

    # 占位方法，用于新的系统托盘菜单项
    def open_trust_zone(self): # 打开信任区
        print("打开信任区")
        from Engine.PYAS_TrustZone import TrustZoneDialog
        trust_zone_dialog = TrustZoneDialog(self)
        trust_zone_dialog.exec_()

    def open_quarantine(self): # 打开隔离区
        print("打开隔离区")
        from Engine.PYAS_Quarantine import QuarantineDialog
        quarantine_dialog = QuarantineDialog(self)
        quarantine_dialog.exec_()

    def open_security_log(self): # 打开安全日志
        print("打开安全日志")
        # TODO: Implement functionality to open security log
        
    def get_current_time(self):
        """获取当前时间的格式化字符串"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def check_for_updates(self): # 检查更新
        print("检查更新")
        # TODO: Implement functionality to check for updates

    def open_security_settings(self): # 打开安全设置
        print("打开安全设置")
        # TODO: Implement functionality to open security settings

    def init_config_lang(self): # 初始化語言
        try:
            if self.config_json["language_ui"] == "zh_TW":
                self.ui.Language_Traditional_Chinese.setChecked(True)
            elif self.config_json["language_ui"] == "zh_CN":
                self.ui.Language_Simplified_Chinese.setChecked(True)
            elif self.config_json["language_ui"] == "en_US":
                self.ui.Language_English.setChecked(True)
            self.init_change_text()
        except Exception as e:
            print(e)

    def init_change_lang(self): # 變更語言
        try:
            if self.ui.Language_Traditional_Chinese.isChecked():
                self.config_json["language_ui"] = "zh_TW"
            elif self.ui.Language_Simplified_Chinese.isChecked():
                self.config_json["language_ui"] = "zh_CN"
            elif self.ui.Language_English.isChecked():
                self.config_json["language_ui"] = "en_US"
            self.init_change_text()
            self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    def trans(self, text):
        for k, v in translate_dict.get(self.config_json["language_ui"], translate_dict).items():
            text = text.replace(str(k), str(v))
        return text

    def init_change_text(self): # 變更文字
        self.ui.State_title.setText(self.trans("此裝置已受到防護"))
        self.ui.Window_title.setText(self.trans(f"PYAS Security"))
        self.ui.PYAS_CopyRight.setText(self.trans(f"Copyright© 2020-{max(int(time.strftime('%Y')), 2020)} PYAS Security"))
        self.ui.Virus_Scan_title.setText(self.trans("病毒掃描"))
        self.ui.Virus_Scan_text.setText(self.trans("請選擇掃描方式"))
        self.ui.Virus_Scan_choose_Button.setText(self.trans("病毒掃描"))
        self.ui.File_Scan_Button.setText(self.trans("檔案掃描"))
        self.ui.Path_Scan_Button.setText(self.trans("路徑掃描"))
        self.ui.Disk_Scan_Button.setText(self.trans("全盤掃描"))
        self.ui.Virus_Scan_Solve_Button.setText(self.trans("立即隔離"))
        self.ui.Virus_Scan_Break_Button.setText(self.trans("停止掃描"))
        self.ui.Process_Total_title.setText(self.trans("進程總數:"))
        self.ui.Protection_title.setText(self.trans("進程防護"))
        self.ui.Protection_illustrate.setText(self.trans("啟用此選項可以攔截進程病毒"))
        self.ui.Protection_switch_Button.setText(self.trans(self.ui.Protection_switch_Button.text()))
        self.ui.Protection_title_2.setText(self.trans("檔案防護"))
        self.ui.Protection_illustrate_2.setText(self.trans("啟用此選項可以監控檔案變更"))
        self.ui.Protection_switch_Button_2.setText(self.trans(self.ui.Protection_switch_Button_2.text()))
        self.ui.Protection_title_3.setText(self.trans("系統防護"))
        self.ui.Protection_illustrate_3.setText(self.trans("啟用此選項可以修復系統項目"))
        self.ui.Protection_switch_Button_3.setText(self.trans(self.ui.Protection_switch_Button_3.text()))
        self.ui.Protection_title_4.setText(self.trans("驅動防護"))
        self.ui.Protection_illustrate_4.setText(self.trans("啟用此選項可以增強自身防護"))
        self.ui.Protection_switch_Button_4.setText(self.trans(self.ui.Protection_switch_Button_4.text()))
        self.ui.Protection_title_5.setText(self.trans("網路防護"))
        self.ui.Protection_illustrate_5.setText(self.trans("啟用此選項可以監控網路通訊"))
        self.ui.Protection_switch_Button_5.setText(self.trans(self.ui.Protection_switch_Button_5.text()))
        self.ui.Protection_title_8.setText(self.trans("自訂防護"))
        self.ui.Protection_illustrate_8.setText(self.trans("啟用此選項可以選擇自訂防護"))
        self.ui.Protection_switch_Button_8.setText(self.trans(self.ui.Protection_switch_Button_8.text()))
        self.ui.State_log.setText(self.trans("日誌:"))
        self.ui.System_Process_Manage_title.setText(self.trans("進程管理"))
        self.ui.System_Process_Manage_illustrate.setText(self.trans("此選項可以實時查看系統進程"))
        self.ui.System_Process_Manage_Button.setText(self.trans("選擇"))
        self.ui.Clean_System_Files_title.setText(self.trans("垃圾清理"))
        self.ui.Clean_System_Files_illustrate.setText(self.trans("此選項可以清理暫存檔案"))
        self.ui.Clean_System_Files_Button.setText(self.trans("選擇"))
        self.ui.Repair_System_Files_title.setText(self.trans("系統修復"))
        self.ui.Repair_System_Files_illustrate.setText(self.trans("此選項可以修復系統註冊表"))
        self.ui.Repair_System_Files_Button.setText(self.trans("選擇"))
        self.ui.Repair_System_Network_title.setText(self.trans("網路修復"))
        self.ui.Repair_System_Network_illustrate.setText(self.trans("此選項可以重置系統網路連接"))
        self.ui.Repair_System_Network_Button.setText(self.trans("選擇"))
        self.ui.Reset_Options_title.setText(self.trans("重置選項"))
        self.ui.Reset_Options_illustrate.setText(self.trans("此選項可以重置所有設定選項"))
        self.ui.Reset_Options_Button.setText(self.trans("選擇"))
        self.ui.Window_Block_title.setText(self.trans("彈窗攔截"))
        self.ui.Window_Block_illustrate.setText(self.trans("此選項可以選擇指定窗口並攔截"))
        self.ui.Window_Block_Button.setText(self.trans("增加"))
        self.ui.Window_Block_Button_2.setText(self.trans("移除"))
        self.ui.PYAS_Version.setText(self.trans(f"PYAS Security V{self.pyas_version} ({self.pyae_version})"))
        self.ui.GUI_Made_title.setText(self.trans("介面製作:"))
        self.ui.GUI_Made_Name.setText(self.trans("mtkiao"))
        self.ui.Core_Made_title.setText(self.trans("核心製作:"))
        self.ui.Core_Made_Name.setText(self.trans("87owo"))
        self.ui.Testers_title.setText(self.trans("特別感謝:"))
        self.ui.Testers_Name.setText(self.trans("SYSTEM-WIN-ZDY"))
        self.ui.PYAS_URL_title.setText(self.trans("官方網站:"))
        self.ui.PYAS_URL.setText(self.trans("<html><head/><body><p><a href=\"https://github.com/87owo/PYAS\"><span style=\" text-decoration: underline; color:#000000;\">https://github.com/87owo/PYAS</span></a></p></body></html>"))
        self.ui.high_sensitivity_title.setText(self.trans("高靈敏度模式"))
        self.ui.high_sensitivity_illustrate.setText(self.trans("啟用此選項可以提高掃描引擎靈敏度"))
        self.ui.high_sensitivity_switch_Button.setText(self.trans(self.ui.high_sensitivity_switch_Button.text()))
        self.ui.extension_kit_title.setText(self.trans("擴展掃描引擎"))
        self.ui.extension_kit_illustrate.setText(self.trans("啟用此選項可以使用第三方擴展套件"))
        self.ui.extension_kit_switch_Button.setText(self.trans(self.ui.extension_kit_switch_Button.text()))
        self.ui.cloud_services_title.setText(self.trans("雲端掃描服務"))
        self.ui.cloud_services_illustrate.setText(self.trans("啟用此選項可以連接雲端掃描服務"))
        self.ui.cloud_services_switch_Button.setText(self.trans(self.ui.cloud_services_switch_Button.text()))
        self.ui.Add_White_list_title.setText(self.trans("增加到白名單"))
        self.ui.Add_White_list_illustrate.setText(self.trans("此選項可以選擇檔案並增加到白名單"))
        self.ui.Add_White_list_Button.setText(self.trans("增加"))
        self.ui.Add_White_list_Button_3.setText(self.trans("移除"))
        self.ui.Theme_title.setText(self.trans("顯色主題"))
        self.ui.Theme_illustrate.setText(self.trans("請選擇主題"))
        self.ui.Theme_Customize.setText(self.trans("自訂义主題"))
        self.ui.Theme_White.setText(self.trans("白色主題"))
        self.ui.Theme_Yellow.setText(self.trans("黃色主題"))
        self.ui.Theme_Red.setText(self.trans("紅色主題"))
        self.ui.Theme_Green.setText(self.trans("綠色主題"))
        self.ui.Theme_Blue.setText(self.trans("藍色主題"))
        self.ui.Language_title.setText(self.trans("顯示語言"))
        self.ui.Language_illustrate.setText(self.trans("請選擇語言"))
        self.ui.License_terms_title.setText(self.trans("許可條款:"))

    def init_config_color(self):
        self.config_theme = {
        "White": {"color": "White", "icon": ":/icon/Check.png",
        "button_on": """QPushButton{border:none;
        background-color:rgb(200,250,200);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(210,250,210);}""",
        "button_off": """QPushButton{border:none;
        background-color:rgb(230,230,230);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(220,220,220);}""",
        "widget_style": "background-color:rgb(255,255,255);",
        "window_style": "background-color:rgb(245,245,245);",
        "navigation_style": "background-color:rgb(235,235,235);"},#
        "Red": {"color": "Red", "icon": ":/icon/Check.png",
        "button_on": """QPushButton{border:none;
        background-color:rgb(250,200,200);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(250,210,210);}""",
        "button_off": """QPushButton{border:none;
        background-color:rgb(250,220,220);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(250,210,210);}""",
        "widget_style": "background-color:rgb(250,240,240);",
        "window_style": "background-color:rgb(250,230,230);",
        "navigation_style": "background-color:rgb(250,220,220);"},#
        "Green": {"color": "Green", "icon": ":/icon/Check.png",
        "button_on": """QPushButton{border:none;
        background-color:rgb(200,250,200);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(210,250,210);}""",
        "button_off": """QPushButton{border:none;
        background-color:rgb(220,250,220);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(210,250,210);}""",
        "widget_style": "background-color:rgb(240,250,240);",
        "window_style": "background-color:rgb(230,250,230);",
        "navigation_style": "background-color:rgb(220,250,220);"},#
        "Blue": {"color": "Blue", "icon": ":/icon/Check.png",
        "button_on": """QPushButton{border:none;
        background-color:rgb(200,250,250);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(210,250,250);}""",
        "button_off": """QPushButton{border:none;
        background-color:rgb(220,250,250);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(210,250,250);}""",
        "widget_style": "background-color:rgb(240,250,250);",
        "window_style": "background-color:rgb(230,250,250);",
        "navigation_style": "background-color:rgb(220,250,250);"},#
        "Yellow": {"color": "Yellow", "icon": ":/icon/Check.png",
        "button_on": """QPushButton{border:none;
        background-color:rgb(250,250,200);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(250,250,210);}""",
        "button_off": """QPushButton{border:none;
        background-color:rgb(250,250,220);border-radius: 10px;}
        QPushButton:hover{background-color:rgb(250,250,210);}""",
        "widget_style": "background-color:rgb(250,250,240);",
        "window_style": "background-color:rgb(250,250,230);",
        "navigation_style": "background-color:rgb(250,250,220);"}}
        self.init_change_color()

    def init_config_theme(self): # 初始化主題
        try:
            if self.config_json["theme_color"] == "White":
                self.ui.Theme_White.setChecked(True)
            elif self.config_json["theme_color"] == "Red":
                self.ui.Theme_Red.setChecked(True)
            elif self.config_json["theme_color"] == "Green":
                self.ui.Theme_Green.setChecked(True)
            elif self.config_json["theme_color"] == "Yellow":
                self.ui.Theme_Yellow.setChecked(True)
            elif self.config_json["theme_color"] == "Blue":
                self.ui.Theme_Blue.setChecked(True)
            elif os.path.exists(self.config_json["theme_color"]):
                self.ui.Theme_Customize.setChecked(True)
            self.init_change_color()
        except Exception as e:
            print(e)

    def init_change_theme(self): # 變更主題
        try:
            if self.ui.Theme_White.isChecked():
                self.config_json["theme_color"] = "White"
            elif self.ui.Theme_Red.isChecked():
                self.config_json["theme_color"] = "Red"
            elif self.ui.Theme_Green.isChecked():
                self.config_json["theme_color"] = "Green"
            elif self.ui.Theme_Blue.isChecked():
                self.config_json["theme_color"] = "Blue"
            elif self.ui.Theme_Yellow.isChecked():
                self.config_json["theme_color"] = "Yellow"
            elif self.ui.Theme_Customize.isChecked():
                self.config_json["theme_color"] = "Customize"
            self.init_change_color()
            self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    def init_change_color(self): # 變更色彩
        try:
            if self.config_json["theme_color"] in self.config_theme:
                self.theme = self.config_theme[self.config_json["theme_color"]]
                self.config_json["theme_color"] = self.theme["color"]
                self.ui.State_icon.setPixmap(QPixmap(self.theme["icon"]))
            else:
                if not os.path.exists(os.path.join(self.config_json["theme_color"], "Color.json")):
                    path = str(QFileDialog.getExistingDirectory(self, self.trans("自訂主題"), ""))
                    if path and os.path.exists(os.path.join(path, "Color.json")):
                        self.config_json["theme_color"] = path
                with open(os.path.join(self.config_json["theme_color"], "Color.json"), "r") as f: 
                    self.theme = json.load(f)
                icon_path = os.path.join(self.config_json["theme_color"], self.theme["icon"])
                self.ui.State_icon.setPixmap(QPixmap(icon_path))
            self.ui.Window_widget.setStyleSheet(self.theme["window_style"])
            self.ui.Navigation_Bar.setStyleSheet(self.theme["navigation_style"])
            self.ui.State_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.Virus_Scan_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.Tools_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.Process_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.Protection_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.Setting_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.About_widget.setStyleSheet(self.theme["widget_style"])
            self.ui.widget_2.setStyleSheet(self.theme["widget_style"])
            self.ui.Virus_Scan_choose_Button.setStyleSheet(self.theme["button_on"])
            self.ui.Add_White_list_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Add_White_list_Button_3.setStyleSheet(self.theme["button_off"])
            self.ui.System_Process_Manage_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Repair_System_Files_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Clean_System_Files_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Reset_Options_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Window_Block_Button.setStyleSheet(self.theme["button_off"])
            self.ui.Window_Block_Button_2.setStyleSheet(self.theme["button_off"])
            self.ui.Repair_System_Network_Button.setStyleSheet(self.theme["button_off"])
            if self.ui.Protection_switch_Button.text() == self.trans("已開啟"):
                self.ui.Protection_switch_Button.setStyleSheet(self.theme["button_on"])
            else:
                self.ui.Protection_switch_Button.setStyleSheet(self.theme["button_off"])
            if self.ui.Protection_switch_Button_2.text() == self.trans("已開啟"):
                self.ui.Protection_switch_Button_2.setStyleSheet(self.theme["button_on"])
            else:
                self.ui.Protection_switch_Button_2.setStyleSheet(self.theme["button_off"])
            if self.ui.Protection_switch_Button_3.text() == self.trans("已開啟"):
                self.ui.Protection_switch_Button_3.setStyleSheet(self.theme["button_on"])
            else:
                self.ui.Protection_switch_Button_3.setStyleSheet(self.theme["button_off"])
            if self.ui.Protection_switch_Button_4.text() == self.trans("已開啟"):
                self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_on"])
            else:
                self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
            if self.ui.Protection_switch_Button_5.text() == self.trans("已開啟"):
                self.ui.Protection_switch_Button_5.setStyleSheet(self.theme["button_on"])
            else:
                self.ui.Protection_switch_Button_5.setStyleSheet(self.theme["button_off"])
            if self.ui.Protection_switch_Button_8.text() == self.trans("已開啟"):
                self.ui.Protection_switch_Button_8.setStyleSheet(self.theme["button_on"])
            else:
                self.ui.Protection_switch_Button_8.setStyleSheet(self.theme["button_off"])
            if self.ui.high_sensitivity_switch_Button.text() == self.trans("已開啟"):
                self.ui.high_sensitivity_switch_Button.setStyleSheet(self.theme["button_on"])
            else:
                self.ui.high_sensitivity_switch_Button.setStyleSheet(self.theme["button_off"])
            if self.ui.extension_kit_switch_Button.text() == self.trans("已開啟"):
                self.ui.extension_kit_switch_Button.setStyleSheet(self.theme["button_on"])
            else:
                self.ui.extension_kit_switch_Button.setStyleSheet(self.theme["button_off"])
            if self.ui.cloud_services_switch_Button.text() == self.trans("已開啟"):
                self.ui.cloud_services_switch_Button.setStyleSheet(self.theme["button_on"])
            else:
                self.ui.cloud_services_switch_Button.setStyleSheet(self.theme["button_off"])
        except Exception as e:
            print(e)
            self.config_json["theme_color"] = "White"
            self.init_config_theme()

    def init_config_done(self): # 初始化完畢
        try:
            if len(sys.argv) > 1: 
                param = sys.argv[1].replace("/", "-")
                if "-h" not in param:
                    self.init_config_show()
            elif len(sys.argv) <= 1:
                self.init_config_show()
            self.first_startup = 0
        except Exception as e:
            print(e)

    def init_config_func(self): # 初始化功能
        try:
            if self.config_json["proc_protect"] == 1:
                self.protect_proc_init()
            if self.config_json["file_protect"] == 1:
                self.protect_file_init()
            if self.config_json["sys_protect"] == 1:
                self.protect_sys_init()
            if self.config_json["net_protect"] == 1:
                self.protect_net_init()
            #if self.config_json["cus_protect"] == 1:
                #self.protect_cus_init()
            if self.config_json["sensitivity"] == 1:
                self.change_sensitive()
            if self.config_json["extend_mode"] == 1:
                self.extension_kit()
            self.protect_drv_init()
            self.block_window_init()
            self.gc_collect_init()
        except Exception as e:
            print(e)

    def protect_proc_init(self): # 初始化進程防護
        try:
            if self.ui.Protection_switch_Button.text() == self.trans("已開啟"):
                self.ui.Protection_switch_Button.setText(self.trans("已關閉"))
                self.ui.Protection_switch_Button.setStyleSheet(self.theme["button_off"])
                self.config_json["proc_protect"] = 0
            else:
                self.config_json["proc_protect"] = 1
                Thread(target=self.protect_proc_thread, daemon=True).start()
                self.ui.Protection_switch_Button.setText(self.trans("已開啟"))
                self.ui.Protection_switch_Button.setStyleSheet(self.theme["button_on"])
            self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    def protect_file_init(self): # 初始化檔案防護
        try:
            if self.ui.Protection_switch_Button_2.text() == self.trans("已開啟"):
                self.ui.Protection_switch_Button_2.setText(self.trans("已關閉"))
                self.ui.Protection_switch_Button_2.setStyleSheet(self.theme["button_off"])
                self.config_json["file_protect"] = 0
            else:
                self.config_json["file_protect"] = 1
                Thread(target=self.protect_file_thread, daemon=True).start()
                self.ui.Protection_switch_Button_2.setText(self.trans("已開啟"))
                self.ui.Protection_switch_Button_2.setStyleSheet(self.theme["button_on"])
            self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    def protect_sys_init(self): # 初始化系統防護
        try:
            if self.ui.Protection_switch_Button_3.text() == self.trans("已開啟"):
                self.ui.Protection_switch_Button_3.setText(self.trans("已關閉"))
                self.ui.Protection_switch_Button_3.setStyleSheet(self.theme["button_off"])
                self.config_json["sys_protect"] = 0
            else:
                self.config_json["sys_protect"] = 1
                Thread(target=self.protect_boot_thread, daemon=True).start()
                Thread(target=self.protect_reg_thread, daemon=True).start()
                self.ui.Protection_switch_Button_3.setText(self.trans("已開啟"))
                self.ui.Protection_switch_Button_3.setStyleSheet(self.theme["button_on"])
            self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    def protect_drv_init(self): # 初始化驅動防護
        try:
            file_path = self.path_driver.replace("\\", "/")
            if os.path.exists(file_path):
                if self.ui.Protection_switch_Button_4.text() == self.trans("已開啟"):
                    result = Popen("sc stop PYAS_Driver", shell=True, stdout=PIPE, stderr=PIPE).wait()
                    if not self.first_startup:
                        if result == 0 or result == 577:
                            if self.question_event("使用此選項需要重啟，您確定要重啟嗎?"):
                                Popen(f'"{file_path}/Uninstall_Driver.bat"', shell=True, stdout=PIPE, stderr=PIPE)
                            else:
                                Popen("sc start PYAS_Driver", shell=True, stdout=PIPE, stderr=PIPE).wait()
                    if result == 1062 or result == 1060:
                        self.ui.Protection_switch_Button_4.setText(self.trans("已關閉"))
                        self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_off"])
                else:
                    result = Popen("sc start PYAS_Driver", shell=True, stdout=PIPE, stderr=PIPE).wait()
                    if not self.first_startup:
                        if result == 1060 or result == 3 or result == 577:
                            if self.question_event("此選項可能會與其他軟體不兼容，您確定要開啟嗎?"):
                                Popen("sc delete PYAS_Driver", shell=True, stdout=PIPE, stderr=PIPE).wait()
                                Popen(f'"{file_path}/Install_Driver.bat"', shell=True, stdout=PIPE, stderr=PIPE)
                            else:
                                Popen("sc stop PYAS_Driver", shell=True, stdout=PIPE, stderr=PIPE).wait()
                    if result == 0 or result == 1056:
                        self.ui.Protection_switch_Button_4.setText(self.trans("已開啟"))
                        self.ui.Protection_switch_Button_4.setStyleSheet(self.theme["button_on"])
        except Exception as e:
            print(e)

    def protect_net_init(self): # 初始化網路防護
        try:
            if self.ui.Protection_switch_Button_5.text() == self.trans("已開啟"):
                self.ui.Protection_switch_Button_5.setText(self.trans("已關閉"))
                self.ui.Protection_switch_Button_5.setStyleSheet(self.theme["button_off"])
                self.config_json["net_protect"] = 0
            else:
                self.config_json["net_protect"] = 1
                Thread(target=self.protect_net_thread, daemon=True).start()
                self.ui.Protection_switch_Button_5.setText(self.trans("已開啟"))
                self.ui.Protection_switch_Button_5.setStyleSheet(self.theme["button_on"])
            self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    def protect_cus_init(self): # 初始化自訂防護
        self.info_event("此功能不支持使用")
        #if self.ui.Protection_switch_Button_8.text() == self.trans("已開啟"):
            #self.ui.Protection_switch_Button_8.setText(self.trans("已關閉"))
            #self.ui.Protection_switch_Button_8.setStyleSheet(self.theme["button_off"])
            #self.config_json["cus_protect"] = 0
        #else:
            #self.config_json["cus_protect"] = 1
            #self.ui.Protection_switch_Button_8.setText(self.trans("已開啟"))
            #self.ui.Protection_switch_Button_8.setStyleSheet(self.theme["button_on"])
        #self.init_config_write(self.config_json)

    def change_sensitive(self): # 初始化靈敏度
        if self.ui.high_sensitivity_switch_Button.text() == self.trans("已開啟"):
            self.ui.high_sensitivity_switch_Button.setText(self.trans("已關閉"))
            self.ui.high_sensitivity_switch_Button.setStyleSheet(self.theme["button_off"])
            self.config_json["sensitivity"] = 0
        elif self.first_startup or self.question_event("此選項可能會誤報檔案，您確定要開啟嗎?"):
            self.config_json["sensitivity"] = 1
            self.ui.high_sensitivity_switch_Button.setText(self.trans("已開啟"))
            self.ui.high_sensitivity_switch_Button.setStyleSheet(self.theme["button_on"])
        self.init_config_write(self.config_json)

    def extension_kit(self): # 初始化擴展引擎
        if self.ui.extension_kit_switch_Button.text() == self.trans("已開啟"):
            self.ui.extension_kit_switch_Button.setText(self.trans("已關閉"))
            self.ui.extension_kit_switch_Button.setStyleSheet(self.theme["button_off"])
            self.config_json["extend_mode"] = 0
        else:
            self.config_json["extend_mode"] = 1
            self.ui.extension_kit_switch_Button.setText(self.trans("已開啟"))
            self.ui.extension_kit_switch_Button.setStyleSheet(self.theme["button_on"])
        self.init_config_write(self.config_json)

    def cloud_services(self): # 初始化雲端掃描
        self.info_event("此功能不支持使用")
        #if self.ui.cloud_services_switch_Button.text() == self.trans("已開啟"):
            #self.ui.cloud_services_switch_Button.setText(self.trans("已關閉"))
            #self.ui.cloud_services_switch_Button.setStyleSheet(self.theme["button_off"])
            #self.config_json["service_url"] = 0
        #else:
            #self.config_json["service_url"] = 1
            #self.ui.cloud_services_switch_Button.setText(self.trans("已開啟"))
            #self.ui.cloud_services_switch_Button.setStyleSheet(self.theme["button_on"])
        #self.init_config_write(self.config_json)

    def gc_collect_init(self): # 初始化程式回收
        try:
            self.gc_collect = 1
            Thread(target=self.gc_collect_thread, daemon=True).start()
        except Exception as e:
            print(e)

    def gc_collect_thread(self): # 程式回收線程
        while self.gc_collect:
            try:
                time.sleep(0.2)
                collected = gc.collect()
            except:
                pass

    def block_window_init(self): # 初始化彈窗攔截
        try:
            self.block_window = 1
            Thread(target=self.block_software_window, daemon=True).start()
        except Exception as e:
            print(e)

    def add_white_list(self): # 添加白名單
        try:
            file = str(QFileDialog.getExistingDirectory(self,self.trans("增加到白名單"),"")).replace("\\", "/")
            if file and self.question_event("您確定要增加到白名單嗎?"):
                if file not in self.config_json["white_lists"]:
                    self.config_json["white_lists"].append(file)
                self.info_event(f"成功增加到白名單: "+file)
                self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    def remove_white_list(self):
        try:
            file = str(QFileDialog.getExistingDirectory(self,self.trans("移除白名單"),"")).replace("\\", "/")
            if file and self.question_event("您確定要移除白名單嗎?"):
                if file in self.config_json["white_lists"]:
                    self.config_json["white_lists"].remove(file)
                self.info_event(f"成功移除白名單: "+file)
                self.init_config_write(self.config_json)
        except Exception as e:
            print(e)

    def add_software_window(self): # 添加彈窗攔截
        try:
            self.block_window = 0
            if self.question_event("請選擇要攔截的軟體彈窗"):
                while True:
                    QApplication.processEvents()
                    hWnd = self.user32.GetForegroundWindow()
                    window_info = self.get_window_info(hWnd)
                    if window_info not in self.pass_windows:
                        if self.question_event(f"您確定要攔截 {window_info} 嗎?"):
                            if window_info not in self.config_json["block_lists"]:
                                self.config_json["block_lists"].append(window_info)
                            self.info_event(f"成功增加到彈窗攔截: {window_info}")
                        break
                self.init_config_write(self.config_json)
            self.block_window_init()
        except Exception as e:
            print(e)

    def remove_software_window(self):
        try:
            self.block_window = 0
            if self.question_event("請選擇要取消攔截的軟體彈窗"):
                while True:
                    QApplication.processEvents()
                    hWnd = self.user32.GetForegroundWindow()
                    window_info = self.get_window_info(hWnd)
                    if window_info not in self.pass_windows:
                        if self.question_event(f"您確定要取消攔截 {window_info} 嗎?"):
                            if window_info in self.config_json["block_lists"]:
                                self.config_json["block_lists"].remove(window_info)
                            self.info_event(f"成功取消彈窗攔截: {window_info}")
                        break
                self.init_config_write(self.config_json)
            self.block_window_init()
        except Exception as e:
            print(e)

    def get_window_info(self, hWnd): # 取得窗口資訊
        length = self.user32.GetWindowTextLengthW(hWnd)
        title = ctypes.create_unicode_buffer(length + 1)
        self.user32.GetWindowTextW(hWnd, title, length + 1)
        window_title = str(title.value)
        class_name = ctypes.create_unicode_buffer(256)
        self.user32.GetClassNameW(hWnd, class_name, 256)
        class_name = str(class_name.value)
        return {window_title: class_name}

    def enum_windows_callback(self, hWnd, lParam):
        self.hwnd_list.append(hWnd)
        return True

    def get_all_windows(self):
        self.hwnd_list = []
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
        self.user32.EnumWindows(WNDENUMPROC(self.enum_windows_callback), 0)
        return self.hwnd_list

    def block_software_window(self):  # 彈窗攔截線程
        while self.block_window:
            try:
                time.sleep(0.2)
                if not self.config_json["block_lists"]:
                    continue
                for hWnd in self.get_all_windows():
                    window_info = self.get_window_info(hWnd)
                    if window_info in self.config_json["block_lists"]:
                        self.user32.SendMessageW(hWnd, 0x0010, 0xF060, 0) # WM_CLOSE, SC_CLOSE
                        self.user32.SendMessageW(hWnd, 0x0002, 0xF060, 0) # WM_DESTROY, SC_CLOSE
                        self.user32.SendMessageW(hWnd, 0x0012, 0xF060, 0) # WM_QUIT, SC_CLOSE
                        self.user32.SendMessageW(hWnd, 0x0112, 0xF060, 0) # WM_SYSCOMMAND, SC_CLOSE
            except Exception as e:
                print(e)

    def init_config_show(self): # 顯示畫面
        def update_opacity():
            if self.pyas_opacity <= 100:
                self.pyas_opacity += 2
                self.setWindowOpacity(self.pyas_opacity/100)
            else:
                self.timer.stop()
        self.pyas_opacity = 0
        self.show()
        self.timer = QTimer()
        self.timer.timeout.connect(update_opacity)
        self.timer.start(2)

    def init_config_hide(self): # 隱藏畫面
        def update_opacity():
            if self.pyas_opacity >= 0:
                self.pyas_opacity -= 2
                self.setWindowOpacity(self.pyas_opacity/100)
            else:
                self.timer.stop()
                self.hide()
        self.timer = QTimer()
        self.timer.timeout.connect(update_opacity)
        self.timer.start(2)

    def showMinimized(self): # 最小化畫面
        if self.block_window:
            self.init_config_hide()
            #self.send_notify(self.trans("PYAS 已最小化到系統托盤圖標"))

    def nativeEvent(self, eventType, message):
        msg = ctypes.wintypes.MSG.from_address(int(message))
        if msg.message in [0x0010, 0x0002, 0x0012, 0x0112, 0x0212]:
            return True, 0
        return super(MainWindow_Controller, self).nativeEvent(eventType, message)

    def closeEvent(self, event): # 拦截关闭事件，最小化到系统托盘
        event.ignore()
        self.hide()

    def quit_application(self): # 真正的退出应用
        if self.question_event("您確定要退出 PYAS 和所有防護嗎?"):
            self.init_config_write(self.config_json)
            self.clean_function()
            QApplication.quit()

    def show_menu(self): # 功能選單
        #self.WindowMenu = QMenu()
        #Main_Settings = QAction(self.trans("設定"),self)
        #Main_Update = QAction(self.trans("更新"),self)
        #Main_About = QAction(self.trans("關於"),self)
        #self.WindowMenu.addAction(Main_Settings)
        #self.WindowMenu.addAction(Main_Update)
        #self.WindowMenu.addAction(Main_About)
        #Qusetion = self.WindowMenu.exec_(self.ui.Menu_Button.mapToGlobal(QPoint(0, 30)))
        #if Qusetion == Main_About and self.ui.About_widget.isHidden():
        if self.ui.About_widget.isHidden():
            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.About_widget.show()
            self.ui.Setting_widget.hide()
            self.Process_Timer.stop()
            self.change_animation_3(self.ui.About_widget,0.5)
            self.change_animation_5(self.ui.About_widget,80,50,761,481)
        #if Qusetion == Main_Update:
            #self.update_database()

    def update_database(self): # 更新數據
        try:
            if self.question_event("您確定要更新數據庫嗎?"):
                self.info_event(f"Not support this function")
                pass
        except Exception as e:
            print(e)

    def change_animation(self,widget): # 畫面動畫
        x, y = 80, widget.pos().y()
        self.anim = QPropertyAnimation(widget, b"geometry")
        widget.setGeometry(QRect(x - 60,y, 761, 481))
        self.anim.setKeyValueAt(0.2, QRect(x - 30,y,761,481))
        self.anim.setKeyValueAt(0.3, QRect(x - 10,y,761,481))
        self.anim.setKeyValueAt(0.4, QRect(x - 5,y,761,481))
        self.anim.setKeyValueAt(1, QRect(x,y,761,481))
        self.anim.start()

    def change_animation_3(self,widget,time):
        self.opacity = QGraphicsOpacityEffect()
        self.opacity.setOpacity(0)
        self.opacity.i = self.opacity.opacity()
        widget.setGraphicsEffect(self.opacity)
        widget.setAutoFillBackground(True)
        self.timer = QTimer()
        self.timer.timeout.connect(self.timeout)
        self.timer.start(2)

    def timeout(self): # 透明度動畫
        if self.opacity.i <= 1:
            self.opacity.i += 0.05
            self.opacity.setOpacity(self.opacity.i)
        else:
            self.timer.stop()

    def change_animation_4(self,widget,time,ny,ny2): # 掃描選單動畫
        x, y = widget.pos().x(), widget.pos().y()
        self.anim4 = QPropertyAnimation(widget, b"geometry")
        self.anim4.setDuration(time)
        self.anim4.setStartValue(QRect(x, y, 111, ny))
        self.anim4.setEndValue(QRect(x, y, 111, ny2))
        self.anim4.start()

    def change_animation_5(self,widget,x,y,nx,ny): # 設置動畫
        self.anim = QPropertyAnimation(widget, b"geometry")
        widget.setGeometry(QRect(x,y - 45, nx,ny))
        self.anim.setKeyValueAt(0.2, QRect(x,y - 30,nx,ny))
        self.anim.setKeyValueAt(0.3, QRect(x,y - 10,nx,ny))
        self.anim.setKeyValueAt(0.4, QRect(x,y - 5,nx,ny))
        self.anim.setKeyValueAt(1, QRect(x,y,nx,ny))
        self.anim.start()

    def change_setting_widget(self): # 狀態動畫
        if self.ui.Setting_widget.isHidden():
            self.change_animation_3(self.ui.Setting_widget,0.5)
            self.change_animation(self.ui.Setting_widget)
            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Setting_widget.show()
            self.Process_Timer.stop()

    def change_state_widget(self): # 狀態動畫
        if self.ui.State_widget.isHidden():
            self.change_animation_3(self.ui.State_widget,0.5)
            self.change_animation(self.ui.State_widget)
            self.ui.State_widget.show()
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Setting_widget.hide()
            self.Process_Timer.stop()

    def change_scan_widget(self): # 掃描動畫
        if self.ui.Virus_Scan_widget.isHidden():
            self.change_animation_3(self.ui.Virus_Scan_widget,0.5)
            self.change_animation(self.ui.Virus_Scan_widget)
            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.show()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Setting_widget.hide()
            self.Process_Timer.stop()

    def change_tools_widget(self): # 工具動畫
        if self.ui.Tools_widget.isHidden():
            self.change_animation_3(self.ui.Tools_widget,0.5)
            self.change_animation(self.ui.Tools_widget)
            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.show()
            self.ui.Protection_widget.hide()
            self.ui.Process_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Setting_widget.hide()
            self.Process_Timer.stop()

    def change_protect_widget(self): # 防護動畫
        if self.ui.Protection_widget.isHidden():
            self.change_animation_3(self.ui.Protection_widget,0.5)
            self.change_animation(self.ui.Protection_widget)
            self.ui.State_widget.hide()
            self.ui.Virus_Scan_widget.hide()
            self.ui.Tools_widget.hide()
            self.ui.Protection_widget.show()
            self.ui.Process_widget.hide()
            self.ui.About_widget.hide()
            self.ui.Setting_widget.hide()
            self.Process_Timer.stop()

    def change_tools(self,widget): # 切換工具
        self.Process_Timer.stop()
        self.ui.Tools_widget.hide()
        self.ui.Setting_widget.hide()
        self.ui.About_widget.hide()
        if widget == self.ui.Process_widget:
            self.Process_Timer.start(0)
        self.change_animation_3(widget,0.5)
        self.change_animation(widget)
        widget.show()

    def mousePressEvent(self, event): # 滑鼠按下動畫
        def update_opacity():
            if self.pyas_opacity > 80 and self.m_flag == True:
                self.pyas_opacity -= 1
                self.setWindowOpacity(self.pyas_opacity/100)
            else:
                self.timer.stop()
        x, y = event.x(), event.y()
        if event.button()==Qt.LeftButton and x >= 10 and x <= 841 and y >= 10 and y <= 49:
            self.m_flag = True
            self.m_Position=event.globalPos()-self.pos()
            event.accept()
            self.timer = QTimer()
            self.timer.timeout.connect(update_opacity)
            self.timer.start(5)

    def mouseMoveEvent(self, QMouseEvent): # 滑鼠拖曳動畫
        try:
            if Qt.LeftButton and self.m_flag:
                self.move(QMouseEvent.globalPos()-self.m_Position)
                QApplication.processEvents()
                QMouseEvent.accept()
        except:
            pass

    def mouseReleaseEvent(self, QMouseEvent): # 滑鼠鬆開動畫
        def update_opacity():
            if self.pyas_opacity < 100 and self.m_flag == False:
                self.pyas_opacity += 1
                self.setWindowOpacity(self.pyas_opacity/100)
            else:
                self.timer.stop()
        self.m_flag = False
        self.setCursor(QCursor(Qt.ArrowCursor))
        self.timer = QTimer()
        self.timer.timeout.connect(update_opacity)
        self.timer.start(5)

    def paintEvent(self, event):
        pat2 = QPainter(self)
        pat2.setRenderHint(QPainter.Antialiasing)
        pat2.setBrush(Qt.white)
        pat2.setPen(Qt.transparent)
        rect = self.rect()
        rect.setLeft(10)
        rect.setTop(10)
        rect.setWidth(rect.width()-10)
        rect.setHeight(rect.height()-10)
        pat2.drawRoundedRect(rect, 1, 1)

    def info_event(self, text): # 顯示訊息
        try:
            print(f"[Info] > {text}")
            if not self.first_startup:
                QMessageBox.information(self, "Info", self.trans(str(text)), QMessageBox.Ok)
        except:
            pass

    def question_event(self, text): # 詢問訊息
        try:
            print(f"[Quest] > {text}")
            if not self.first_startup:
                return QMessageBox.question(self, "Quest",
                self.trans(str(text)),QMessageBox.Yes|QMessageBox.No) == 16384
        except:
            return False

    def send_notify(self, text, notify_bar=True): # 發送通知
        try:
            now_time = time.strftime('%Y-%m-%d %H:%M:%S')
            print(f"[Notify] > [{now_time}] {text}")
            QMetaObject.invokeMethod(self.ui.State_output, "append",
            Qt.QueuedConnection, Q_ARG(str, f"[{now_time}] {text}"))
            if not self.first_startup and notify_bar == True:
                self.tray_icon.showMessage(now_time, text, 5000)
        except:
            pass

    def process_list(self): # 排序列表
        try:
            Process_list_app = []
            for pid in self.get_process_list():
                QApplication.processEvents()
                h_process = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
                file = self.get_process_file(h_process).replace("\\", "/")
                if os.path.exists(file):
                    Process_list_app.append((pid, f"[{pid}] > {file}"))
            Process_list_app.sort(key=lambda x: x[0])
            self.Process_list_all_pid = [pid for pid, _ in Process_list_app]
            if len(self.Process_list_all_pid) != self.Process_quantity:
                self.Process_quantity = len(self.Process_list_all_pid)
                self.ui.Process_Total_View.setText(str(self.Process_quantity))
                process_display = [name for _, name in Process_list_app]
                self.Process_sim.setStringList(process_display)
                self.ui.Process_list.setModel(self.Process_sim)
        except Exception as e:
            print(e)

    def process_list_menu(self, pos): # 系統進程管理
        try:
            for i in self.ui.Process_list.selectedIndexes():
                selected_pid = self.Process_list_all_pid[i.row()]
            self.Process_popMenu = QMenu()
            self.kill_Process = QAction(self.trans("結束進程"), self)
            self.Process_popMenu.addAction(self.kill_Process)
            if self.Process_popMenu.exec_(self.ui.Process_list.mapToGlobal(pos)) == self.kill_Process:
                try:
                    hProcess = self.kernel32.OpenProcess(0x1F0FFF, False, selected_pid)
                    file_path = self.get_process_file(hProcess).replace('\\', '/')
                    if file_path == self.path_pyas:
                        self.close()
                    else:
                        self.kernel32.TerminateProcess(hProcess, 0)
                    self.kernel32.CloseHandle(hProcess)
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)

    def init_scan(self): # 初始化掃描
        try:
            self.ui.Virus_Scan_text.setText(self.trans("正在初始化中"))
            QApplication.processEvents()
            try:
                for file in self.virus_lock:
                    self.lock_file(file, False)
            except:
                pass
            self.scan_file = True
            self.total_scan = 0
            self.scan_time = time.time()
            self.virus_lock = {}
            self.virus_list_ui = []
            self.ui.Virus_Scan_Solve_Button.hide()
            self.ui.Virus_Scan_choose_widget.hide()
            self.ui.Virus_Scan_choose_Button.hide()
            self.ui.Virus_Scan_Break_Button.show()
            self.ui.Virus_Scan_output.clear()
        except Exception as e:
            print(e)

    def Virus_Scan_output_menu(self, point): # 複製掃描內容
        def copyPathFunc():
            item_row = False
            for i in self.ui.Virus_Scan_output.selectedIndexes():
                item_row = self.virus_list_ui[i.row()]
            if item_row:
                pyperclip.copy(item_row.replace("/", "\\"))
        menu = QMenu()
        copyPath = menu.addAction(self.trans("複製路徑"))
        copyPath.triggered.connect(lambda: copyPathFunc())
        menu.exec_(self.ui.Virus_Scan_output.mapToGlobal(point))

    def lock_file(self, file, lock): # 鎖定檔案
        try:
            if lock:
                self.virus_lock[file] = os.open(file, os.O_RDWR)
                msvcrt.locking(self.virus_lock[file], msvcrt.LK_NBRLCK, os.path.getsize(file))
            else:
                msvcrt.locking(self.virus_lock[file], msvcrt.LK_UNLCK, os.path.getsize(file))
                os.close(self.virus_lock[file])
        except Exception as e:
            print(e)

    def virus_solve(self): # 清理病毒
        try:
            self.ui.Virus_Scan_Solve_Button.hide()
            # Iterate through items in the list widget
            files_to_process = []
            for i in range(self.ui.Virus_Scan_output.count()):
                item = self.ui.Virus_Scan_output.item(i)
                file = item.data(Qt.UserRole)
                if file and item.checkState() == Qt.Checked:
                    files_to_process.append(file)

            for file in files_to_process:
                try:
                    QMetaObject.invokeMethod(self.ui.Virus_Scan_title, "setText",
                    Qt.QueuedConnection, Q_ARG(str, self.trans("正在隔離")))
                    QMetaObject.invokeMethod(self.ui.Virus_Scan_text, "setText",
                    Qt.QueuedConnection, Q_ARG(str, file))
                    QApplication.processEvents()

                    # Release the lock before quarantining
                    self.lock_file(file, False)
                    self.ransom_counts = 0 # Reset ransom_counts if used for locking

                    # 检查文件是否在信任区
                    from Engine.PYAS_TrustZone import is_file_trusted
                    if is_file_trusted(self, file):
                        print(f"File in trust zone, skipping: {file}")
                        continue
                        
                    quarantined_path = self.quarantine_file(file)
                    if quarantined_path:
                        print(f"File quarantined: {file} -> {quarantined_path}")
                    else:
                        print(f"Failed to quarantine file: {file}")
                except Exception as e:
                    print(f"Error processing file {file}: {e}")
                    continue

            # Clear the virus list UI and the virus_lock dictionary after processing
            self.ui.Virus_Scan_output.clear()
            self.virus_lock.clear()
            QMetaObject.invokeMethod(self.ui.Virus_Scan_title, "setText",
            Qt.QueuedConnection, Q_ARG(str, self.trans("病毒掃描")))
            QMetaObject.invokeMethod(self.ui.Virus_Scan_text, "setText",
            Qt.QueuedConnection, Q_ARG(str, self.trans("請選擇掃描方式")))
        except Exception as e:
            print(e)

    def write_scan(self, state, file): # 顯示掃描結果
        try:
            if state and file:
                self.lock_file(file, True)
                item = QListWidgetItem()
                item.setText(f"[{state}] {file}")
                item.setData(Qt.UserRole, file) # Store original file path
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Checked)
                self.ui.Virus_Scan_output.addItem(item)
        except:
            pass

    def answer_scan(self): # 統計結果 
        try:
            QMetaObject.invokeMethod(self.ui.Virus_Scan_title, "setText",
            Qt.QueuedConnection, Q_ARG(str, self.trans("病毒掃描")))
            virus_count = self.ui.Virus_Scan_output.count()
            if virus_count > 0:
                self.ui.Virus_Scan_Solve_Button.show()
                self.ui.Virus_Scan_Break_Button.hide()
                self.ui.Virus_Scan_choose_Button.show()
                text = self.trans(f"當前發現 {virus_count} 個病毒")
            else:
                self.virus_scan_break()
                text = self.trans("當前未發現病毒")
            takes_time = int(time.time() - self.scan_time) + 1
            text_end = self.trans(f"，耗時 {takes_time} 秒，共掃描 {self.total_scan} 個檔案")
            QMetaObject.invokeMethod(self.ui.Virus_Scan_text, "setText",
            Qt.QueuedConnection, Q_ARG(str, text+text_end))
            self.send_notify(text+text_end)
        except Exception as e:
            print(e)

    def virus_scan_break(self): # 停止掃描
        self.scan_file = False
        self.ui.Virus_Scan_Break_Button.hide()
        self.ui.Virus_Scan_choose_Button.show()

    def virus_scan_menu(self):
        if self.ui.Virus_Scan_choose_widget.isHidden():
            self.ui.Virus_Scan_choose_widget.show()
            self.change_animation_4(self.ui.Virus_Scan_choose_widget,100,0,101)
        else:
            self.ui.Virus_Scan_choose_widget.hide()

    def file_scan(self): # 檔案掃描
        try:
            file = str(QFileDialog.getOpenFileName(self,self.trans("病毒掃描"),"")[0])
            if file and not self.check_whitelist(file):
                self.init_scan()
                self.scan_thread = Thread(target=self.write_scan,
                args=(self.start_scan(file),file,), daemon=True)
                self.scan_thread.start()
                self.total_scan += 1
                while self.scan_thread.is_alive():
                    QApplication.processEvents()
                self.scan_thread.join()
                self.answer_scan()
        except Exception as e:
            print(e)
            self.virus_scan_break()

    def path_scan(self): # 路徑掃描
        try:
            path = str(QFileDialog.getExistingDirectory(self,self.trans("病毒掃描"),""))
            if path and not self.check_whitelist(path):
                self.init_scan()
                self.scan_thread = Thread(target=self.traverse_path, args=(path,), daemon=True)
                self.scan_thread.start()
                while self.scan_thread.is_alive():
                    QApplication.processEvents()
                self.scan_thread.join()
                self.answer_scan()
        except Exception as e:
            print(e)
            self.virus_scan_break()

    def disk_scan(self): # 全盤掃描
        try:
            self.init_scan()
            for l in range(65, 91):
                if os.path.exists(f"{chr(l)}:/"):
                    self.scan_thread = Thread(target=self.traverse_path, args=(f"{chr(l)}:/",), daemon=True)
                    self.scan_thread.start()
                    while self.scan_thread.is_alive():
                        QApplication.processEvents()
                    self.scan_thread.join()
            self.answer_scan()
        except Exception as e:
            print(e)
            self.virus_scan_break()

    def traverse_path(self, file_path): # 遍歷路徑
        for fd in os.listdir(file_path):
            try:
                file = str(os.path.join(file_path,fd)).replace("\\", "/")
                if self.scan_file == False:
                    break
                elif os.path.isdir(file):
                    self.traverse_path(file)
                elif not self.check_whitelist(file):
                    QMetaObject.invokeMethod(self.ui.Virus_Scan_title, "setText",
                    Qt.QueuedConnection, Q_ARG(str, self.trans("正在掃描")))
                    QMetaObject.invokeMethod(self.ui.Virus_Scan_text, "setText",
                    Qt.QueuedConnection, Q_ARG(str, file))
                    self.write_scan(self.start_scan(file), file)
                    self.total_scan += 1
            except:
                pass

    def start_scan(self, file): # 調用掃描引擎
        try:
            label, level = self.model.dl_scan(file)
            if label and self.config_json["sensitivity"]:
                return f"{label}.{level}"
            elif label and level >= self.model.values:
                return f"{label}.{level}"
        except Exception as e:
            print(e)
        try:
            if self.config_json["extend_mode"]:
                label, level = self.rules.yr_scan(file)
                if label and isinstance(level, str):
                    return f"{label}.{level}"
        except Exception as e:
            print(e)
        return False

    def repair_system(self): # 修復系統
        try:
            if self.question_event("您確定要修復系統檔案嗎?"):
                self.repair_system_wallpaper()
                self.repair_system_restrict()
                self.repair_system_file_type()
                self.repair_system_file_icon()
                self.repair_system_image()
                self.info_event("修復系統檔案成功")
        except Exception as e:
            print(e)

    def open_registry_key(self, hkey, subkey, access=0xF003F): # 開啟註冊表
        key_handle = ctypes.wintypes.HANDLE()
        if self.advapi32.RegOpenKeyExW(hkey, subkey, 0, access, ctypes.byref(key_handle)) == 0:
            return key_handle
        return None

    def delete_registry_key(self, hkey, subkey): # 刪除註冊表鍵
        if self.advapi32.RegDeleteKeyW(hkey, subkey) == 0 and self.track_proc:
            self.kill_process("註冊表攔截", *self.track_proc)

    def delete_registry_value(self, hkey, subkey, value_name): # 刪除註冊表值
        key_handle = self.open_registry_key(hkey, subkey)
        if self.advapi32.RegDeleteValueW(key_handle, value_name) == 0 and self.track_proc:
            self.kill_process("註冊表攔截", *self.track_proc)
        self.advapi32.RegCloseKey(key_handle)

    def create_registry_keys(self, hkey, subkey): # 創建註冊表鍵
        key_handle = self.open_registry_key(hkey, subkey)
        if key_handle:
            self.advapi32.RegCreateKeyExW(hkey, subkey, 0, None, 0, 0xF003F, None, ctypes.byref(key_handle), None)
        self.advapi32.RegCloseKey(key_handle)

    def set_registry_value(self, hkey, subkey, value_name, value_data): # 設置註冊表值
        key_handle = self.open_registry_key(hkey, subkey)
        if key_handle:
            self.advapi32.RegSetValueExW(key_handle, value_name, 0, 1, value_data, (len(value_data) + 1) * 2)
        self.advapi32.RegCloseKey(key_handle)

    def repair_system_restrict(self): # 遍歷修復內容
        permissions = ["NoControlPanel", "NoDrives", "NoFileMenu", "NoFind", "NoRealMode", "NoRecentDocsMenu","NoSetFolders",
        "NoSetFolderOptions", "NoViewOnDrive", "NoClose", "NoRun", "NoDesktop", "NoLogOff", "NoFolderOptions", "RestrictRun",
        "NoViewContexMenu", "HideClock", "NoStartMenuMorePrograms", "NoStartMenuMyGames", "NoStartMenuMyMusic", "DisableCMD",
        "NoWinKeys", "StartMenuLogOff", "NoSimpleNetlDList", "NoLowDiskSpaceChecks", "DisableLockWorkstation", "Restrict_Run", 
        "DisableTaskMgr", "DisableRegistryTools", "DisableChangePassword", "Wallpaper", "NoComponents", "NoAddingComponents",
        "NoStartMenuPinnedList", "NoActiveDesktop", "NoSetActiveDesktop", "NoActiveDesktopChanges", "NoChangeStartMenu",
        "NoFavoritesMenu", "NoRecentDocsHistory", "NoSetTaskbar", "NoSMHelp", "NoTrayContextMenu", "NoViewContextMenu", 
        "NoManageMyComputerVerb", "NoWindowsUpdate", "ClearRecentDocsOnExit", "NoStartMenuNetworkPlaces"]
        keys_to_create = [(0x80000001, r"Software\Policies\Microsoft\MMC"),
        (0x80000001, r"Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}"),
        (0x80000001, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
        (0x80000001, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
        (0x80000001, r"SOFTWARE\Policies\Microsoft\Windows\System"),
        (0x80000002, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
        (0x80000002, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
        (0x80000002, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"),
        (0x80000002, r"SOFTWARE\Policies\Microsoft\Windows\System")]
        for hkey, subkey in keys_to_create:
            try:
                self.create_registry_keys(hkey, subkey)
                for value_name in permissions:
                    self.delete_registry_value(hkey, subkey, value_name)
            except:
                print(e)

    def repair_system_image(self): # 修復註冊表映像
        try:
            image_file = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
            key_handle = self.open_registry_key(0x80000002, image_file, 0xF003F)
            count = ctypes.wintypes.DWORD()
            self.advapi32.RegQueryInfoKeyW(key_handle, None, None, None,
            ctypes.byref(count), None, None, None, None, None, None, None)
            for i in range(count.value, -1, -1):
                try:
                    subkey_name = ctypes.create_unicode_buffer(256)
                    self.advapi32.RegEnumKeyW(key_handle, i, subkey_name, 256)
                    self.delete_registry_key(key_handle, subkey_name.value)
                except Exception as e:
                    print(e)
        except Exception as e:
            pass

    def repair_system_file_icon(self): # 修復執行檔圖標
        try:
            self.set_registry_value(0x80000000, 'exefile', 'DefaultIcon', '%1')
            self.set_registry_value(0x80000002, r'SOFTWARE\Classes\exefile', 'DefaultIcon', '%1')
        except:
            pass

    def repair_system_file_type(self): # 修復檔案開啟方式
        for hkey in [0x80000002, 0x80000001, 0x80000000]:
            for ext, value in [('.exe', 'exefile'), ('exefile', 'Application')]:
                try:
                    self.set_registry_value(hkey, r'SOFTWARE\Classes', ext, value)
                    self.set_registry_value(hkey, f'{ext}\\shell\\open\\command', '', '"%1" %*')
                except:
                    pass

    def repair_system_wallpaper(self): # 重置系統壁紙
        try:
            wallpaper = "C:/Windows/web/wallpaper/windows/img0.jpg"
            self.set_registry_value(0x80000001, "Wallpaper", ctypes.create_unicode_buffer(wallpaper), wallpaper)
            self.user32.SystemParametersInfoW(20, 0, wallpaper, 2)
        except Exception as e:
            print(e)

    def repair_network(self): # 重置網路設置
        try:
            if self.question_event("您確定要修復系統網路嗎?"):
                Popen("netsh winsock reset", shell=True, stdout=PIPE, stderr=PIPE).wait()
                if self.question_event("使用此選項需要重啟，您確定要重啟嗎?"):
                    Popen("shutdown -r -t 0", shell=True, stdout=PIPE, stderr=PIPE).wait()
        except Exception as e:
            print(e)

    def clean_system(self): # 清理系統暫存垃圾
        try:
            if self.question_event("您確定要清理系統垃圾嗎?"):
                self.total_deleted_size = 0
                self.traverse_temp(f"C:/Users/{os.getlogin()}/AppData/Local/Temp/")
                self.traverse_temp(f"C:/Windows/Temp/")
                self.traverse_temp(f"C:/$Recycle.Bin/")
                self.info_event(f"成功清理了 {self.total_deleted_size} 位元的系統垃圾")
        except Exception as e:
            print(e)

    def traverse_temp(self, path): # 刪除暫存操作
        for fd in os.listdir(path):
            try:
                file = str(os.path.join(path,fd)).replace("\\", "/")
                QApplication.processEvents()
                if os.path.isdir(file):
                    self.traverse_temp(file)
                else:
                    file_size = os.path.getsize(file)
                    self.ransom_counts = 0
                    os.remove(file)
                    self.total_deleted_size += file_size
            except:
                continue

    def protect_proc_thread(self): # 進程防護
        while self.config_json["proc_protect"]:
            try:
                time.sleep(0.1)
                new_process = self.get_process_list()
                for pid in new_process - self.exist_process:
                    self.handle_new_process(pid)
                self.exist_process = new_process
            except Exception as e:
                print(e)
        if self.ui.Protection_switch_Button.text() == self.trans("已開啟"):
            if not self.first_startup:
                self.send_notify(self.trans(f"竄改警告: self.proc_protect"), False)
                self.kill_process("竄改攔截", *self.track_proc)

    def get_process_list(self): # 獲取進程列表
        try:
            exist_process, pe32 = set(), PROCESSENTRY32()
            pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
            hSnapshot = self.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
            if self.kernel32.Process32First(hSnapshot, ctypes.byref(pe32)):
                while self.kernel32.Process32Next(hSnapshot, ctypes.byref(pe32)):
                    exist_process.add(pe32.th32ProcessID)
            self.kernel32.CloseHandle(hSnapshot)
            return exist_process
        except:
            return None

    def handle_new_process(self, pid): # 過濾並掃描
        try:
            h_process = self.kernel32.OpenProcess(0x1F0FFF, False, pid)
            file = self.get_process_file(h_process).replace("\\", "/")
            if os.path.exists(file) and not self.check_whitelist(file):
                self.lock_process(h_process, True)
                if self.start_scan(file):
                    self.kill_process("病毒攔截", h_process, file)
                elif ":/Windows" not in file:
                    self.track_proc = (h_process, file)
            self.lock_process(h_process, False)
        except Exception as e:
            print(e)
            self.lock_process(h_process, False)

    def check_whitelist(self, file): # 計算是否在白名單路徑內
        path = os.path.dirname(file)
        for whitefile in self.config_json["white_lists"]:
            if whitefile in path:
                return True
        return False

    def kill_process(self, info, h_process, file): # 終止進程
        try:
            self.kernel32.TerminateProcess(h_process, 0)
            self.kernel32.CloseHandle(h_process)
            self.send_notify(self.trans(f"{info}: ")+file, True)
            self.track_proc = None
        except:
            pass

    def lock_process(self, h_process, lock): # 暫停進程
        try:
            if lock:
                self.ntdll.NtSuspendProcess(h_process)
            else:
                self.ntdll.NtResumeProcess(h_process)
        except:
            pass

    def get_process_file(self, h_process): # 獲取進程檔案路徑
        exe_path = ctypes.create_unicode_buffer(260)
        self.psapi.GetProcessImageFileNameW(h_process, exe_path, ctypes.sizeof(exe_path) // 2)
        full_path = exe_path.value
        drives = [f"{chr(l)}:\\" for l in range(65, 91) if os.path.exists(f"{chr(l)}:\\")]
        for drive in drives:
            drive_letter = drive[0] + ":"
            device_path = ctypes.create_unicode_buffer(260)
            self.kernel32.QueryDosDeviceW(drive_letter, device_path, 260)
            if full_path.startswith(device_path.value):
                full_path = full_path.replace(device_path.value, drive, 1)
                return full_path.replace("\\\\", "\\")
        return full_path

    def protect_file_thread(self): # 檔案變更監控
        self.ransom_counts = 0
        hDir = self.kernel32.CreateFileW("C:\\", 0x80000000, 0x00000001 | 0x00000002 | 0x00000004, None, 3, 0x02000000, None)
        buffer = ctypes.create_string_buffer(2060)
        while self.config_json["file_protect"]:
            try:
                bytesReturned = ctypes.wintypes.DWORD()
                if self.kernel32.ReadDirectoryChangesW(hDir, buffer, ctypes.sizeof(buffer), True,
                    0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000100,
                    ctypes.byref(bytesReturned), None, None):
                    notify_info = FILE_NOTIFY_INFORMATION.from_buffer_copy(buffer[0:])
                    raw_filename = notify_info.FileName[:notify_info.FileNameLength // 2]
                    fpath = f"C:/{raw_filename}".replace("\\", "/")
                    ftype = os.path.splitext(fpath)[-1].lower()
                    if self.ransom_counts >= 5 and self.track_proc:
                        self.ransom_counts = 0
                        self.kill_process("勒索攔截", *self.track_proc)
                    elif ":/Windows" in fpath and "/Temp/" not in fpath:
                        if notify_info.Action in [2, 4] and ftype in file_types:
                            self.ransom_counts += 1
                    elif ":/Users" in fpath and "/AppData/" not in fpath:
                        if notify_info.Action in [2, 4] and ftype in file_types:
                            self.ransom_counts += 1
                    if ":/Windows" not in fpath and ":/Program" not in fpath:
                        if notify_info.Action == 3 and self.start_scan(fpath):
                            self.ransom_counts = 0
                            os.remove(fpath)
                            self.send_notify(self.trans("病毒刪除: ") + fpath, True)
            except:
                print(e)
        self.kernel32.CloseHandle(hDir)
        if self.ui.Protection_switch_Button_2.text() == self.trans("已開啟"):
            if not self.first_startup:
                self.send_notify(self.trans(f"竄改警告: self.file_protect"), False)
                self.kill_process("竄改攔截", *self.track_proc)

    def protect_boot_thread(self): # 引導防護
        while self.config_json["sys_protect"] and self.mbr_value:
            try:
                time.sleep(0.2)
                with open(r"\\.\PhysicalDrive0", "r+b") as f:
                    if self.mbr_value[510:512] != b'\x55\xAA':
                        self.kill_process("引導攔截", *self.track_proc)
                    elif f.read(512) != self.mbr_value:
                        f.seek(0)
                        f.write(self.mbr_value)
                        self.kill_process("引導攔截", *self.track_proc)
            except PermissionError as e:
                self.kill_process("引導攔截", *self.track_proc)
            except Exception as e:
                print(e)
        if self.ui.Protection_switch_Button_3.text() == self.trans("已開啟"):
            if not self.first_startup:
                self.send_notify(self.trans(f"竄改警告: self.sys_protect (boot)"), False)
                self.kill_process("竄改攔截", *self.track_proc)

    def protect_reg_thread(self): # 註冊表防護
        while self.config_json["sys_protect"]:
            try:
                time.sleep(0.2)
                self.repair_system_image()
                self.repair_system_restrict()
                self.repair_system_file_type()
                self.repair_system_file_icon()
            except:
                pass
        try:
            if hasattr(self, 'ui') and hasattr(self.ui, 'Protection_switch_Button_3') and \
               self.ui.Protection_switch_Button_3.text() == self.trans("已開啟"):
                if not self.first_startup:
                    self.send_notify(self.trans(f"竄改警告: self.sys_protect (reg)"), False)
                    self.kill_process("竄改攔截", *self.track_proc)
        except:
            pass

    def get_connections_list(self):  # 獲取連接列表
        try:
            connections = set()
            size = ctypes.wintypes.DWORD()
            ret = self.iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), True, 2, 5, 0)
            if ret != 122:
                raise ctypes.WinError(ret)
            buf = ctypes.create_string_buffer(size.value)
            ret = self.iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), True, 2, 5, 0)
            if ret != 0:
                raise ctypes.WinError(ret)
            num_entries = ctypes.cast(buf, ctypes.POINTER(ctypes.wintypes.DWORD)).contents.value
            row_size = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
            offset = ctypes.sizeof(ctypes.wintypes.DWORD)
            for i in range(num_entries):
                entry_address = ctypes.addressof(buf) + offset + i * row_size
                conn = ctypes.cast(entry_address, ctypes.POINTER(MIB_TCPROW_OWNER_PID)).contents
                connections.add((conn.dwOwningPid, conn.dwLocalAddr, conn.dwRemoteAddr, conn.dwState))
            return connections
        except Exception as e:
            print(e)
            return None

    def protect_net_thread(self):
        while self.config_json["net_protect"]:
            try:
                time.sleep(0.2)
                new_connections = self.get_connections_list()
                for key in new_connections - self.exist_connections:
                    self.handle_new_connections(key)
                self.exist_connections = new_connections
            except Exception as e:
                print(e)
        try:
            if hasattr(self, 'ui') and hasattr(self.ui, 'Protection_switch_Button_5') and \
               self.ui.Protection_switch_Button_5.text() == self.trans("已開啟"):
                if not self.first_startup:
                    self.send_notify(self.trans(f"竄改警告: self.net_protect"), False)
                    self.kill_process("竄改攔截", *self.track_proc)
        except:
            pass

    def handle_new_connections(self, key): # 過濾並掃描
        try:
            h_process = self.kernel32.OpenProcess(0x1F0FFF, False, key[0])
            file = self.get_process_file(h_process).replace("\\", "/")
            remote_ip = f"{key[2] & 0xFF}.{(key[2] >> 8) & 0xFF}.{(key[2] >> 16) & 0xFF}.{(key[2] >> 24) & 0xFF}"
            if os.path.exists(file) and not self.check_whitelist(file):
                self.lock_process(h_process, True)
                if remote_ip in self.rules.network:
                    self.kill_process("網路攔截", h_process, file)
            self.lock_process(h_process, False)
        except Exception as e:
            print(e)
            self.lock_process(h_process, False)

if __name__ == '__main__': # 檢查主程序
    QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QGuiApplication.setAttribute(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    MainWindow_Controller()
    sys.exit(app.exec_())
