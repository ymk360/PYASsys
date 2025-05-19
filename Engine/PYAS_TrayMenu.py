import os
from PyQt5.QtWidgets import QSystemTrayIcon, QMenu, QAction, QApplication
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QFileIconProvider
from PyQt5.QtCore import QFileInfo
from PyQt5.QtCore import QPoint, Qt

def create_tray_icon(main_window, trans_func):
    """
    创建并配置系统托盘图标和菜单。

    Args:
        main_window: 主窗口实例，用于连接信号和访问属性。
        trans_func: 翻译函数。

    Returns:
        QSystemTrayIcon: 配置好的系统托盘图标实例。
    """
    tray_icon = QSystemTrayIcon(main_window)
    tray_icon.activated.connect(main_window.on_tray_icon_activated)
    # Assuming main_window has a path_pyas attribute
    tray_icon.setIcon(QFileIconProvider().icon(QFileInfo(main_window.path_pyas)))

    # 创建系统托盘菜单
    tray_menu = QMenu()
    open_action = QAction(trans_func("进入"), main_window)
    trust_zone_action = QAction(trans_func("信任区"), main_window)
    quarantine_action = QAction(trans_func("隔离区"), main_window)
    security_log_action = QAction(trans_func("安全日志"), main_window)
    check_update_action = QAction(trans_func("检查更新"), main_window)
    security_settings_action = QAction(trans_func("安全设置"), main_window)
    exit_action = QAction(trans_func("退出"), main_window)

    # 连接信号到主窗口的方法
    open_action.triggered.connect(main_window.init_config_show)
    trust_zone_action.triggered.connect(main_window.open_trust_zone)
    quarantine_action.triggered.connect(main_window.open_quarantine)
    security_log_action.triggered.connect(main_window.open_security_log)
    check_update_action.triggered.connect(main_window.check_for_updates)
    security_settings_action.triggered.connect(main_window.open_security_settings)
    exit_action.triggered.connect(main_window.quit_application)

    tray_menu.addAction(open_action)
    tray_menu.addAction(trust_zone_action)
    tray_menu.addAction(quarantine_action)
    tray_menu.addAction(security_log_action)
    tray_menu.addSeparator() # 添加分隔符
    tray_menu.addAction(check_update_action)
    tray_menu.addAction(security_settings_action)
    tray_menu.addSeparator() # 添加分隔符
    tray_menu.addAction(exit_action)

    tray_icon.setContextMenu(tray_menu)
    tray_icon.show()

    return tray_icon

# Note: The on_tray_icon_activated method remains in the main window class
# as it directly interacts with the main window's state (showing/hiding).