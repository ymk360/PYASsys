import os
import json
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QListWidget, QPushButton, QFileDialog, QMessageBox
from PyQt5.QtCore import Qt

class TrustZoneDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setWindowTitle(self.parent.trans("信任区管理"))
        self.resize(600, 400)
        
        # 创建主布局
        main_layout = QVBoxLayout()
        
        # 创建文件列表
        self.file_list = QListWidget()
        main_layout.addWidget(self.file_list)
        
        # 创建按钮布局
        button_layout = QHBoxLayout()
        
        # 添加文件按钮
        self.add_button = QPushButton(self.parent.trans("添加文件"))
        self.add_button.clicked.connect(self.add_file)
        button_layout.addWidget(self.add_button)
        
        # 移除文件按钮
        self.remove_button = QPushButton(self.parent.trans("移除"))
        self.remove_button.clicked.connect(self.remove_file)
        button_layout.addWidget(self.remove_button)
        
        # 关闭按钮
        self.close_button = QPushButton(self.parent.trans("关闭"))
        self.close_button.clicked.connect(self.close)
        button_layout.addWidget(self.close_button)
        
        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)
        
        # 加载信任区文件列表
        self.load_trusted_files()
    
    def add_file(self):
        """添加文件到信任区"""
        file_paths, _ = QFileDialog.getOpenFileNames(
            self,
            self.parent.trans("选择要添加到信任区的文件"),
            "",
            "All Files (*.*)"
        )
        
        if not file_paths:
            return
        
        # 获取当前信任区文件列表
        trusted_files = self.get_trusted_files()
        
        # 添加新文件到信任区
        for file_path in file_paths:
            if file_path not in trusted_files:
                trusted_files.append(file_path)
        
        # 保存更新后的信任区文件列表
        self.save_trusted_files(trusted_files)
        
        # 重新加载信任区文件列表
        self.load_trusted_files()
        
        QMessageBox.information(
            self,
            self.parent.trans("添加成功"),
            self.parent.trans("文件已添加到信任区")
        )
    
    def remove_file(self):
        """从信任区移除文件"""
        current_item = self.file_list.currentItem()
        if not current_item:
            QMessageBox.warning(
                self,
                self.parent.trans("警告"),
                self.parent.trans("请选择要移除的文件")
            )
            return
        
        file_path = current_item.text()
        
        # 获取当前信任区文件列表
        trusted_files = self.get_trusted_files()
        
        # 从信任区移除文件
        if file_path in trusted_files:
            trusted_files.remove(file_path)
        
        # 保存更新后的信任区文件列表
        self.save_trusted_files(trusted_files)
        
        # 重新加载信任区文件列表
        self.load_trusted_files()
        
        QMessageBox.information(
            self,
            self.parent.trans("移除成功"),
            self.parent.trans("文件已从信任区移除")
        )
    
    def load_trusted_files(self):
        """加载信任区文件列表"""
        self.file_list.clear()
        
        trusted_files = self.get_trusted_files()
        self.file_list.addItems(trusted_files)
    
    def get_trusted_files(self):
        """获取信任区文件列表"""
        trust_zone_file = os.path.join(self.parent.path_conf, "TrustZone.json")
        
        if not os.path.exists(trust_zone_file):
            return []
        
        try:
            with open(trust_zone_file, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading trust zone file: {e}")
            return []
    
    def save_trusted_files(self, trusted_files):
        """保存信任区文件列表"""
        trust_zone_file = os.path.join(self.parent.path_conf, "TrustZone.json")
        
        try:
            with open(trust_zone_file, "w") as f:
                json.dump(trusted_files, f, indent=4)
        except Exception as e:
            print(f"Error saving trust zone file: {e}")

def is_file_trusted(main_window, file_path):
    """检查文件是否在信任区中"""
    trust_zone_file = os.path.join(main_window.path_conf, "TrustZone.json")
    
    if not os.path.exists(trust_zone_file):
        return False
    
    try:
        with open(trust_zone_file, "r") as f:
            trusted_files = json.load(f)
            return file_path in trusted_files
    except Exception as e:
        print(f"Error checking trust zone: {e}")
        return False