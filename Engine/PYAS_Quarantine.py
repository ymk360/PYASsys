import os
import json
import shutil
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QListWidget, QPushButton, QMessageBox
from PyQt5.QtCore import Qt

class QuarantineDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setWindowTitle(self.parent.trans("隔离区管理"))
        self.resize(600, 400)
        
        # 创建主布局
        main_layout = QVBoxLayout()
        
        # 创建文件列表
        self.file_list = QListWidget()
        main_layout.addWidget(self.file_list)
        
        # 创建按钮布局
        button_layout = QHBoxLayout()
        
        # 恢复文件按钮
        self.restore_button = QPushButton(self.parent.trans("恢复"))
        self.restore_button.clicked.connect(self.restore_file)
        button_layout.addWidget(self.restore_button)
        
        # 删除文件按钮
        self.delete_button = QPushButton(self.parent.trans("删除"))
        self.delete_button.clicked.connect(self.delete_file)
        button_layout.addWidget(self.delete_button)
        
        # 关闭按钮
        self.close_button = QPushButton(self.parent.trans("关闭"))
        self.close_button.clicked.connect(self.close)
        button_layout.addWidget(self.close_button)
        
        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)
        
        # 加载隔离区文件列表
        self.load_quarantined_files()
    
    def restore_file(self):
        """从隔离区恢复文件"""
        current_item = self.file_list.currentItem()
        if not current_item:
            QMessageBox.warning(
                self,
                self.parent.trans("警告"),
                self.parent.trans("请选择要恢复的文件")
            )
            return
        
        quarantine_info = self.get_quarantine_info(current_item.text())
        if not quarantine_info:
            QMessageBox.warning(
                self,
                self.parent.trans("错误"),
                self.parent.trans("无法获取隔离文件信息")
            )
            return
        
        original_path = quarantine_info.get("original_path")
        if not original_path:
            QMessageBox.warning(
                self,
                self.parent.trans("错误"),
                self.parent.trans("无法获取原始文件路径")
            )
            return
        
        # 确认是否恢复文件
        reply = QMessageBox.question(
            self,
            self.parent.trans("确认恢复"),
            self.parent.trans(f"确定要将文件恢复到 {original_path} 吗？"),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        # 检查原始目录是否存在，如果不存在则创建
        original_dir = os.path.dirname(original_path)
        if not os.path.exists(original_dir):
            try:
                os.makedirs(original_dir)
            except Exception as e:
                QMessageBox.critical(
                    self,
                    self.parent.trans("错误"),
                    self.parent.trans(f"无法创建目录: {e}")
                )
                return
        
        # 恢复文件
        quarantine_path = os.path.join(self.parent.path_quarantine, current_item.text())
        try:
            shutil.copy2(quarantine_path, original_path)
            
            # 从隔离区信息中移除该文件
            self.remove_quarantine_info(current_item.text())
            
            # 删除隔离区中的文件
            os.remove(quarantine_path)
            
            # 重新加载隔离区文件列表
            self.load_quarantined_files()
            
            QMessageBox.information(
                self,
                self.parent.trans("恢复成功"),
                self.parent.trans("文件已成功恢复")
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                self.parent.trans("错误"),
                self.parent.trans(f"恢复文件时出错: {e}")
            )
    
    def delete_file(self):
        """从隔离区删除文件"""
        current_item = self.file_list.currentItem()
        if not current_item:
            QMessageBox.warning(
                self,
                self.parent.trans("警告"),
                self.parent.trans("请选择要删除的文件")
            )
            return
        
        # 确认是否删除文件
        reply = QMessageBox.question(
            self,
            self.parent.trans("确认删除"),
            self.parent.trans("确定要永久删除此文件吗？此操作无法撤销。"),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        # 删除隔离区中的文件
        quarantine_path = os.path.join(self.parent.path_quarantine, current_item.text())
        try:
            os.remove(quarantine_path)
            
            # 从隔离区信息中移除该文件
            self.remove_quarantine_info(current_item.text())
            
            # 重新加载隔离区文件列表
            self.load_quarantined_files()
            
            QMessageBox.information(
                self,
                self.parent.trans("删除成功"),
                self.parent.trans("文件已成功删除")
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                self.parent.trans("错误"),
                self.parent.trans(f"删除文件时出错: {e}")
            )
    
    def load_quarantined_files(self):
        """加载隔离区文件列表"""
        self.file_list.clear()
        
        # 获取隔离区目录中的所有文件
        if os.path.exists(self.parent.path_quarantine):
            quarantined_files = [f for f in os.listdir(self.parent.path_quarantine) 
                               if os.path.isfile(os.path.join(self.parent.path_quarantine, f))]
            self.file_list.addItems(quarantined_files)
    
    def get_quarantine_info(self, filename):
        """获取隔离文件的信息"""
        quarantine_info_file = os.path.join(self.parent.path_conf, "QuarantineInfo.json")
        
        if not os.path.exists(quarantine_info_file):
            return None
        
        try:
            with open(quarantine_info_file, "r") as f:
                quarantine_info = json.load(f)
                return quarantine_info.get(filename)
        except Exception as e:
            print(f"Error loading quarantine info: {e}")
            return None
    
    def remove_quarantine_info(self, filename):
        """从隔离区信息中移除文件"""
        quarantine_info_file = os.path.join(self.parent.path_conf, "QuarantineInfo.json")
        
        if not os.path.exists(quarantine_info_file):
            return
        
        try:
            with open(quarantine_info_file, "r") as f:
                quarantine_info = json.load(f)
            
            if filename in quarantine_info:
                del quarantine_info[filename]
            
            with open(quarantine_info_file, "w") as f:
                json.dump(quarantine_info, f, indent=4)
        except Exception as e:
            print(f"Error updating quarantine info: {e}")

def quarantine_file(main_window, file_path):
    """将文件移动到隔离区"""
    if not os.path.exists(file_path):
        return None
    
    # 确保隔离区目录存在
    if not os.path.exists(main_window.path_quarantine):
        os.makedirs(main_window.path_quarantine)
    
    # 生成隔离区中的文件名
    file_name = os.path.basename(file_path)
    name, ext = os.path.splitext(file_name)
    counter = 1
    quarantine_path = os.path.join(main_window.path_quarantine, file_name)
    
    # 如果文件名已存在，则添加计数器
    while os.path.exists(quarantine_path):
        counter += 1
        quarantine_path = os.path.join(main_window.path_quarantine, f"{name}_{counter}{ext}")
    
    try:
        # 移动文件到隔离区
        shutil.move(file_path, quarantine_path)
        
        # 保存隔离文件信息
        quarantine_info_file = os.path.join(main_window.path_conf, "QuarantineInfo.json")
        quarantine_info = {}
        
        if os.path.exists(quarantine_info_file):
            try:
                with open(quarantine_info_file, "r") as f:
                    quarantine_info = json.load(f)
            except:
                pass
        
        # 添加新隔离文件的信息
        quarantine_filename = os.path.basename(quarantine_path)
        quarantine_info[quarantine_filename] = {
            "original_path": file_path,
            "quarantine_date": main_window.get_current_time(),
            "file_size": os.path.getsize(quarantine_path)
        }
        
        # 保存隔离区信息
        with open(quarantine_info_file, "w") as f:
            json.dump(quarantine_info, f, indent=4)
        
        return quarantine_path
    except Exception as e:
        print(f"Error quarantining file: {e}")
        return None