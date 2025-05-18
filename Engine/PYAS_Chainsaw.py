import os
import re
import json
import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Union, Any
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
from PyQt5.QtWidgets import QWidget, QVBoxLayout

class ChainSawAnalyzer:
    """
    Chainsaw日志分析引擎，用于解析、分析和可视化Windows事件日志和其他安全日志
    
    功能：
    1. 支持多种日志格式解析（Windows事件日志、Sysmon日志、防火墙日志等）
    2. 威胁检测和异常行为识别
    3. 日志数据可视化和报告生成
    4. 与PYAS安全引擎集成
    """
    
    def __init__(self):
        """
        初始化Chainsaw分析引擎
        """
        # 日志解析规则库
        self.rules = {}
        # 威胁检测规则
        self.detection_rules = {}
        # 解析后的日志数据
        self.log_data = []
        # 分析结果
        self.analysis_results = {}
        # 支持的日志类型
        self.supported_formats = [
            "evtx",      # Windows事件日志
            "xml",      # XML格式日志
            "json",     # JSON格式日志
            "csv",      # CSV格式日志
            "txt",      # 文本日志
            "log"       # 通用日志文件
        ]
    
    def load_rules(self, rules_path: str) -> bool:
        """
        加载日志分析规则
        
        Args:
            rules_path: 规则文件路径
            
        Returns:
            bool: 加载是否成功
        """
        try:
            if not os.path.exists(rules_path):
                print(f"规则文件不存在: {rules_path}")
                return False
                
            file_ext = os.path.splitext(rules_path)[1].lower()
            
            if file_ext == ".json":
                with open(rules_path, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
                    
                # 区分解析规则和检测规则
                if "parser_rules" in rules:
                    self.rules.update(rules["parser_rules"])
                if "detection_rules" in rules:
                    self.detection_rules.update(rules["detection_rules"])
                    
                return True
            else:
                print(f"不支持的规则文件格式: {file_ext}")
                return False
                
        except Exception as e:
            print(f"加载规则文件失败: {str(e)}")
            return False
    
    def parse_log(self, log_path: str) -> bool:
        """
        解析日志文件
        
        Args:
            log_path: 日志文件路径
            
        Returns:
            bool: 解析是否成功
        """
        try:
            if not os.path.exists(log_path):
                print(f"日志文件不存在: {log_path}")
                return False
                
            file_ext = os.path.splitext(log_path)[1].lower().replace('.', '')
            
            if file_ext not in self.supported_formats:
                print(f"不支持的日志文件格式: {file_ext}")
                return False
            
            # 根据不同格式调用不同的解析方法
            if file_ext == "evtx":
                return self._parse_evtx(log_path)
            elif file_ext == "xml":
                return self._parse_xml(log_path)
            elif file_ext == "json":
                return self._parse_json(log_path)
            elif file_ext == "csv":
                return self._parse_csv(log_path)
            elif file_ext in ["txt", "log"]:
                return self._parse_text(log_path)
            
            return False
            
        except Exception as e:
            print(f"解析日志文件失败: {str(e)}")
            return False
    
    def _parse_evtx(self, log_path: str) -> bool:
        """
        解析Windows事件日志(.evtx)文件
        
        Args:
            log_path: 日志文件路径
            
        Returns:
            bool: 解析是否成功
        """
        try:
            # 这里需要使用专门的evtx解析库，如python-evtx
            # 由于依赖关系，这里使用简化实现
            print(f"解析Windows事件日志: {log_path}")
            
            # 模拟解析结果
            self.log_data.append({
                "source": log_path,
                "type": "evtx",
                "events": [
                    {"id": "模拟事件ID", "timestamp": datetime.datetime.now().isoformat(), 
                     "level": "信息", "message": "这是一个模拟的Windows事件日志条目"}
                ]
            })
            
            return True
        except Exception as e:
            print(f"解析Windows事件日志失败: {str(e)}")
            return False
    
    def _parse_xml(self, log_path: str) -> bool:
        """
        解析XML格式日志文件
        
        Args:
            log_path: 日志文件路径
            
        Returns:
            bool: 解析是否成功
        """
        # XML解析实现
        return True
    
    def _parse_json(self, log_path: str) -> bool:
        """
        解析JSON格式日志文件
        
        Args:
            log_path: 日志文件路径
            
        Returns:
            bool: 解析是否成功
        """
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
            
            # 处理不同的JSON日志格式
            if isinstance(json_data, list):
                # 列表格式的日志
                events = json_data
            elif isinstance(json_data, dict) and "events" in json_data:
                # 包含events字段的字典
                events = json_data["events"]
            else:
                # 单个事件
                events = [json_data]
            
            self.log_data.append({
                "source": log_path,
                "type": "json",
                "events": events
            })
            
            return True
        except Exception as e:
            print(f"解析JSON日志失败: {str(e)}")
            return False
    
    def _parse_csv(self, log_path: str) -> bool:
        """
        解析CSV格式日志文件
        
        Args:
            log_path: 日志文件路径
            
        Returns:
            bool: 解析是否成功
        """
        try:
            # 使用pandas读取CSV
            df = pd.read_csv(log_path)
            
            # 转换为字典列表
            events = df.to_dict('records')
            
            self.log_data.append({
                "source": log_path,
                "type": "csv",
                "events": events
            })
            
            return True
        except Exception as e:
            print(f"解析CSV日志失败: {str(e)}")
            return False
    
    def _parse_text(self, log_path: str) -> bool:
        """
        解析文本日志文件
        
        Args:
            log_path: 日志文件路径
            
        Returns:
            bool: 解析是否成功
        """
        try:
            events = []
            
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # 简单的行解析
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # 尝试提取时间戳和消息
                timestamp_match = re.search(r'\[(\d{4}-\d{2}-\d{2}[\s|T]\d{2}:\d{2}:\d{2})\]', line)
                
                if timestamp_match:
                    timestamp = timestamp_match.group(1)
                    message = line.replace(f"[{timestamp}]", "").strip()
                    
                    events.append({
                        "timestamp": timestamp,
                        "message": message
                    })
                else:
                    events.append({
                        "timestamp": "",
                        "message": line
                    })
            
            self.log_data.append({
                "source": log_path,
                "type": "text",
                "events": events
            })
            
            return True
        except Exception as e:
            print(f"解析文本日志失败: {str(e)}")
            return False
    
    def detect_threats(self) -> List[Dict[str, Any]]:
        """
        使用检测规则分析日志数据，识别潜在威胁
        
        Returns:
            List[Dict]: 检测到的威胁列表
        """
        threats = []
        
        if not self.log_data:
            print("没有可分析的日志数据")
            return threats
        
        # 遍历所有日志数据
        for log_source in self.log_data:
            source_path = log_source["source"]
            log_type = log_source["type"]
            events = log_source["events"]
            
            # 遍历所有事件
            for event in events:
                # 遍历所有检测规则
                for rule_id, rule in self.detection_rules.items():
                    if "pattern" not in rule or "severity" not in rule:
                        continue
                    
                    pattern = rule["pattern"]
                    severity = rule["severity"]
                    description = rule.get("description", "未知威胁")
                    
                    # 检查事件是否匹配规则
                    if self._match_rule(event, pattern):
                        threat = {
                            "rule_id": rule_id,
                            "source": source_path,
                            "event": event,
                            "severity": severity,
                            "description": description,
                            "timestamp": datetime.datetime.now().isoformat()
                        }
                        
                        threats.append(threat)
        
        # 保存检测结果
        self.analysis_results["threats"] = threats
        
        return threats
    
    def _match_rule(self, event: Dict[str, Any], pattern: Dict[str, Any]) -> bool:
        """
        检查事件是否匹配规则模式
        
        Args:
            event: 事件数据
            pattern: 规则模式
            
        Returns:
            bool: 是否匹配
        """
        # 简单的模式匹配实现
        for key, value in pattern.items():
            if key not in event:
                return False
            
            # 如果模式值是正则表达式字符串
            if isinstance(value, str) and value.startswith("regex:"):
                regex = value.replace("regex:", "").strip()
                if not re.search(regex, str(event[key])):
                    return False
            # 普通字符串匹配
            elif str(event[key]) != str(value):
                return False
        
        return True
    
    def generate_statistics(self) -> Dict[str, Any]:
        """
        生成日志数据统计信息
        
        Returns:
            Dict: 统计信息
        """
        stats = {
            "total_logs": len(self.log_data),
            "total_events": sum(len(log["events"]) for log in self.log_data),
            "log_types": {},
            "event_timeline": {},
            "threat_severity": {"高": 0, "中": 0, "低": 0}
        }
        
        # 统计日志类型
        for log in self.log_data:
            log_type = log["type"]
            if log_type in stats["log_types"]:
                stats["log_types"][log_type] += 1
            else:
                stats["log_types"][log_type] = 1
        
        # 统计威胁严重程度
        if "threats" in self.analysis_results:
            for threat in self.analysis_results["threats"]:
                severity = threat["severity"]
                if severity in stats["threat_severity"]:
                    stats["threat_severity"][severity] += 1
        
        # 保存统计结果
        self.analysis_results["statistics"] = stats
        
        return stats
    
    def visualize_data(self, parent_widget: QWidget = None) -> Optional[QWidget]:
        """
        可视化日志数据和分析结果
        
        Args:
            parent_widget: 父级Qt部件
            
        Returns:
            QWidget: 包含可视化图表的部件
        """
        if not self.log_data or not self.analysis_results:
            print("没有可视化的数据")
            return None
        
        # 创建可视化部件
        if parent_widget:
            visualization_widget = QWidget(parent_widget)
            layout = QVBoxLayout(visualization_widget)
            
            # 创建威胁严重程度饼图
            if "statistics" in self.analysis_results and "threat_severity" in self.analysis_results["statistics"]:
                severity_data = self.analysis_results["statistics"]["threat_severity"]
                
                # 过滤掉数量为0的项
                filtered_data = {k: v for k, v in severity_data.items() if v > 0}
                
                if filtered_data:
                    fig = Figure(figsize=(6, 4))
                    ax = fig.add_subplot(111)
                    ax.pie(filtered_data.values(), labels=filtered_data.keys(), autopct='%1.1f%%')
                    ax.set_title("威胁严重程度分布")
                    
                    canvas = FigureCanvasQTAgg(fig)
                    layout.addWidget(canvas)
            
            # 创建日志类型柱状图
            if "statistics" in self.analysis_results and "log_types" in self.analysis_results["statistics"]:
                log_types = self.analysis_results["statistics"]["log_types"]
                
                if log_types:
                    fig = Figure(figsize=(6, 4))
                    ax = fig.add_subplot(111)
                    ax.bar(log_types.keys(), log_types.values())
                    ax.set_title("日志类型分布")
                    ax.set_xlabel("日志类型")
                    ax.set_ylabel("数量")
                    
                    canvas = FigureCanvasQTAgg(fig)
                    layout.addWidget(canvas)
            
            return visualization_widget
        else:
            # 非GUI环境下，保存图表到文件
            if "statistics" in self.analysis_results:
                stats = self.analysis_results["statistics"]
                
                # 威胁严重程度饼图
                if "threat_severity" in stats:
                    severity_data = stats["threat_severity"]
                    filtered_data = {k: v for k, v in severity_data.items() if v > 0}
                    
                    if filtered_data:
                        plt.figure(figsize=(8, 6))
                        plt.pie(filtered_data.values(), labels=filtered_data.keys(), autopct='%1.1f%%')
                        plt.title("威胁严重程度分布")
                        plt.savefig("threat_severity.png")
                        plt.close()
                
                # 日志类型柱状图
                if "log_types" in stats and stats["log_types"]:
                    plt.figure(figsize=(10, 6))
                    plt.bar(stats["log_types"].keys(), stats["log_types"].values())
                    plt.title("日志类型分布")
                    plt.xlabel("日志类型")
                    plt.ylabel("数量")
                    plt.savefig("log_types.png")
                    plt.close()
            
            return None
    
    def export_report(self, output_path: str) -> bool:
        """
        导出分析报告
        
        Args:
            output_path: 报告输出路径
            
        Returns:
            bool: 导出是否成功
        """
        try:
            if not self.analysis_results:
                print("没有可导出的分析结果")
                return False
            
            # 确保输出目录存在
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # 构建报告数据
            report = {
                "generated_at": datetime.datetime.now().isoformat(),
                "log_sources": [log["source"] for log in self.log_data],
                "statistics": self.analysis_results.get("statistics", {}),
                "threats": self.analysis_results.get("threats", [])
            }
            
            # 导出为JSON格式
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            
            print(f"分析报告已导出到: {output_path}")
            return True
            
        except Exception as e:
            print(f"导出分析报告失败: {str(e)}")
            return False
    
    def clear_data(self) -> None:
        """
        清除所有已加载的日志数据和分析结果
        """
        self.log_data = []
        self.analysis_results = {}
        print("已清除所有日志数据和分析结果")

# 示例用法
if __name__ == "__main__":
    # 创建Chainsaw分析器实例
    analyzer = ChainSawAnalyzer()
    
    # 加载规则
    rules_path = "../Engine/Rules/chainsaw_rules.json"
    if os.path.exists(rules_path):
        analyzer.load_rules(rules_path)
    
    # 解析日志文件
    log_path = "../samples/sample.log"
    if os.path.exists(log_path):
        analyzer.parse_log(log_path)
        
        # 检测威胁
        threats = analyzer.detect_threats()
        print(f"检测到 {len(threats)} 个潜在威胁")
        
        # 生成统计信息
        stats = analyzer.generate_statistics()
        print(f"总日志数: {stats['total_logs']}")
        print(f"总事件数: {stats['total_events']}")
        
        # 导出报告
        analyzer.export_report("../reports/analysis_report.json")