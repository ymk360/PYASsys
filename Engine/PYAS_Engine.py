import yara

class ChainsawScanner:
    '''基于YARA规则的快速扫描引擎
    
    示例用法：
    >>> scanner = ChainsawScanner()
    >>> scanner.load_rules('Engine/Rules/')
    >>> scanner.scan('可疑文件.exe')
    '''
    
    def __init__(self):
        self.rules = None

    def load_rules(self, rules_path: str):
        '''加载YARA规则集'''
        self.rules = yara.compile(rules_path + 'PYAS_Rules_B1.ips')

    def scan(self, target_path: str) -> dict:
        '''执行快速特征扫描'''
        if not self.rules:
            self.load_rules('Engine/Rules/')
        
        matches = self.rules.match(target_path)
        return {
            'threat_name': matches[0].rule if matches else None,
            'matches': [m.rule for m in matches]
        }

class SecurityEngine:
    '''安全引擎聚合模块'''
    
    def __init__(self):
        self.chainsaw = ChainsawScanner()

    def full_scan(self, path: str) -> dict:
        '''执行全引擎扫描'''
        return {
            'chainsaw': self.chainsaw.scan(path)
        }