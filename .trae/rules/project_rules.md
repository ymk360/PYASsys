# PYASsys 项目规范

## 目录结构规范
1. 驱动文件存放于 `/Driver` 目录
2. 核心引擎代码存放于 `/Engine` 目录
3. 扩展工具存放于 `/Extens` 目录

## 编码规范
1. 遵循 PEP8 代码风格
2. 模块化开发，每个功能组件独立封装
3. 所有函数/类必须包含 docstring
4. 使用类型注解(Type hints)
5. 生成的UI风格要符合 PYASsys 的风格
6. 生成的UI要有很好的动画
7. 自动运行脚本
8. 自动编码写程序
9. 每次提问时检查文件版本

## 版本控制
1. 功能开发使用 feature 分支
2. 紧急修复使用 hotfix 分支
3. 提交信息格式：[类型] 简要描述 (示例：[Driver] 更新数字签名机制)
4. 在每次修改后都提交代码
5. 提交信息必须包含类型和简要描述
6. 提交信息必须包含相关的 Issue 编号

## 文档要求
1. 所有接口必须包含使用示例
2. 重要算法需要流程图说明
3. 驱动级代码需要安全规范说明

## 测试规范
1. 核心模块要求 90%+ 单元测试覆盖率
2. 驱动测试需在虚拟化环境进行
3. 界面测试使用自动化脚本

## 安全规范
1. 驱动程序必须经过微软WHQL认证
2. 内存操作必须进行边界检查
3. 敏感操作需要用户二次确认