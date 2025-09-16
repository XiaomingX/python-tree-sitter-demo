# Tree-sitter 学习笔记与示例代码

这个仓库包含我学习和使用Tree-sitter技术的笔记和示例代码。Tree-sitter是一个解析器生成工具和库，能够为源代码构建高效且增量的抽象语法树(AST)，非常适合代码分析、语法高亮、自动补全等场景。

## 示例代码说明

仓库中包含两个主要的Python示例文件，展示了如何使用Tree-sitter进行代码分析：

### 1. main.py
基础的代码分析示例，展示了如何：
- 初始化Tree-sitter解析器
- 解析Python代码并生成语法树
- 遍历语法树查找危险函数调用（如`eval`、`exec`、`os.system`等）
- 定位危险函数在代码中的位置并提取相关代码片段

### 2. taint-x.py
进阶示例，在基础检测之上增加了污点分析功能：
- 识别函数参数作为污点源头
- 追踪污点变量在代码中的传播路径
- 检测危险函数是否使用了受污染的变量作为参数
- 更精准地识别潜在的远程代码执行(RCE)漏洞

## 运行方法

1. 安装必要的依赖：
```bash
pip install tree-sitter tree-sitter-python
```

2. 运行基础分析示例：
```bash
python main.py
```

3. 运行污点分析示例：
```bash
python taint-x.py
```

## Tree-sitter 学习资源

- [Tree-sitter 官方文档](https://tree-sitter.github.io/tree-sitter/)
- [Tree-sitter Python绑定](https://github.com/tree-sitter/py-tree-sitter)
- [Tree-sitter 语法仓库](https://github.com/tree-sitter)

## 许可证

本仓库中的代码以MIT许可证开源，详情请见LICENSE文件。

通过这些示例，你可以了解如何利用Tree-sitter强大的语法解析能力，构建自己的代码分析工具、静态分析器或IDE插件等应用。