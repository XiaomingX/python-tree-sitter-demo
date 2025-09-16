from tree_sitter import Language, Parser
import tree_sitter_python as tspython

# 危险函数列表（示例）
DANGEROUS_FUNCTIONS = {'eval', 'exec', 'os.system', 'subprocess.Popen'}

def parse_code_and_detect_rce(code: str):
    PY_LANGUAGE = Language(tspython.language())
    parser = Parser(PY_LANGUAGE)
    tree = parser.parse(bytes(code, "utf8"))
    root_node = tree.root_node

    print(f"根节点类型: {root_node.type}")

    # 递归遍历语法树，查找危险函数调用
    def walk_tree(node):
        # 检查函数调用表达式
        if node.type == "call":
            function_node = node.child_by_field_name("function")
            if function_node is not None:
                # 获取函数调用名称，支持多级名称拼接如 os.system
                func_name = get_full_func_name(function_node)
                if func_name in DANGEROUS_FUNCTIONS:
                    print(f"警告: 发现危险函数调用 `{func_name}`，位置：{node.start_point}")
                    # 简易示例：打印函数调用的源码
                    print(f"代码片段: {code[node.start_byte:node.end_byte]}")
        # 递归检查子节点
        for child in node.children:
            walk_tree(child)

    # 辅助函数：获取完整函数名
    def get_full_func_name(node):
        # 单个标识符
        if node.type == "identifier":
            return node.text.decode('utf8')
        # 成员表达式，如 os.system，递归拼接
        elif node.type == "attribute":
            left = get_full_func_name(node.child_by_field_name("object"))
            right = node.child_by_field_name("attribute")
            if right:
                return f"{left}.{right.text.decode('utf8')}"
        return ""

    walk_tree(root_node)

if __name__ == "__main__":
    sample_code = """
import os

def vuln_func(user_input):
    eval(user_input)  # 危险
    os.system("ls -al")  # 潜在危险

def safe_func():
    print("安全的代码")
"""
    parse_code_and_detect_rce(sample_code)
