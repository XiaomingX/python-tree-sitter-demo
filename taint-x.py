from tree_sitter import Language, Parser
import tree_sitter_python as tspython

# 危险函数列表（示例）
DANGEROUS_FUNCTIONS = {'eval', 'exec', 'os.system', 'subprocess.Popen'}

def parse_code_and_detect_rce_with_taint(code: str):
    PY_LANGUAGE = Language(tspython.language())
    parser = Parser(PY_LANGUAGE)
    tree = parser.parse(bytes(code, "utf8"))
    root_node = tree.root_node

    print(f"根节点类型: {root_node.type}")

    # 存储函数的污点参数名集合
    tainted_vars = set()

    # 保存函数参数列表（函数名 -> 参数名列表）
    func_params = {}

    # 递归遍历函数体，标记并传播污点
    def walk_tree(node, current_func=None):
        # 定义函数，记录参数
        if node.type == "function_definition":
            func_name_node = node.child_by_field_name("name")
            func_name = func_name_node.text.decode('utf8') if func_name_node else None
            param_node = node.child_by_field_name("parameters")
            params = []
            if param_node:
                # 参数列表格式是括号内的逗号分隔标识符
                for child in param_node.children:
                    if child.type == "identifier":
                        params.append(child.text.decode('utf8'))
            func_params[func_name] = params
            # 传入当前函数名，继续递归函数体
            body_node = node.child_by_field_name("body")
            if body_node:
                walk_tree(body_node, current_func=func_name)
            return

        # 标记函数的参数名为污点变量
        if current_func is not None and node.type == "parameters":
            # 这一步已在上面函数定义里做过，注释掉本段
            # for child in node.children:
            #     if child.type == "identifier":
            #         tainted_vars.add(child.text.decode('utf8'))
            pass

        # 赋值语句，处理污点传播
        if node.type == "assignment":
            # 左值
            left_node = node.child_by_field_name("left")
            # 右值
            right_node = node.child_by_field_name("right")
            if left_node and right_node:
                left_name = get_identifier_name(left_node)
                right_name = get_identifier_name(right_node)
                # 如果右侧是污点变量，左侧也变成污点
                if right_name in tainted_vars:
                    tainted_vars.add(left_name)

        # 找到危险函数调用，检查参数是否来自污点
        if node.type == "call":
            function_node = node.child_by_field_name("function")
            arguments_node = node.child_by_field_name("arguments")

            func_name = get_full_func_name(function_node)
            if func_name in DANGEROUS_FUNCTIONS and arguments_node:
                # 遍历所有参数节点，检查是否包含污点变量
                for arg in arguments_node.children:
                    arg_name = get_identifier_name(arg)
                    if arg_name and arg_name in tainted_vars:
                        print(f"警告: 发现危险函数调用 `{func_name}`，参数为用户输入污点变量，位置：{node.start_point}")
                        print(f"代码片段: {code[node.start_byte:node.end_byte]}")
                        break

        # 遍历子节点
        for child in node.children:
            walk_tree(child, current_func=current_func)

    # 辅助函数：递归获得标识符名字（支持标识符、属性访问）
    def get_identifier_name(node):
        if node.type == "identifier":
            return node.text.decode('utf8')
        # 支持对代码字符串字面量的排除
        if node.type == "string":
            return None
        # 处理成员访问或点表达式
        if node.type == "attribute":
            left = get_identifier_name(node.child_by_field_name("object"))
            right_node = node.child_by_field_name("attribute")
            right = right_node.text.decode('utf8') if right_node else ""
            return f"{left}.{right}"
        # 处理带括号的表达式，比如参数列表
        if node.type == "parenthesized_expression":
            for c in node.children:
                name = get_identifier_name(c)
                if name:
                    return name
        return None

    # 递归获得函数调用完整名字
    def get_full_func_name(node):
        if node.type == "identifier":
            return node.text.decode('utf8')
        elif node.type == "attribute":
            left = get_full_func_name(node.child_by_field_name("object"))
            right_node = node.child_by_field_name("attribute")
            right = right_node.text.decode('utf8') if right_node else ""
            return f"{left}.{right}"
        return ""

    # 先找所有函数，提取其参数作为污点变量（演示只支持顶层函数单层）
    def extract_taints():
        for child in root_node.children:
            if child.type == "function_definition":
                func_name_node = child.child_by_field_name("name")
                func_name = func_name_node.text.decode('utf8') if func_name_node else None
                if func_name:
                    params_node = child.child_by_field_name("parameters")
                    if params_node:
                        for param in params_node.children:
                            if param.type == "identifier":
                                tainted_vars.add(param.text.decode('utf8'))

    extract_taints()
    walk_tree(root_node)

if __name__ == "__main__":
    sample_code = """
import os

def vuln_func(user_input):
    data = user_input
    eval(data)  # 危险，data受污点污染

def safe_func():
    safe_data = "Hello"
    os.system(safe_data)  # 安全，因为参数不是污点
"""
    parse_code_and_detect_rce_with_taint(sample_code)
