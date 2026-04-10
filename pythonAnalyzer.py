import ast
import sys
import json

code = sys.stdin.read()
issues = []

try:
    tree = ast.parse(code)

    for node in ast.walk(tree):

        # Detect eval
        if isinstance(node, ast.Call):
            if hasattr(node.func, 'id') and node.func.id == 'eval':
                issues.append({
                    "type": "error",
                    "message": "Avoid using eval(). It is unsafe.",
                    "line": node.lineno
                })

        # Detect print usage
        if isinstance(node, ast.Call):
            if hasattr(node.func, 'id') and node.func.id == 'print':
                issues.append({
                    "type": "warning",
                    "message": "Avoid leaving print() statements in production code.",
                    "line": node.lineno
                })

except SyntaxError as e:
    issues.append({
        "type": "error",
        "message": "Syntax Error detected.",
        "line": e.lineno
    })

print(json.dumps(issues))
