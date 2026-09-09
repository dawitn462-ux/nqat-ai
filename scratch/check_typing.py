import ast
import glob

typing_names = {'Optional', 'List', 'Dict', 'Tuple', 'Any', 'Union', 'Callable'}
found_errors = 0
for path in glob.glob('backend/**/*.py', recursive=True) + glob.glob('scanner/**/*.py', recursive=True):
    with open(path, 'r', encoding='utf-8') as f:
        tree = ast.parse(f.read(), filename=path)
    defined = set()
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                defined.add(n.asname or n.name)
        elif isinstance(node, ast.ImportFrom):
            for n in node.names:
                defined.add(n.asname or n.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id in typing_names:
                used.add((node.id, node.lineno))
    for name, lineno in used:
        if name not in defined:
            print(f'{path}:{lineno}: Undefined typing name "{name}"')
            found_errors += 1

if found_errors == 0:
    print("ALL TYPING NAMES ARE PROPERLY IMPORTED!")
