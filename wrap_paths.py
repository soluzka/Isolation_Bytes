import os
import re

# Configuration
project_root = os.path.abspath(".")
ignore_dirs = {"__pycache__", ".git", "venv", "env", "dist", "build"}
file_extensions = (".py",)

# Regex to match file access
file_access_patterns = [
    re.compile(r'open\(["\'](.+?)["\']'),
    re.compile(r'open\((.+?),'),
]

wrap_template = "get_resource_path(os.path.join({}))"
import_line = "from utils.paths import get_resource_path\nimport os\n"

def is_valid_file(file_path):
    return file_path.endswith(file_extensions)

def should_ignore(path):
    return any(part in ignore_dirs for part in path.split(os.sep))

def has_import(content):
    return "get_resource_path" in content and "from utils.paths import get_resource_path" in content

def wrap_file_access(content):
    lines = content.splitlines()
    modified_lines = []
    modified = False

    for line in lines:
        modified_line = line
        for pattern in file_access_patterns:
            match = pattern.search(line)
            if match:
                path_expr = match.group(1)
                if "get_resource_path" not in path_expr:
                    joined_path = f'"{path_expr}"' if path_expr.startswith(("'", '"')) else path_expr
                    wrapped = wrap_template.format(joined_path)
                    modified_line = line.replace(path_expr, wrapped)
                    modified = True
                    break
        modified_lines.append(modified_line)

    # Inject import at the top if necessary
    if modified and not has_import(content):
        modified_lines.insert(0, import_line)
        modified = True

    return "\n".join(modified_lines), modified

# Process files
for root, _, files in os.walk(project_root):
    if should_ignore(root):
        continue

    for file in files:
        if not is_valid_file(file):
            continue

        path = os.path.join(root, file)
        with open(path, "r", encoding="utf-8") as f:
            original_content = f.read()

        wrapped_content, changed = wrap_file_access(original_content)

        if changed:
            with open(path, "w", encoding="utf-8") as f:
                f.write(wrapped_content)
            print(f"✔ Updated: {path}")
