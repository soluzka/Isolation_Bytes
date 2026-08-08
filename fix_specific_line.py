"""
Quick utility to fix the specific indentation issue in app.py line 2920
"""

def fix_specific_line():
    file_path = 'app.py'
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    
    # Look for the specific indentation issue at around line 2920
    for i, line in enumerate(lines):
        if 'folder_watcher.directories = directories' in line and line.strip() != 'folder_watcher.directories = directories':
            # Fix the indentation for this line
            lines[i] = 'folder_watcher.directories = directories\n'
            print(f"Fixed line {i+1}: {line.strip()} -> folder_watcher.directories = directories")
    
    # Write the fixed content back to the file
    with open(file_path, 'w', encoding='utf-8') as file:
        file.writelines(lines)
    
    print("Fixed the specific indentation issue.")

if __name__ == "__main__":
    fix_specific_line()
