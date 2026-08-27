import os
import re
from pathlib import Path

repo_root = Path(r'c:\Users\gwkim\Desktop\trust-triage')

for p in repo_root.rglob('*'):
    if p.is_file() and p.suffix in ['.py', '.md'] and '.venv' not in p.parts and '.git' not in p.parts:
        try:
            with open(p, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Replace filenames like download.py -> download.py
            new_content = re.sub(r'\b\d{2}_([a-zA-Z_]+)\.py', r'\1.py', content)
            
            # Replace logging/prints like "01_download" -> "download"
            # setup_logging("download", ...)
            new_content = re.sub(r'setup_logging\("\d{2}_([a-zA-Z_]+)"', r'setup_logging("\1"', new_content)
            
            # Replace specific print strings
            new_content = re.sub(r'\[\d{2}_([a-zA-Z_]+)\]', r'[\1]', new_content)
            
            # Replace 'python download.py' (already covered by the first regex, but just in case)
            
            if content != new_content:
                with open(p, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f"Updated {p}")
        except Exception as e:
            pass
