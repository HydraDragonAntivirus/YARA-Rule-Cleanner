import os
import yara
import re
from concurrent.futures import ProcessPoolExecutor

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_errors(file_path, error_message):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    error_line = int(re.search(r'\((\d+)\)', error_message).group(1))

    modified_lines = []
    comment_added = False
    for line_number, line in enumerate(lines, start=1):
        if line_number == error_line - 1:
            if not line.strip().startswith('//'):
                modified_lines.append(f'// {line.strip()}')
                comment_added = True
            else:
                modified_lines.append(line)
        elif line_number == error_line:
            if not line.strip().startswith('//'):
                modified_lines.append(f'// {line.strip()}')
            else:
                modified_lines.append(line)
        else:
            modified_lines.append(line)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(modified_lines)

def process_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except UnicodeDecodeError:
        print(f'UnicodeDecodeError for file: {file_path}. Skipping this file.')
        return False

    try:
        rules = yara.compile(filepath=file_path)
    except yara.SyntaxError as e:
        error_message = str(e)
        comment_out_errors(file_path, error_message)
        print(f'Processed: {file_path} - Error message: {error_message}')
        return True
    return False

# Process all ".yara" files in the specified directory using parallel processing
while True:
    errors_found = False
    with ProcessPoolExecutor() as executor:
        file_paths = [os.path.join(root, file) for root, _, files in os.walk(yara_directory) for file in files if file.endswith('.yara')]
        error_results = list(executor.map(process_file, file_paths))
        if any(error_results):
            errors_found = True

    if not errors_found:
        break

print('YARA rules processed successfully.')
