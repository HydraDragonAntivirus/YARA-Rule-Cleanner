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
    for line_number, line in enumerate(lines, start=1):
        if line_number == error_line:
            modified_lines.append(f'// {line.strip()}')
            print(f'Processed Line {line_number}: {line.strip()}')
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
errors_found = False
with ProcessPoolExecutor() as executor:
    file_paths = [os.path.join(root, file) for root, _, files in os.walk(yara_directory) for file in files if file.endswith('.yara')]
    error_results = list(executor.map(process_file, file_paths))
    if any(error_results):
        errors_found = True

if errors_found:
    print('YARA rules processed with errors.')
else:
    print('YARA rules processed successfully.')
