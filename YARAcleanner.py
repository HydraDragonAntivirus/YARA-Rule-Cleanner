import os
import yara
import re
from concurrent.futures import ThreadPoolExecutor

# Directory containing YARA rules
yara_directory = 'YARA'

def compile_yara_rules(file_path):
    try:
        return yara.compile(filepath=file_path)
    except yara.SyntaxError as e:
        return None, str(e)

def comment_out_errors(file_path, error_message):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    modified_lines = []
    error_line = int(re.search(r'\((\d+)\)', error_message).group(1))

    for line_number, line in enumerate(lines, start=1):
        if line_number == error_line:
            modified_lines.append(f'// {line.strip()}')
        else:
            modified_lines.append(line)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(modified_lines)

def process_yara_file(file_path):
    rules, error_message = compile_yara_rules(file_path)
    if rules is None:
        comment_out_errors(file_path, error_message)
        print(f'Processed: {file_path} - Error message: {error_message}')
        return True
    return False

if __name__ == "__main__":
    while True:
        errors_found = False

        with ThreadPoolExecutor() as executor:
            for root, _, files in os.walk(yara_directory):
                for file in files:
                    if file.endswith('.yara'):
                        file_path = os.path.join(root, file)
                        if process_yara_file(file_path):
                            errors_found = True

        if not errors_found:
            break

    print('YARA rules processed successfully.')
