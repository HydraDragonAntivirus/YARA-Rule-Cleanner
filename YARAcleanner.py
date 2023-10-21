import os
import yara
import re
from concurrent.futures import ThreadPoolExecutor

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_errors(file_path, error_message):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    modified_lines = []

    # Extract the line number from the error message using regular expression
    error_match = re.search(r'\((\d+)\)', error_message)
    error_line = int(error_match.group(1) if error_match else -1)

    flag_above = False

    for line_number, line in enumerate(lines, start=1):
        if line_number == error_line:
            # Check if the line already has '//'
            if '//' in line:
                flag_above = True
            modified_lines.append(f'// {line.strip()}')
            print(f'Processed Line {line_number}: {line.strip()}')
        elif flag_above:
            modified_lines.append(f'// {line.strip()}')
            print(f'Processed Line {line_number}: {line.strip()}')
            flag_above = False
        else:
            modified_lines.append(line)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(modified_lines)

def process_yara_file(file_path):
    try:
        rules = yara.compile(filepath=file_path)
    except yara.SyntaxError as e:
        error_message = str(e)
        comment_out_errors(file_path, error_message)
        print(f'Processed: {file_path} - Error message: {error_message}')
        return True
    return False

if __name__ == '__main__':
    with ThreadPoolExecutor() as executor:
        while True:
            errors_found = False

            for root, _, files in os.walk(yara_directory):
                yara_files = [os.path.join(root, file) for file in files if file.endswith('.yaa')]
                results = list(executor.map(process_yara_file, yara_files))
                if any(results):
                    errors_found = True

            if not errors_found:
                break

    print('YARA rules processed successfully.')
