import os
import yara
import re
import concurrent.futures

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_errors(file_path, error_message):
    with open(file_path, 'rb') as f:
        lines = f.read().decode('utf-8', 'ignore').splitlines()

    # Extract the line number from the error message using regular expression
    error_match = re.search(r'\((\d+)\)', error_message)
    error_line = int(error_match.group(1) if error_match else -1)

    modified_lines = []
    for line_number, line in enumerate(lines, start=1):
        if line_number == error_line:
            if line.strip().startswith('//'):
                modified_lines[-1] = f'// {modified_lines[-1].strip()}'
            else:
                modified_lines.append(f'// {line.strip()}')
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

def main():
    while True:
        errors_found = False

        with concurrent.futures.ThreadPoolExecutor() as executor:
            for root, _, files in os.walk(yara_directory):
                yara_files = [os.path.join(root, file) for file in files if file.endswith('.yar')]
                results = list(executor.map(process_yara_file, yara_files))
                if any(results):
                    errors_found = True

        if not errors_found:
            break

    print('YARA rules processed successfully.')

if __name__ == '__main__':
    main()
