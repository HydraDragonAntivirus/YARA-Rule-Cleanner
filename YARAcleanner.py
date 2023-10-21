import os
import yara
import re

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_errors(file_path, error_messages):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    modified_lines = []

    for error_message in error_messages:
        error_line = 0  # Initialize error line number

        # Extract the line number from the error message using regular expression
        error_match = re.search(r'\((\d+)\)', error_message)
        if error_match:
            error_line = int(error_match.group(1))

        for line_number, line in enumerate(lines, start=1):
            if line_number == error_line:
                modified_lines.append(f'// {line.strip()}')
                print(f'Processed Line {line_number}: {line.strip()}')
            else:
                modified_lines.append(line)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(modified_lines)

def process_yara_file(file_path):
    error_messages = []

    while True:
        try:
            rules = yara.compile(filepath=file_path)
            break  # No error, so exit the loop
        except yara.SyntaxError as e:
            error_messages.append(str(e))
            comment_out_errors(file_path, error_messages)
            print(f'Processed: {file_path} - Error messages: {error_messages}')
            error_messages = []

if __name__ == '__main__':
    # Process all ".yar" files in parallel
    yara_files = [os.path.join(root, file) for root, _, files in os.walk(yara_directory) for file in files if file.endswith('.yar')]
    for file_path in yara_files:
        process_yara_file(file_path)

    print('YARA rules processed successfully.')
