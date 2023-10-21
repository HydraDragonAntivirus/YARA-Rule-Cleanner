import os
import yara
import re

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_errors(file_path, error_messages):
    with open(file_path, 'r', encoding='utf-8') as f:
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

# Process all ".yar" files in the specified directory
for root, _, files in os.walk(yara_directory):
    for file in files:
        if file.endswith('.yar'):
            file_path = os.path.join(root, file)
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

print('YARA rules processed successfully.')
