import os
import yara
import re

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_errors(file_path, error_message):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    modified_lines = []
    error_line = -1

    for line_number, line in enumerate(lines, start=1):
        if error_line == -1:
            if re.search(r'\((\d+)\)', error_message):
                error_match = re.search(r'\((\d+)\)', error_message)
                error_line = int(error_match.group(1))

        if error_line == -1:
            modified_lines.append(line)
        else:
            if line_number == error_line:
                modified_lines.append(f'// {line.strip()}')
                print(f'Processed Line {line_number}: {line.strip()}')
            elif line.strip() == "}":
                error_line = -1
                modified_lines.append(line)
            else:
                modified_lines.append(f'// {line.strip()}')

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(modified_lines)

# Process all ".yar" files in the specified directory
while True:
    errors_found = False

    for root, _, files in os.walk(yara_directory):
        for file in files:
            if file.endswith('.yar'):
                file_path = os.path.join(root, file)

                # Use YARA Python library to validate the rule file
                try:
                    rules = yara.compile(filepath=file_path)
                except yara.SyntaxError as e:
                    error_message = str(e)
                    comment_out_errors(file_path, error_message)
                    print(f'Processed: {file_path} - Error message: {error_message}')
                    errors_found = True

    if not errors_found:
        break

print('YARA rules processed successfully.')
