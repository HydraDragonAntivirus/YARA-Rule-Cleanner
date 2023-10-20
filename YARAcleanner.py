import os
import yara
import re

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_errors(file_path, error_message):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    modified_lines = []
    inside_rule = False  # Tracks whether we're inside a rule block

    for line in lines:
        if line.strip().startswith('}'):
            inside_rule = False
            modified_lines.append(f'// {line.strip()}')
        elif inside_rule:
            modified_lines.append(f'// {line.strip()}')
        elif line.strip().startswith('rule'):
            inside_rule = True
        else:
            modified_lines.append(line)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(modified_lines)

# Process all ".yar" files in the specified directory
while True:
    errors_found = False

    for root, _, files in os.walk(yara_directory):
        for file in files:
            if file.endswith('.yar'):
                file_path = os.path.join(root, file)

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
