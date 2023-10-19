import os
import yara
import re

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_rule(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    modified_lines = []

    for line in lines:
        modified_lines.append(f'// {line}')

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(modified_lines)

# Process all ".yara" files in the specified directory
while True:
    errors_found = False

    for root, _, files in os.walk(yara_directory):
        for file in files:
            if file.endswith('.yara'):
                file_path = os.path.join(root, file)

                # Use YARA Python library to validate the rule file
                try:
                    rules = yara.compile(filepath=file_path)
                except Exception as e:
                    error_message = str(e)
                    print(f'Processed: {file_path} - Error message: {error_message}')
                    comment_out_rule(file_path)  # Comment out the entire rule
                    errors_found = True

    if not errors_found:
        break

print('YARA rules processed successfully.')
