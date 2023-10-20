import os
import yara
import re

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_errors(file_path, error_message):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    modified_lines = []

    # Extract the line number from the error message using regular expression
    error_match = re.search(r'\((\d+)\)', error_message)
    error_line = int(error_match.group(1) if error_match else -1)

    inside_rule = False

    for line_number, line in enumerate(lines, start=1):
        if 'rule ' in line:
            inside_rule = True
            modified_lines.append(line)  # Include the 'rule' line

        if inside_rule:
            modified_lines.append(f'// {line.strip()}')  # Comment out lines within the rule

        if inside_rule and '}' in line:
            inside_rule = False

        # Check if we're at the error line, and set a flag to stop commenting
        if line_number == error_line:
            inside_rule = False
            modified_lines[-1] = f'// {lines[error_line - 1].strip()}'  # Comment out the 'rule' line

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
                except yara.SyntaxError as e:
                    error_message = str(e)
                    comment_out_errors(file_path, error_message)
                    print(f'Processed: {file_path} - Error message: {error_message}')
                    errors_found = True

    if not errors_found:
        break

print('YARA rules processed successfully.')
