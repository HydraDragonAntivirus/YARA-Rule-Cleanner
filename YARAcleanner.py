import os
import yara
import re

# Directory containing YARA rules
yara_directory = 'YARA'
def comment_out_errors(file_path, error_message):
    with open(file_path, 'rb') as f:
        lines = f.read().decode('utf-8', 'ignore').splitlines()
    modified_lines = []

    # Extract the line number from the error message using regular expression
    error_match = re.search(r'\((\d+)\)', error_message)
    error_line = int(error_match.group(1) if error_match else -1)

    for line_number, line in enumerate(lines, start=1):
        if line_number == error_line:
            if line.strip().startswith('//'):
                # If the line causing an error already starts with '//',
                # add '//' to the line above it instead
                modified_lines[-1] = f'// {modified_lines[-1].strip()}'
                print(f'Processed Line {line_number - 1}: {modified_lines[-1]}')
            else:
                modified_lines.append(f'// {line.strip()}')
                print(f'Processed Line {line_number}: {line.strip()}')
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
