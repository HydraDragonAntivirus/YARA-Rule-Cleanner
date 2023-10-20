import os
import yara

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_lines_with_error(file_path, error_message):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    modified_lines = []
    in_error_block = False

    for line in lines:
        if error_message in line:
            in_error_block = True

        if in_error_block:
            modified_lines.append(f'// {line}')
        else:
            modified_lines.append(line)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(modified_lines)

# Process all ".yar" files in the specified directory
for root, _, files in os.walk(yara_directory):
    for file in files:
        if file.endswith('.yar'):
            file_path = os.path.join(root, file)

            # Use YARA Python library to validate the rule file
            try:
                rules = yara.compile(filepath=file_path)
            except yara.SyntaxError as e:
                error_message = str(e)
                comment_out_lines_with_error(file_path, error_message)
                print(f'Processed: {file_path} - Error message: {error_message}')

print('YARA rules processed successfully.')