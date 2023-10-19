import os
import yara

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_errors(file_path, error_message):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    modified_lines = []
    inside_rule = False

    for line in lines:
        match = re.match(r'(}private\s)?(}rule|rule|private rule)\s+\w+\s*{', line)
        if match:
            inside_rule = not match.group(1)  # Set inside_rule based on the presence of "}private"
        if inside_rule:
            modified_lines.append(f'// {line}')
        else:
            modified_lines.append(line)

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
