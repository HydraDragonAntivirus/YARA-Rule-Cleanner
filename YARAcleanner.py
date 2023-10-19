import os
import yara
import re

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_private_or_rule(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    modified_lines = []

    inside_rule = False

    for line in lines:
        if (
            line.strip().startswith("private rule")
            or line.strip().startswith("rule")
            or line.strip().startswith("}private rule")
            or line.strip().startswith("}rule")
        ):
            inside_rule = True
        if inside_rule:
            modified_lines.append(f'// {line.strip()}')
        else:
            modified_lines.append(line)

        if inside_rule and line.strip() == "}":
            inside_rule = False

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
                    comment_out_private_or_rule(file_path)
                    print(f'Processed: {file_path} - Rule commented out due to error')
                    errors_found = True

    if not errors_found:
        break

print('YARA rules processed successfully.')
