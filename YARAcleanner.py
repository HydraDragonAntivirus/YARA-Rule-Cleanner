import os
import yara

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_entire_rule(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    modified_lines = []

    in_rule_block = False
    error_found = False  # Hata bulunduğunda yorum satırına eklemek için bayrak
    for line in lines:
        if line.strip().startswith("rule "):
            in_rule_block = True
            error_found = False

        if in_rule_block:
            if not error_found:
                modified_lines.append(line)
            else:
                modified_lines.append(f'// {line}')
        else:
            modified_lines.append(line)

        if line.strip() == "}":
            in_rule_block = False

        if line.strip().startswith('// error:'):
            error_found = True

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
                    comment_out_entire_rule(file_path)
                    print(f'Processed: {file_path} - Error message: {str(e)}')
                    errors_found = True

    if not errors_found:
        break

print('YARA rules processed successfully.')
