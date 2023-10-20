import os
import yara
import re

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_rule(file_path, rule_name):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    modified_lines = []
    in_rule_block = False

    for line in lines:
        if line.strip().startswith("rule " + rule_name):
            in_rule_block = True

        if in_rule_block:
            modified_lines.append(f'// {line.strip()}')
        else:
            if is_utf8(line):
                modified_lines.append(f'// {line.strip()}')
            else:
                modified_lines.append(line)

        if line.strip() == "}":
            in_rule_block = False

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(modified_lines)

def is_utf8(line):
    try:
        line.encode('utf-8')
        return True
    except UnicodeEncodeError:
        return False

def process_yara_rules():
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
                        error_match = re.search(r'\((\d+)\)', error_message)
                        error_line = int(error_match.group(1) if error_match else -1)
                        
                        if error_line != -1:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                lines = f.readlines()
                            rule_name_match = re.search(r'rule (\S+)', lines[error_line - 1])
                            if rule_name_match:
                                rule_name = rule_name_match.group(1)
                                comment_out_rule(file_path, rule_name)
                                print(f'Processed: {file_path} - Error message: {error_message}')
                                errors_found = True

        if not errors_found:
            break

    print('YARA rules processed successfully.')

if __name__ == '__main__':
    process_yara_rules()
