import os
import yara
import re

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_error_rule(file_path, error_lines):
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    modified_lines = []
    inside_rule = False
    is_error_rule = False

    for line in lines:
        match = re.match(r'(}private\s)?(}rule|rule|private rule)\s+\w+\s*{', line)
        if match:
            inside_rule = not match.group(1)
            is_error_rule = False
        if inside_rule:
            if 'syntax error' in line or 'undefined identifier' in line:
                is_error_rule = True
            if is_error_rule:
                line = f'// {line}'  # Comment out the line with '//'
        modified_lines.append(line)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(modified_lines)

    return error_lines

# Process all ".yara" files in the specified directory
def process_yara_files(directory):
    errors_found = True
    error_lines = []  # Track error lines for import statements

    while errors_found:
        errors_found = False

        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.yara'):
                    file_path = os.path.join(root, file)

                    try:
                        rules = yara.compile(filepath=file_path)
                    except Exception as e:
                        error_message = str(e)
                        print(f'Processed: {file_path} - Error message: {error_message}')

                        is_syntax_error = "syntax error" in error_message
                        if is_syntax_error:
                            error_lines = comment_out_error_rule(file_path, error_lines)
                            errors_found = True

    print('YARA rules processed successfully.')

if __name__ == "__main__":
    process_yara_files(yara_directory)
