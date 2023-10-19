import os
import yara
import re

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_error_rule(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    modified_lines = []
    inside_rule = False
    is_error_rule = False
    error_lines = []  # Store lines causing syntax errors

    for line in lines:
        match = re.match(r'(}private\s)?(}rule|rule|private rule)\s+\w+\s*{', line)
        if match:
            inside_rule = not match.group(1)
            is_error_rule = False
            error_lines = []  # Reset error lines for each rule
        if inside_rule:
            if 'syntax error' in line:
                is_error_rule = True
                error_lines.append(line)
            elif is_error_rule:
                error_lines.append(line)
            else:
                modified_lines.append(line)
        else:
            modified_lines.append(line)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(modified_lines)

    # Add comments to the error lines
    if error_lines:
        with open(file_path, 'a', encoding='utf-8') as f:
            f.write("\n// Syntax error: The following lines have syntax errors\n")
            f.writelines(error_lines)

def add_import(file_path, missing_identifier):
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    modified_lines = []
    import_added = False

    for line in lines:
        modified_lines.append(line)
        if line.strip() == f'import "{missing_identifier}"':
            import_added = True

    if not import_added:
        modified_lines.insert(0, f'import "{missing_identifier}"\n')

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(modified_lines

# Process all ".yara" files in the specified directory
while True:
    errors_found = False

    for root, _, files in os.walk(yara_directory):
        for file in files:
            if file.endswith('.yara'):
                file_path = os.path.join(root, file)
                rule_name = None  # Track the current rule name

                # Use YARA Python library to validate the rule file
                try:
                    rules = yara.compile(filepath=file_path)
                except Exception as e:
                    error_message = str(e)
                    print(f'Processed: {file_path} - Error message: {error_message}')

                    # Check if it's an "undefined identifier" error
                    if "undefined identifier" in error_message:
                        # Try to extract the missing identifier
                        match = re.search(r'undefined identifier "(\w+)"', error_message)
                        if match:
                            missing_identifier = match.group(1)
                            add_import(file_path, missing_identifier)
                            print(f'Added import statement for "{missing_identifier}"')
                        continue  # Do not comment out the entire rule for undefined identifiers

                    is_syntax_error = "syntax error" in error_message
                    if is_syntax_error:
                        comment_out_error_rule(file_path)
                        errors_found = True

    if not errors_found:
        break

print('YARA rules processed successfully.')
