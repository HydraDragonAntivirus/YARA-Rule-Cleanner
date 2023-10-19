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
    current_rule = []

    for line in lines:
        match = re.match(r'(}private\s)?(}rule|rule|private rule)\s+\w+\s*{', line)
        if match:
            inside_rule = not match.group(1)
            is_error_rule = False
            current_rule = []  # Reset current_rule for each rule
        if inside_rule:
            current_rule.append(line)
            if 'syntax error' in line or 'undefined identifier' in line:
                is_error_rule = True
            if is_error_rule:
                current_rule[-1] = f'// {current_rule[-1]}'  # Comment out the line with '//'
        else:
            if is_error_rule:
                modified_lines.extend(['// ' + l for l in current_rule])  # Comment out the entire rule with '//'
            modified_lines.append(line)
            current_rule = []  # Reset current_rule for each non-rule line

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(modified_lines)

    return error_lines

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
        f.writelines(modified_lines)

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

                        # Check if it's an "undefined identifier" error
                        if "undefined identifier" in error_message:
                            # Try to extract the missing identifier
                            match = re.search(r'undefined identifier "(\w+)"', error_message)
                            if match:
                                missing_identifier = match.group(1)
                                add_import(file_path, missing_identifier)
                                print(f'Added import statement for "{missing_identifier}"')
                                # Retry compilation
                                try:
                                    yara.compile(filepath=file_path)
                                except Exception as e:
                                    error_message = str(e)
                                    if "undefined identifier" in error_message:
                                        error_lines = comment_out_error_rule(file_path, error_lines)
                                        errors_found = True
                            continue  # Do not comment out the entire rule for undefined identifiers

                        is_syntax_error = "syntax error" in error_message
                        if is_syntax_error:
                            add_import(file_path, "non_existing_identifier")
                            error_lines = comment_out_error_rule(file_path, error_lines)
                            errors_found = True

    print('YARA rules processed successfully.')

if __name__ == "__main__":
    process_yara_files(yara_directory)
