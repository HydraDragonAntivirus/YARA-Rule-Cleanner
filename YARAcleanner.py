import os
import yara
import re
import codecs
import multiprocessing

# Directory containing YARA rules
yara_directory = 'YARA'

def comment_out_errors(file_path, error_message):
    with codecs.open(file_path, 'r', encoding='ISO8859-1') as f:
        lines = f.readlines()

    modified_lines = []

    # Extract the line number from the error message using regular expression
    error_match = re.search(r'\((\d+)\)', error_message)
    error_line = int(error_match.group(1) if error_match else -1)

    for line_number, line in enumerate(lines, start=1):
        if line_number == error_line:
            modified_lines.append(f'// {line.strip()}')
            print(f'Processed Line {line_number}: {line.strip()}')
        else:
            modified_lines.append(line)

    with codecs.open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(modified_lines)

def scan_and_process_yara_file(file_path):
    try:
        rules = yara.compile(filepath=file_path)
    except yara.SyntaxError as e:
        error_message = str(e)
        comment_out_errors(file_path, error_message)
        print(f'Processed: {file_path} - Error message: {error_message}')
        return True  # Return True if there was an error
    return False

if __name__ == '__main':
    yara_files = []

    for root, _, files in os.walk(yara_directory):
        for file in files:
            if file.endswith('.yar'):
                file_path = os.path.join(root, file)
                yara_files.append(file_path)

    while True:
        num_cpus = multiprocessing.cpu_count()
        pool = multiprocessing.Pool(processes=num_cpus)
        errors_found = any(pool.map(scan_and_process_yara_file, yara_files))
        pool.close()
        pool.join()

        if not errors_found:
            break

    print('YARA rules processed successfully.')
