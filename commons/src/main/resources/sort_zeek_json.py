import json
import sys

def sort_zeek_json_log(input_file, output_file):
    # Open the input file with UTF-8 encoding
    with open(input_file, 'r', encoding='utf-8') as f:
        # Read each line, strip whitespace, and parse as JSON
        logs = [json.loads(line) for line in f if line.strip()]

    # Sort logs by the 'ts' (timestamp) field, assuming it’s numeric
    sorted_logs = sorted(logs, key=lambda x: float(x['ts']))

    # Write sorted logs to the output file, also using UTF-8
    with open(output_file, 'w', encoding='utf-8') as f:
        for log in sorted_logs:
            f.write(json.dumps(log) + '\n')

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python sort_zeek_json.py <input_file> <output_file>")
        sys.exit(1)
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    sort_zeek_json_log(input_file, output_file)