import json
import sys
import os


def read_json(file):
    try:
        with open(file, "r") as json_file:
            data = json.load(json_file)
            return data

    except FileNotFoundError:
        print(f"The {file} file doesn't exist!")
        sys.exit(1)

    except json.JSONDecodeError:
        print(f"The {file} file is not in JSON format!")
        sys.exit(1)

def write_json(object, exercise):
    output = json.dumps(object, indent=4)
    file = "output/"+exercise + ".output.json"
    os.makedirs(os.path.dirname(file), exist_ok=True)
    # Writing to sample.json
    with open("output/"+exercise + ".output.json", "w") as outfile:
        outfile.write(output)
    return
