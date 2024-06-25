import sys
from json_parser import read_json, write_json
from project import traverse_ast


# python ./php-analyser.py slice.json patterns.json
def main():
    if len(sys.argv) != 3:
        print("Not enough or too many arguments!")
        sys.exit(1)


    # READ ARGS
    ast = read_json(sys.argv[1])
    patterns = read_json(sys.argv[2])
    exercise = sys.argv[1].split("/")[-1].split('.json')[0]

    vuln = []

    for pattern in patterns:
        sources = pattern["sources"]
        sanitizers = pattern["sanitizers"]
        sinks = pattern["sinks"]
        vulnerability = pattern["vulnerability"]
        implicit = pattern['implicit']

        vuln.extend(traverse_ast(ast, sources, sanitizers, sinks, implicit, vulnerability))

        write_json(vuln, exercise)

    sys.exit(0)

if __name__ == '__main__':
    main()
