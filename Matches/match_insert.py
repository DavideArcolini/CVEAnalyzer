import os
import sys

def main():
    LOG_FILE = './vulnerable_projects.md'
    
    message()


    if len(sys.argv) < 2:
        print("Wrong format")
        message()
        exit(1)

    with open(LOG_FILE, 'a') as file:
        if os.stat(LOG_FILE).st_size == 0:
            write_header(file)

        
        data = get_input()
        write_data(file, data)


def write_header(file):
    TITLE = "# Projects Vulnerable to the found CVEs\n\n"
    TABLE_COLUMNS = "| **CVE IDENTIFIER** | **PROJECT URL** | **CRITERIA** |\n"
    SEPARATOR = "|:-:|:-:|:-:|\n"

    file.write(TITLE)
    file.write(TABLE_COLUMNS)
    file.write(SEPARATOR)

def write_data(file, data):
    criteria_list = ""
    for criteria in data["criteria"]:
        criteria_list += "<li>" + criteria + "</br>"

    file.write('|' + data["cve_id"] + '|' + data["project_link"] + '|' + criteria_list + '|\n')


def get_input():
    data = {}
    data["cve_id"] = sys.argv[1]
    data["project_link"] = sys.argv[2]
    data["criteria"] = []


    for criteria in sys.argv[3:]:
        data["criteria"].append(criteria)

    return data

def message():
    print("Insert a new match with this format: CVE_ID PROJECT_LINK [CRITERIA...]")
    print("If a criteria contains spaces, enclose it in this way: \"long criteria\" ")


if __name__ == '__main__':
    main()