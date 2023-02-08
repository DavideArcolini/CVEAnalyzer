class Logger:
    '''
    Class containing the functions used to log the result to a markdown file
    '''
    
    def log_CVE_info(result):
        print("logging")
        default_columns = "| CVE_id | description | affected product name | affected product versions |\n"
        separator = "|----------|--------------------|----------|----------|\n"
        with open('CVE_log.md', 'w') as log:
            log.write(default_columns)
            log.write(separator)
            ref_table = []

            for id, cve in result.items():
                ref_list = ""
                
                for ref in cve["references"]:
                    ref_list += "- " + ref + "</br>" 

                ref_table.append("|" + str(id) + "|" + ref_list + "|\n")
                

                log.write("|" + str(id) + "|" + cve["description"] + "|" + cve["affected product name"] + "|" + cve["affected product version"] + "|\n")
            

            references_columns = "| CVE_id | References |\n"
            separator = "|----------|------------------|\n"

            log.write("\n\n\n")
            log.write(references_columns)
            log.write(separator)

            for ref in ref_table:
                log.write(ref)