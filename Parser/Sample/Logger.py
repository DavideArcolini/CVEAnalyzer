from Sample.Terminal import Terminal
from alive_progress import alive_bar

class Logger:
    '''
    Class containing the functions used to log the result to a markdown file.
    
    Thee format of the output file is the following:
    
        IDENTIFIER | DESCRIPTIONS | AFFECTED PRODUCT NAMES | AFFECTED PRODUCT VERSIONS
           cve_id0 | descriptions |         names          |        versions
                   |    d0        |           n0           |            v0
                   |    d1        |           n1           |            v1
           cve_id1 | descriptions |         names          |        versions
                   |    d0        |           n0           |            v0
                   |    d1        |           n1           |            v1    
        '''
    
    def __init__(self, PATH_OUTPUT: str) -> None:
        '''
        It receives in input the name of the output file and prompts the user in case the 
        file already exist. The file is always overwritten.
        '''
        self.terminal = Terminal()
        self.file = open(f'Results/{PATH_OUTPUT}', "w") # overwrite file
        self.terminal.log(f'Output file: {PATH_OUTPUT}')
        pass
    
    def __del__(self): 
        self.file.close()
    
    def log_CVE_info(self, result):
        
        # logging results
        self.terminal.log('Logging result...')
        
        # building output file
        TABLE_CVE = "| **IDENTIFIER** | **DESCRIPTIONS** | **AFFECTED PRODUCT NAMES** | **AFFECTED PRODUCT VERSIONS** |\n"
        separator = "|:-:|:-:|:-:|:-:|\n"
        
        self.file.write(TABLE_CVE)
        self.file.write(separator)

        print()
        with alive_bar(len(result)) as bar:
            for id, cve in result.items():
                
                self.file.write(f'| **{id}** | **Description** | **Affected product name** | **Affected product version** |\n')
                for counter in range(len(cve['description'])):
                    self.file.write('| | ' + cve['description'][counter] + '|' + cve['affected product name'][counter] + '|' + cve['affected product version'][counter] + '|\n')
                bar()
        
        # logging completed
        print()
        self.terminal.log("Logging results completed. Check the results in the Results folder.")