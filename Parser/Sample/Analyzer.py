from os import listdir
from re import match
from json import load
from alive_progress import alive_bar
from Sample.CVE import CVE
from Sample.Terminal import Terminal


class Analyzer: 
    '''
    Contains the definition of the functions used to analyze the CVE repository
    '''
    
    def __init__(self, path_config: str, path_target: str) -> None:
        self.target = path_target
        self.terminal = Terminal()
        self.terminal.print_banner()
        try:
            with open(path_config) as file:
                self.filters = load(file)
        except FileNotFoundError as E:
            raise E
        
    def get_output_file(self) -> str:
        return self.filters['output']
    
    def check_filters(self, cve: CVE) -> bool:
        '''
        Custom checks based on the configuration file.
        '''
        
        if cve.check_status('PUBLIC') and \
            cve.check_descriptions(self.filters['descriptions']) and \
            cve.check_problems(self.filters['problems']):
                return True
        return False
    
    def get_data(self) -> list:
        '''
        Retrieve the list of json files containing the CVEs for a specific range of years.
        Non-related files are filtered out.
        '''
        
        # banner
        self.terminal.log('Collecting CVEs from the original repository.')
        
        # retrieving list of years
        years = []
        for year in listdir(self.target):
            if year.isdigit() and len(year) == 4 and self.filters['years']['start'] <= year <= self.filters['years']['end']:
                years.append(year)
        years.sort()
        
        # for every year, retrieve list of CVEs file
        data = []
        for year in years:
            ids = [id for id in listdir(f'{self.target}/{year}') if match(r"^\d+x*$", id)]
            for id in ids:
                data.extend([f'{self.target}/{year}/{id}/{file}' for file in listdir(f'{self.target}/{year}/{id}')])

        # banner
        self.terminal.log('Collected ' + str(len(data)) + ' CVEs')
        return data
    
    def parse_data(self, data: list) -> dict:
        '''
        Given a list of CVE json files, parse the files that corresponds to the given filters.
        Returns a dictionary containing the information to be pretty printed, having:
            - key: the CVE identifier
            - value: a dictionary containing the CVE information
        '''
        
        # banner
        self.terminal.log('Analyzing data retrieved.')
        self.terminal.log('This could take a while...')
        
        result = {}
        
        # reading every file collected
        print()
        with alive_bar(len(data)) as bar:
            for path in data:
                if path.endswith('json'):
                    try:
                        # creating CVE object
                        cve = CVE(path, self.filters['lang'])
                        if self.check_filters(cve):
                            
                            # building result object
                            result[cve.get_id()] = {
                                "description": cve.get_descriptions(),
                                "affected product name": cve.get_affected_product_names(),
                                "affected product version": cve.get_affected_product_versions(),
                                "references": cve.get_references()
                            }                           
                    except UnicodeDecodeError as UDE:
                        print(UDE)
                    except FileNotFoundError as FNF:
                        print(FNF)
                bar()
        
        # banner
        print()
        self.terminal.log(f'Found {len(result)} CVEs compliant the configuration provided.\n')
        return result