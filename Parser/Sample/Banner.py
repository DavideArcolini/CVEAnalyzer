from colorama import Fore

class Banner: 
    '''
    Visual banner for the script
    '''
    
    def __init__(self) -> None:
        self.header = '''
        ===========================================================================================
                              _____   _____     _             _                 
                             / __\ \ / / __|   /_\  _ _  __ _| |_  _ ______ _ _ 
                            | (__ \ V /| _|   / _ \| ' \/ _` | | || |_ / -_) '_|
                             \___| \_/ |___| /_/ \_\_||_\__,_|_|\_, /__\___|_|  
                                                                |__/            
        ===========================================================================================
        
        The CVE Analyzer streamlines the process of collecting and analyzing vulnerability information 
        from the Github repository: CVEProject/cvelist. This script provides flexible configuration 
        options, allowing you to search for specific keywords within the list. Results of the given 
        analysis can be easily logged in a clear and organized Markdown file for future references.
         
        '''
        
        
    def print_banner(self) -> None:
        print(self.header)
        
    def print_start_collection(self) -> None:
        print(Fore.GREEN + '[+]' + Fore.RESET + ' Collecting CVEs from the original repository.')
    
    def print_start_analysis(self) -> None:
        print(Fore.GREEN + '[+]' + Fore.RESET + ' Analyzing data retrieved.')
        print(Fore.GREEN + '[+]' + Fore.RESET + ' This could take a while...')
        
    def print_number_of_CVE(self, count: int) -> None:
        print(Fore.GREEN + '[+]' + Fore.RESET + ' Collected ' + str(count) + ' CVEs')
        
    def print_number_of_results(self, count: int) -> None:
        print(Fore.GREEN + '[!]' + Fore.RESET + ' Found ' + Fore.CYAN + str(count) + Fore.RESET + ' CVEs compliant the configuration provided.\n')