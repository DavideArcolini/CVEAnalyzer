from colorama import Fore

class Terminal: 
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
        
    def log(self, message) -> None:
        print(Fore.GREEN + '[+] ' + Fore.RESET + message)
        return