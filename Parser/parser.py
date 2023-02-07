

'''
"CVE_data_meta"
        "ID": "CVE-2023-22602",
        "STATE": "PUBLIC"                                       <-- Filter on this

"description"
    "description_data" 
        {
            "value"                                             <-- Description of CVE
        }                                        

"problemtype"
    "problemtype_data" (array)
        {
            "description"
                {
                    "value"                                     <-- Type of vulnerability (filter for injections)
                }  
        }                                       

"affects"
    "vendor"
        "vendor_data" (array)
            "vendor_name"                                       <-- Keep this info
            "product" 
                "product_data" (array)
                    {
                        "product_name"
                        "version"                               <-- Keep this info
                            "version_data" (array)
                                {
                                    "version_value"         
                                    "version_affected" 
                                }
                    }

"references"
    "reference_data" (array)
        "url"
        "name"



| CVE_id | description | affected product name | affected product versions | references (url + name)
 
'''

import sys
import os
import json
from re import match
from colorama import Fore, Back, Style
from logging import exception
from alive_progress import alive_bar

def is_any_included(strings_list, target_string):
    for s in strings_list:
        if s.lower() in target_string.lower():
            return True
    return False

def check_filters(cve: dict, filters: dict) -> bool:
    if cve['CVE_data_meta']['STATE'].upper() == filters['state']:
        if is_any_included(filters['descriptions'], cve['description']['description_data'][0]['value']):
            if is_any_included(filters['problems'], cve['problemtype']['problemtype_data'][0]['description'][0]['value']):
                return True
    return False
            

def get_data(CVE_DIR: str, filters: dict) -> list:
    '''
    Retrieve the list of json files containing the CVEs for a specific range of years.
    Non-related files are filtered out.
    '''
    
    # retrieving list of years
    years = []
    for year in os.listdir(CVE_DIR):
        if year.isdigit() and len(year) == 4 and filters['start'] <= year <= filters['end']:
            years.append(year)
    years.sort()
    
    # for every year, retrieve list of CVEs file
    data = []
    for year in years:
        ids = [id for id in os.listdir(f'{CVE_DIR}/{year}') if match(r"^\d+x*$", id)]
        for id in ids:
            data.extend([f'{CVE_DIR}/{year}/{id}/{file}' for file in os.listdir(f'{CVE_DIR}/{year}/{id}')])

    return data


def parse_data(data: list, filters: dict) -> dict:
    '''
    Given a list of CVE json files, parse the files that corresponds to the given filters.
    Returns a dictionary containing the information to be pretty printed, having:
        - key: the CVE identifier
        - value: a dictionary containing the CVE information
    '''
    
    result = {}
    
    # reading every file collected
    with alive_bar(len(data)) as bar:
        for path in data:
            if path.endswith('json'):
                try:
                    with open(path) as file:
                        cve = json.load(file)
                        if check_filters(cve, filters):
                            
                            # building cve object to be printed
                            ref = []
                            for reference_data in cve['references']['reference_data']:
                                ref.append(reference_data['url'])
                            
                            details = {
                                "description": cve['description']['description_data'][0]['value'],
                                "affected product name": cve['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['product_name'],
                                "affected product version": cve['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['version']['version_data'][0]['version_value'],
                                "references": ref
                            }
                            
                            result[cve['CVE_data_meta']['ID']] = details
                except UnicodeDecodeError as UDE:
                    print(UDE)
                except FileNotFoundError as FNF:
                    print(FNF)
            bar()
    
    return result
    
    


def main(argv = None) -> None: 
    '''
    Entry point of the script
    '''
    
    # loading configuration file
    try:
        with open('./config.json', 'r') as config:
            filters = json.load(config)
    except FileNotFoundError as E:
        exception(Fore.RED + ' ' + E.strerror + Fore.RESET)
        return
        
        
    # retrieving list of json files
    CVE_DIR = "../CVE/cvelist-master"
    data = get_data(CVE_DIR, filters['years'])
    
    # parse data into results 
    print(Fore.GREEN + '[+]' + Fore.RESET + ' Collecting CVEs')
    print(Fore.GREEN + '[+]' + Fore.RESET + ' Take a break and drink a coffee...')
    result = parse_data(data, filters)
    print(Fore.GREEN + '[!]' + Fore.RESET + ' I have found ' + Fore.CYAN + str(len(result)) + Fore.RESET + ' CVEs.')
    
    return 
    

if __name__ == '__main__':
    main()
    sys.exit()