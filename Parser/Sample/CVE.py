import json

class CVE: 
    '''
    CVE objects are loaded from .json files
    '''
    
    def __init__(self, path: str, lang: str) -> None:
        '''
        Opening and loading object information from .json file
        '''
        
        try: 
            with open(path) as file:
                data = json.load(file)  # opening file
                
            # adding information
            self.lang = lang
            self.cve = {}
            for key, value in data.items():
                self.cve[key] = value
        except FileNotFoundError as E: 
            raise E
    
    
    # -- METHODS ---
    
    def get_id(self) -> str: 
        return self.cve['CVE_data_meta']['ID']
    
    def get_descriptions(self) -> list:
        return [item['value'] for item in self.cve['description']['description_data'] if item["lang"] == self.lang]
    
    def get_affected_product_names(self) -> list:
        return [item['product']['product_data'][0]['product_name'] for item in self.cve['affects']['vendor']['vendor_data']]
    
    def get_affected_product_versions(self) -> list:
        return [item['product']['product_data'][0]['version']['version_data'][0]['version_value'] for item in self.cve['affects']['vendor']['vendor_data']]
    
    def get_references(self) -> list: 
        return [item['url'] for item in self.cve['references']['reference_data']]
    
    def check_status(self, status: str) -> bool:
        return status.upper() == self.cve['CVE_data_meta']['STATE'].upper()
    
    def check_descriptions(self, keywords: list) -> bool: 
        descriptions = next((item['value'].lower() for item in self.cve['description']['description_data'] if item["lang"] == self.lang), '')
        for keyword in keywords:
            if keyword.lower() in descriptions:
                return True
        return False
    
    def check_problems(self, keywords: list) -> bool:
        problemtype_data = self.cve['problemtype']['problemtype_data']
        values = [description["value"].lower() for item in problemtype_data for description in item["description"] if description["lang"] == self.lang]
        for keyword in keywords:
            for value in values:
                if keyword in value:
                    return True
            else:
                continue
        return False