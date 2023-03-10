from logging import exception
from Sample.Analyzer import Analyzer
from Sample.Logger import Logger

def main(argv = None) -> None: 
    '''
    Entry point of the script
    '''
    PATH_CONFIG = './config.json'
    PATH_TARGET = '../CVE/cvelist-master'
    
    # initialization
    try: 
        analyzer = Analyzer(PATH_CONFIG, PATH_TARGET)
        logger = Logger(analyzer.get_output_file())
    except FileNotFoundError as E: 
        exception(E)
    
    # collecting and analyzing data
    data = analyzer.get_data()
    result = analyzer.parse_data(data)
    
    # logging CVEs info to markdown
    logger.log_CVE_info(result)
    
    
    return 
    

if __name__ == '__main__':
    main()