# IPScraper

## Usage

    from IPScraper import IPScraper

## Initialize client connection using selected APIs

    go = IPScraper()

## Setting API keys

    etintel_api_key: str = 'your emerging threats intelligence api key'
    greynoise_api_key: str = 'your greynoise community api key'
    onyphe_api_key: str = 'apikey your onyphe api key'
    shodan_api_key: str = 'your shodan api key'
    virustotal_api_key: str = 'your virustotal api key'

## Modules within findip can be commented out if you don't have an API key or don't wish to utilize them. Add # to beginning of these lines as needed:

    self.etintel(ip)
    self.greynoise(ip)
    self.onyphe(ip)              
    self.goShodan(ip)
    self.virustotal(ip)  


## Get details on a specific IP address

    go.findip('58.216.151.245')

## Sample Output

    58.216.151.245 found in ET Intel - Events
    58.216.151.245 found in ET Intel - Geolocation
    58.216.151.245 found in GreyNoise
    58.216.151.245 found in Onyphe - Threat List
    58.216.151.245 found in Shodan
    58.216.151.245 found in VirusTotal - Historical Whois
    Results written to 58.216.151.245_20220422_143656.csv

## Authors
[Jason Ford](http://www.jasonsford.com)

## License
[GPLv3](https://choosealicense.com/licenses/gpl-3.0/)
