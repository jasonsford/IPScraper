README.md

#Usage
    from IPScraper import IPScraper

#Initialize client connection using selected APIs
    go = IPScraper()

#Modules within findip can be commented out if you don't have an API key or don't wish to utilize them. Add # to beginning of these lines as needed:

    self.etintel(ip)
    self.greynoise(ip)
    self.onyphe(ip)              
    self.goShodan(ip)
    self.virustotal(ip)  


#Get details on a specific IP address
go.findip('58.216.151.245')

#Sample Output
    58.216.151.245 found in ET Intel - Events
    58.216.151.245 found in ET Intel - Geolocation
    58.216.151.245 found in GreyNoise
    58.216.151.245 found in Onyphe - Threat List
    58.216.151.245 found in Shodan
    58.216.151.245 found in VirusTotal - Historical Whois
    Results written to 58.216.151.245_20220422_143656.csv