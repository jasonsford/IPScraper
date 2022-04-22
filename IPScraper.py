# IPScraper.py
#
# This script provides a Python library with methods to authenticate to various sources of threat
# intelligence and query IPs for the latest data. Response that do not return empty results are
# reformatted as comma separated values and written to CSV
# 
# Currently supported:
#   Emerging Threats Intelligence (emergingthreats.net)
#   GreyNoise Community API (greynoise.io)
#   Onyphe Free Tier (onyphe.io)
#   Shodan (shodan.io)
#   VirusTotal (virustotal.com)
#
# github.com/jasonsford
# 22  April 2022

import json
import requests
import shodan
from datetime import datetime

class IPScraper:

    def findip(self, ip: str):
    
        now = datetime.now()
        self.flat_output_file = ip + "_" + now.strftime("%Y%m%d_%H%M%S") + ".csv"

        self.etintel(ip)
        self.greynoise(ip)
        self.onyphe(ip)              
        self.goShodan(ip)
        self.virustotal(ip)             

        print('Results written to ' + self.flat_output_file)

    def etintel(self, ip: str):
        
        etintel_base_url: str = 'https://api.emergingthreats.net/v1/'
        etintel_api_key: str = 'your emerging threats intelligence api key'
        etintel_session = requests.session()
        etintel_session.verify = True
        
        etintel_domains_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/domains'), headers={'Authorization': etintel_api_key})
        etintel_events_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/events'), headers={'Authorization': etintel_api_key})
        etintel_geoloc_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/geoloc'), headers={'Authorization': etintel_api_key})
        etintel_reputation_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/reputation'), headers={'Authorization': etintel_api_key})
        etintel_samples_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/samples'), headers={'Authorization': etintel_api_key})
        etintel_urls_response = etintel_session.get((etintel_base_url + 'ips/' + ip + '/urls'), headers={'Authorization': etintel_api_key})

        if "[]" not in etintel_domains_response.text:
            event_array = json.loads(etintel_domains_response.text)['response']
            print(ip + ' found in ET Intel - Domains')
            counter = 0
            for e in event_array:
                counter += 1
                d = json.dumps(e)
                d = 'ET Intel,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                if(counter < 6):
                    print(d)
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_events_response.text:
            event_array = json.loads(etintel_events_response.text)['response']
            print(ip + ' found in ET Intel - Events')
            counter = 0
            for e in event_array:
                counter += 1
                d = json.dumps(e)
                d = 'ET Intel,events,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                if(counter < 6):
                    print(d)
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_geoloc_response.text:
            event_array = json.loads(etintel_geoloc_response.text)['response']
            print(ip + ' found in ET Intel - Geolocation')
            counter = 0
            for e in event_array:
                counter += 1
                d = json.dumps(e)
                d = 'ET Intel,geoloc,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                if(counter < 6):
                    print(d)
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_reputation_response.text:
            event_array = json.loads(etintel_reputation_response.text)['response']
            print(ip + ' found in ET Intel - Reputation')
            counter = 0
            for e in event_array:
                counter += 1
                d = json.dumps(e)
                d = 'ET Intel,reputation,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                if(counter < 6):
                    print(d)
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_samples_response.text:
            event_array = json.loads(etintel_samples_response.text)['response']
            print(ip + ' found in ET Intel - Samples')
            counter = 0
            for e in event_array:
                counter += 1
                d = json.dumps(e)
                d = 'ET Intel,samples,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                if(counter < 6):
                    print(d)
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in etintel_urls_response.text:
            event_array = json.loads(etintel_urls_response.text)['response']
            print(ip + ' found in ET Intel - URLs')
            counter = 0
            for e in event_array:
                counter += 1
                d = json.dumps(e)
                d = 'ET Intel,urls,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                if(counter < 6):
                    print(d)
                print(d, file=open(self.flat_output_file, "a"))
    
    def greynoise(self, ip: str):

        greynoise_base_url: str = 'https://api.greynoise.io/v3/community/'
        greynoise_api_key: str = 'your greynoise community api key'
        greynoise_session = requests.session()
        greynoise_session.verify = True

        greynoise_response = greynoise_session.get((greynoise_base_url + ip), headers={'key': greynoise_api_key})

        grey_array = json.loads(greynoise_response.text)
        print(ip + ' found in GreyNoise')
        d = json.dumps(grey_array)
        d = 'GreyNoise,' + d
        d = d.replace('\'', '')
        d = d.replace('"', '')
        d = d.replace('{', '')
        d = d.replace('}', '')
        d = d.replace('ip:', 'ip,')
        d = d.replace('noise:', 'noise,')
        d = d.replace('riot:', 'riot,')
        d = d.replace('classification:', 'classification,')
        d = d.replace('name:', 'name,')
        d = d.replace('link:', 'link,')
        d = d.replace('last_seen:', 'last_seen,')
        d = d.replace('message:', 'message,')
        print(d, file=open(self.flat_output_file, "a"))
    
    def onyphe(self, ip: str):

        onyphe_base_url: str = 'https://www.onyphe.io/api/v2/simple/'
        onyphe_api_key: str = 'apikey your onyphe api key'
        onyphe_session = requests.session()
        onyphe_session.verify = True

        onyphe_sniffer_response = onyphe_session.get((onyphe_base_url + 'sniffer/' + ip), headers={'Authorization': onyphe_api_key})
        onyphe_threatlist_response = onyphe_session.get((onyphe_base_url + 'threatlist/' + ip), headers={'Authorization': onyphe_api_key})

        if "[]" not in onyphe_sniffer_response.text:
            event_array = json.loads(onyphe_sniffer_response.text)['results']
            print(ip + ' found in Onyphe - Sniffer')
            for e in event_array:
                d = json.dumps(e)
                d = 'Onyphe,sniffer,' + d
                d = d.replace('"', '')
                d = d.replace('@', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace('[', '')
                d = d.replace(']', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in onyphe_threatlist_response.text:
            event_array = json.loads(onyphe_threatlist_response.text)['results']
            print(ip + ' found in Onyphe - Threat List')
            for e in event_array:
                d = json.dumps(e)
                d = 'Onyphe,sniffer,' + d
                d = d.replace('"', '')
                d = d.replace('{', '')
                d = d.replace('}', '')
                d = d.replace('[', '')
                d = d.replace(']', '')
                d = d.replace(' ', '')
                d = d.replace(':', ',')
                print(d, file=open(self.flat_output_file, "a"))
    
    def goShodan(self, ip: str):

        shodan_api_key: str = 'your shodan api key'
        shodan_api = shodan.Shodan(shodan_api_key)       

        try:
            shodan_result = shodan_api.host(ip)
            print(ip + ' found in Shodan')
            d = json.dumps(shodan_result)
            d = 'Shodan,' + d
            d = d.replace('"', '')
            d = d.replace('\'', '')
            d = d.replace('{', '')
            d = d.replace('}', '')
            d = d.replace('[', '')
            d = d.replace(']', '')
            d = d.replace(' ', '')
            d = d.replace(':', ',')
            print(d, file=open(self.flat_output_file, "a"))

        except shodan.APIError as error:
            print('Shodan: {}'.format(error))
    
    def virustotal(self, ip: str):

        virustotal_base_url = 'https://www.virustotal.com/api/v3/'
        virustotal_api_key: str = 'your virustotal api key'
        virustotal_session = requests.session()
        virustotal_session.verify = True
        
        virustotal_whois_response = virustotal_session.get((virustotal_base_url + 'ip_addresses/' + ip + '/historical_whois'), headers={'x-apikey': virustotal_api_key})
        virustotal_commfiles_response = virustotal_session.get((virustotal_base_url + 'ip_addresses/' + ip + '/communicating_files'), headers={'x-apikey': virustotal_api_key})

        if "[]" not in virustotal_whois_response.text: 
            event_array = json.loads(virustotal_whois_response.text)
            print(ip + ' found in VirusTotal - Historical Whois')
            d = json.dumps(event_array)
            d = 'VirusTotal,' + d
            d = d.replace('"', '')
            d = d.replace('{', '')
            d = d.replace('}', '')
            d = d.replace('[', '')
            d = d.replace(']', '')
            d = d.replace(' ', '')
            d = d.replace(':', ',')
            print(d, file=open(self.flat_output_file, "a"))

        if "[]" not in virustotal_commfiles_response.text:    
            event_array = json.loads(virustotal_commfiles_response.text)
            print(ip + ' found in VirusTotal - Communicating Files')
            d = json.dumps(event_array)
            d = 'VirusTotal,' + d
            d = d.replace('"', '')
            d = d.replace('{', '')
            d = d.replace('}', '')
            d = d.replace('[', '')
            d = d.replace(']', '')
            d = d.replace(' ', '')
            d = d.replace(':', ',')
            print(d, file=open(self.flat_output_file, "a"))