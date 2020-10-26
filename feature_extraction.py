import urllib.request
import numpy as np
import pandas as pd
import re
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import time
import socket
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self):
        pass

    def long_url(self, l):
        """This function is defined in order to differntiate website based on the length of the URL"""
        if len(l) < 54:
            return 0
        elif len(l) >= 54 and len(l) <= 75:
            return 2
        return 1

    def have_at_symbol(self, l):
        """This function is used to check whether the URL contains @ symbol or not"""
        if "@" in l:
            return 1
        return 0

    def redirection(self, l):
        """If the url has symbol(//) after protocol then such URL is to be classified as phishing """
        if "//" in l:
            return 1
        return 0

    def prefix_suffix_seperation(self, l):
        if '-' in l:
            return 1
        return 0

    def sub_domains(self,l):
        if l.count('.') < 3:
            return 0
        elif l.count('.') == 3:
            return 2
        return 1

    def having_ip_address(self, url):
        match = re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                        # IPv4 in hexadecimal
                        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'
                        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
        if match:
            return 1
        else:
            return 0

    def shortening_service(self, url):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', url)
        if match:
            return 1
        else:
            return 0

    def https_token(self, url):
        match = re.search('https://|http://', url)
        if match:
            if match.start(0) == 0:
                url = url[match.end(0):]
        match = re.search('http|https', url)
        if match:
            return 1
        else:
            return 0

    def web_traffic(self, url):
        try:
            rank = BeautifulSoup(urllib.request.urlopen(
                "http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        except TypeError:
            return 1
        rank = int(rank)
        if (rank < 100000):
            return 0
        else:
            return 2

    def domain_registration_length_sub(domain):
        expiration_date = domain.expiration_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        if expiration_date is None:
            return 1
        elif type(expiration_date) is list or type(today) is list:
            return 2  # If it is a type of list then we can't select a single value from list. So,it is regarded as suspected website
        else:
            registration_length = abs((expiration_date - today).days)
            if registration_length / 365 <= 1:
                return 1
            else:
                return 0
    
    def domain_registration_length(self,domain):
        dns = 0
        try:
            domain_name = whois.whois(domain)
        except:
            dns = 1

        if dns == 1:
            return 1
        else:
            return self.domain_registration_length_sub(domain_name)

    def age_of_domain_sub(domain):
        creation_date = domain.creation_date
        expiration_date = domain.expiration_date
        if ((expiration_date is None) or (creation_date is None)):
            return 1
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 2
        else:
            ageofdomain = abs((expiration_date - creation_date).days)
            if ((ageofdomain/30) < 6):
                return 1
            else:
                return 0

    def age_of_domain(self, domain):
        dns = 0
        try:
            domain_name = whois.whois(domain)
        except:
            dns = 1

        if dns == 1:
            return 1
        else:
            return self.age_of_domain_sub(domain_name)

    def dns_record(self, domain):
        dns = 0
        try:
            domain_name = whois.whois(domain)
            print(domain_name)
        except:
            dns = 1

        if dns == 1:
            return 1
        else:
            return dns
    
    def statistical_report(self, url):
        hostname = url
        h = [(x.start(0), x.end(0)) for x in re.finditer(
            'https://|http://|www.|https://www.|http://www.', hostname)]
        z = int(len(h))
        if z != 0:
            y = h[0][1]
            hostname = hostname[y:]
            h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
            z = int(len(h))
            if z != 0:
                hostname = hostname[:h[0][0]]
        url_match = re.search(
            'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
        try:
            ip_address = socket.gethostbyname(hostname)
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
        except:
            return 1

        if url_match:
            return 1
        else:
            return 0

    def getProtocol(self, url):
        return urlparse(url).scheme
    
    def getDomain(self, url):
        return urlparse(url).netloc

    def getPath(self, url):
        return urlparse(url).path


def getFeatures(url):
    fe = FeatureExtraction()
    protocol = fe.getProtocol(url)
    path = fe.getPath(url)
    domain = fe.getDomain(url)
    having_ip = fe.having_ip_address(url)
    len_url = fe.long_url(url)
    having_at_symbol = fe.have_at_symbol(url)
    redirection_symbol = fe.redirection(url)
    prefix_suffix_separation = fe.prefix_suffix_seperation(url)
    sub_domains = fe.sub_domains(url)
    tiny_url = fe.shortening_service(url)
    web_traffic = fe.web_traffic(url)
    domain_registration_length = fe.domain_registration_length(url)
    dns_record = fe.dns_record(url)
    statistical_report = fe.statistical_report(url)
    age_domain = fe.age_of_domain(url)
    http_tokens = fe.https_token(url)

    d = {'Protocol': pd.Series(protocol), 'Domain': pd.Series(domain), 'Path': pd.Series(path), 'Having_IP': pd.Series(having_ip),
         'URL_Length': pd.Series(len_url), 'Having_@_symbol': pd.Series(having_at_symbol),
         'Redirection_//_symbol': pd.Series(redirection_symbol), 'Prefix_suffix_separation': pd.Series(prefix_suffix_separation),
         'Sub_domains': pd.Series(sub_domains), 'tiny_url': pd.Series(tiny_url), 'web_traffic': pd.Series(web_traffic),
         'domain_registration_length': pd.Series(domain_registration_length), 'dns_record': pd.Series(dns_record),
         'statistical_report': pd.Series(statistical_report), 'age_domain': pd.Series(age_domain), 'http_tokens': pd.Series(http_tokens)}

    data = pd.DataFrame(d)
    # print(len(data))
    # data.to_clipboard(True)
    data = data.drop(data.columns[[0,1,2]], axis=1)
    # print(data)
    return data


# d = getFeatures('https://vtop.vit.ac.in/vtop/initialProcess')