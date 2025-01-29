import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

class FeatureExtraction:
    features = []
    def __init__(self,url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass


        

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())


     # 1.UsingIp determine if the input URL is a valid IP address or not
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2.longUrl method takes the url attribute of the class instance and returns an integer based on the length of the URL.
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

    # 3.shortUrl function appears to be checking whether the given URL belongs to a list of known URL shortening services.
    def shortUrl(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        if match:
            return -1
        return 1

    # 4.Symbol function checks whether the given URL contains the "@" symbol
    def symbol(self):
        if re.findall("@",self.url):
            return -1
        return 1
    
    # 5.Redirecting function checks whether the given URL has more than one occurrence of "//" after the initial "https://" or "http://" protocol.
    def redirecting(self):
        if self.url.rfind('//')>6:
            return -1
        return 1
    
    # 6.prefixSuffix function checks whether the domain name of the URL contains a hyphen ("-").
    def prefixSuffix(self):
        try:
            match = re.findall('\-', self.domain)
            if match:
                return -1
            return 1
        except:
            return -1
    
    # 7.SubDomains function checks the number of subdomains in the given URL. It counts the number of dots in the URL
    def SubDomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8.HTTPS method to check whether the URL uses HTTPS or not.
    def Hppts(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https:
                return 1
            return -1
        except:
            return 1

    """9.DomainRegLen The DomainRegLen function appears to be using the whois package to retrieve the domain registration
      and creation dates, and then calculates the age of the domain in months. If the age of the domain is greater than or
        equal to 12 months, it returns 1 (indicating a legitimate domain), otherwise it returns -1"""
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            try:
                if(len(expiration_date)):
                    expiration_date = expiration_date[0]
            except:
                pass
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            age = (expiration_date.year-creation_date.year)*12+ (expiration_date.month-creation_date.month)
            if age >=12:
                return 1
            return -1
        except:
            return -1

    # 10. Favicon function checks whether the URL contains a favicon, which is a small icon displayed in the web browser tab
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                        return 1
            return -1
        except:
            return -1

    # 11. NonStdPort
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port)>1:
                return -1
            return 1
        except:
            return -1

    """ 12. HTTPSDomainURL function checks whether the URL contains a non-standard port. If the URL contains a 
    port other than the standard HTTP or HTTPS ports (80 and 443 respectively), it returns -1, otherwise it returns 1."""
    def HTTPSDomainURL(self):
        try:
            if 'https' in self.domain:
                return -1
            return 1
        except:
            return -1
#13. RequestURL It seems like this is a function to check the existence of external URLs in the web page's source code. 
    #The function uses BeautifulSoup to extract image, audio, embed, and iframe tags that have an "src" attribute. Then, it 
    #checks if the URL of the current website or its domain name is present in the "src" attribute of these tags. If the percentage
      #of external URLs is less than 22%, it returns 1 (indicating phishing), if it's between 22% and 61%, it returns 0 
      #(indicating suspicious), and if it's more than 61%, it returns -1 (indicating legitimate)."""
    def RequestURL(self):
        try:
            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            try:
                percentage = success/float(i) * 100
                if percentage < 22.0:
                    return 1
                elif((percentage >= 22.0) and (percentage < 61.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1
    
    
    # 14. AnchorURLchecks the safety of the links present in the anchor tags (<a> tags) of a given URL. Here's how it works:
    #1. The function first initializes two variables i and unsafe to 0. i keeps track of the total number of anchor tags, while
    #unsafe keeps track of the number of unsafe links.
    #2. It then iterates over all the anchor tags in the HTML page using the find_all method of the BeautifulSoup library.
    #3. For each anchor tag, it checks if the link starts with # (indicating an anchor link), or if the link starts with javascript
    #or mailto, or if the link does not contain the URL or the domain of the website. If any of these conditions is true, the link 
    #is considered unsafe and unsafe is incremented.
    #4. Finally, the function calculates the percentage of unsafe links by dividing unsafe by i and multiplying by 100. Based on this 
    #percentage, the function returns 1 (safe), 0 (suspicious), or -1 (unsafe)."""
    def AnchorURL(self):
        try:
            i,unsafe = 0,0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or self.domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1
            try:
                percentage = unsafe / float(i) * 100
                if percentage < 31.0:
                    return 1
                elif ((percentage >= 31.0) and (percentage < 67.0)):
                    return 0
                else:
                    return -1
            except:
                return -1
        except:
            return -1
    

    # 15. LinksInScriptTags function is to check whether links within the script tags on a website are suspicious.
    #The function first initializes variables i and success to zero. It then searches for all link and script tags within the
       #website's HTML code that contain an href or src attribute respectively. For each link found, the function checks whether 
       #it contains the website's domain, URL, or has only one dot. If the link matches any of these criteria, the variable success
       #is incremented. At the end, the function calculates the percentage of successful matches relative to the total number of 
       #links found. If this percentage is less than 17%, the function returns 1, indicating that the links are safe. If the percentage
       #is between 17% and 81%, the function returns 0, indicating that the links may be suspicious. If the percentage is 
       #greater than or equal to 81%, the function returns -1, indicating that the links are likely to be malicious. If any error occurs
       #during the execution of the function, it returns -1."""
    def LinksInScriptTags(self):
        try:
            i,success = 0,0
        
            for link in self.soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for script in self.soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            try:
                percentage = success / float(i) * 100
                if percentage < 17.0:
                    return 1
                elif((percentage >= 17.0) and (percentage < 81.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

    # 16. ServerFormHandler function checks whether the form action URL is empty, points to a blank page, or is not hosted on 
    # the same domain or URL as the current page.
    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True))==0:
                return 1
            else :
                for form in self.soup.find_all('form', action=True):
                    if form['action'] == "" or form['action'] == "about:blank":
                        return -1
                    elif self.url not in form['action'] and self.domain not in form['action']:
                        return 0
                    else:
                        return 1
        except:
            return -1

    # 17. InfoEmail  function is used to determine whether an email address is present on the webpage.
    def InfoEmail(self):
        try:
            if re.findall(r"[mail\(\)|mailto:?]", self.soup):
                return -1
            else:
                return 1
        except:
            return -1

    # 18. AbnormalURLfunction is used to determine if the URL is abnormal or not. It compares the website's response text with
    #  the whois response. If both the response texts match, it is considered as a normal URL and it returns 1. Otherwise, it is 
    #  considered as an abnormal URL and it returns -1.
    def AbnormalURL(self):
        try:
            if self.response.text == self.whois_response:
                return 1
            else:
                return -1
        except:
            return -1

    # 19. WebsiteForwarding function checks whether a website is being forwarded to another website or not.
    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            else:
                return -1
        except:
             return -1

    # 20. StatusBarCust 
    #This function is checking for the presence of certain JavaScript code in the HTML response that is associated with a
      #"status bar customization" attack, where an attacker uses JavaScript to modify the browser's status bar to display a 
      #different URL than the actual destination of a hyperlink.
      #If the function finds such code in the HTML response, it returns 1 to indicate that the attack is present. Otherwise, 
      #it returns -1 to indicate that the attack is not present."""
    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 21. DisableRightClickfunction checks whether the web page disables the right-click context menu using JavaScript.
    #  It does this by searching the HTML source code for the string "event.button == 2", which is a JavaScript event
    #  that is triggered when the right mouse button is clicked.
    def DisableRightClick(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 22. UsingPopupWindow function is checking if the HTML response contains any alert() calls, which typically display a message in a
    # popup window. 
    def UsingPopupWindow(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 23. IframeRedirection function is intended to check if the website uses iframe tags, which could potentially lead to phishing attacks
    #  or other security risks.
    def IframeRedirection(self):
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 24. AgeofDomain function calculates the age of the domain by retrieving the creation date from the whois_response attribute
    # and comparing it to the current date. 
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today  = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >=6:
                return 1
            return -1
        except:
            return -1

    # 25. DNSRecording function checks if the domain has at least one name server.
    def DNSRecording(self):
        try:
            if self.whois_response.name_servers:
                return 1
            else:
                return -1
        except:
            return -1

    # 26. WebsiteTraffic function appears to be checking the website's popularity using the Alexa rank  
    def WebsiteTraffic(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(), "xml").find("REACH")['RANK']
            if (int(rank) < 100000):
                return 1
            return 0
        except:
            return -1

    # 27. PageRank  library is used to send a POST request to the website https://www.checkpagerank.net/index.php with the domain name. Then,
    #  the response text is parsed using a regular expression to extract the global rank.
    def PageRank(self):
        try:
            prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
            global_rank = int(re.findall(r"Global Rank: (\d+)", prank_checker_response.text)[0])
            if global_rank > 0 and global_rank < 100000:
                return 1
            return -1
        except:
            return -1

            

    # 28. GoogleIndex allows users to programmatically perform Google searches and retrieve the results in a convenient format
    def GoogleIndex(self):
        try:
            site = search(self.url, 5)
            if site:
                return 1
            else:
                return -1
        except:
            return 1

    # 29. LinksPointingToPage function is used to determine the number of links pointing to a page.
    def LinksPointingToPage(self):
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            else:
                return -1
        except:
            return -1

    # 30. StatsReport function seems to generate a report on the stats of the website, specifically checking for any potential
    #  red flags in the website's URL or IP address.
#Here are the specific steps of the function:
# 1. It first searches the website's URL for any matches to a list of blacklisted domains. If there is a match, it returns -1, 
# indicating a red flag.
 #2. It then obtains the IP address of the website and searches for any matches to a list of blacklisted IP addresses. 
 #If there is a match, it returns -1, indicating a red flag.
 #3. If there are no matches in the previous steps, it returns 1, indicating that there are no obvious red flags with the website's stats"""
    
    def StatsReport(self):
        try:
            url_match = re.search(
        'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match:
                return -1
            elif ip_match:
                return -1
            return 1
        except:
            return 1
    
    def getFeaturesList(self):
        return self.features
