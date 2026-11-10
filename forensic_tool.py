import json
from datetime import datetime
from urllib.parse import urlparse


class CookieScope:

    # OSINT Domain Lists | Can be modified as needed to include +/- domain names
    Tracking_domains = {
        "doubleclick.net",
        "google-analytics.com",
        "adservice.google.com",
        "facebook.net",
        "scorecardsearch.com",
        "quantserve.com",
        "ads.yahoo.com",
        "adnxs.com",
        "rubiconproject.com"
    }

    Malicious_domains = {
        "evil-malware-site.biz",
        "steal-session.ru",
        "phish-login.cn",
        "malicious-update.net",
        "trojan-dropper.org"
    }

    Fingerprinting_domains = {
        "fingerprintjs.com",
        "browserleaks.com",
        "deviceinfo.me"
    }

    Suspicious_Tlds = {
        ".ru", ".cn", ".biz", ".info", ".top", ".xyz"
    }



    #Build functions
    #Load cookies from json file
    #Function can be deleted once cookie extraction from dbs has been completed
    def load_cookies(self, cookie_file):

        #Open the cookie file 
        with open(cookie_file, "r") as f:

            #Return its data 
            return json.load(f)
        
    #Determine if the cookie session is long lived 
    def is_session_long_lived(self, expiry):

        #Validate there is expiration
        if not expiry:
            return False 

        #Convert to int
        try: 
            expiry = int(expiry)
        except: 
            return False

        sus_time = 13253760000000000

        return expiry > sus_time

    #Identify session cookies based on keywords
    def is_session_cookie(self,name):
        #Normalize all names 
        name = name.lower()
        #Looking for any of these keywords
        session_keywords =["session", "sid", "sessid", "phpsessid", "jsessionid", "auth", "token"]
        #Return any keyword found 
        return any(s in name for s in session_keywords)

    #Create a normal looking data set from the raw cookie data - requires a cookie and the browser (optional browser)
    def normalize_cookie(self, cookie, browser = "unknown"):
        return {
            "browser": browser,
            "domain": cookie.get("domain", ""),
            "name": cookie.get("name", ""),
            "value": cookie.get("value"),
            "path": cookie.get("path", "/"),

            # Security flags
            "secure": (
                cookie.get("secure") or
                cookie.get("isSecure") or
                cookie.get("Secure") or
                False
            ),

            "http_only": (
                cookie.get("httpOnly") or
                cookie.get("httponly") or
                cookie.get("HttpOnly") or
                False
            ),

            "same_site": (
                cookie.get("sameSite") or
                cookie.get("samesite") or
                cookie.get("SameSite") or
                "None"
            ),

            # Expiration
            "expiry": (
                cookie.get("expirationDate") or
                cookie.get("expires_utc") or
                cookie.get("expiry") or
                None
            ),

            # Host-only flag
            "host_only": (
                cookie.get("hostOnly") or
                cookie.get("host_only") or
                cookie.get("HostOnly") or
                True
            )
        }

    
    def analyze_cookies(self, cookies):

        
        findings = {
            "total_cookies": len(cookies),
            "third_party": [],
            "suspcious": [],
            "flags": []
        }

        #List of known suspicious or high risk keywords
        #Add to as needed
        suspicious_keywords= [ "track", "ads", "analytics", "doubleclick",
                               "telemetry", "beacon", "spy", "malware"
                            ]

        #Build information by cookie
        for raw_cookie in cookies:
            #Cook the cookie
            cookie = self.normalize_cookie(raw_cookie)
            #Expected content below
            domain = cookie["domain"]
            name = cookie["name"]
            secure = cookie["secure"]
            http_only = cookie["http_only"]
            same_site = cookie["same_site"]
            expiry = cookie["expiry"]
            host_only = cookie["host_only"]
            parse_domain = urlparse("http://" + domain)
            root_domain = domain.lower()

            if root_domain in self.Tracking_domains:
                findings["third_party"].append({
                    "domain": root_domain,
                    "name": name,
                    "reason": "Known tracking domain"
                })

            if root_domain in self.Malicious_domains:
                findings["suspcious"].append({
                    "domain": root_domain,
                    "name": name,
                    "reason": "Known malicious domain"
                })

            if root_domain in self.Fingerprinting_domains:
                findings["suspcious"].append({
                    "domain": root_domain,
                    "name": name,
                    "reason": "Known fingerprinting service"
                })

            if any(root_domain.endswith(tld) for tld in self.Suspicious_Tlds):
                findings["suspcious"].append({
                    "domain": root_domain,
                    "name": name,
                    "reason": "Suspicious top-level domain"
                })

            if self.is_session_cookie(name):
                issues = []

                if not secure:
                    issues.append("Session cookie missing Secure flag (Sent via HTTP)")
                if not http_only:
                    issues.append("Session cookie missing HttpOnly flag (accessible via JavaScript)")
                if same_site.lower() == "none":
                    issues.append("Session cookie allowed in cross-site requets")

                if issues:
                    findings["suspcious"].append({
                        "domain": root_domain,
                        "name": name,
                        "issues": issues,
                        "reason": "Session hijacking risk"
                    })
            auth_keywords = ["auth", "token", "jwt", "c_user", "xs", "sapisd", "ssid", "hsid"]
            if any(k in name.lower() for k in auth_keywords):
                if self.is_session_long_lived(expiry):
                    findings["suspcious"].append({
                        "domain": root_domain,
                        "name": name,
                        "issues": ["Suspiciously long lived auth cookie"],
                        "reason": "Persistent login token"
                    })

            #Find Third party cookies
            if cookie.get("hostOnly") is False:
                findings["third_party"].append({
                    "domain": root_domain,
                    "name": name
                })

            #Detect suspicious domains
            if any(keyword in root_domain.lower() for keyword in suspicious_keywords):
                 findings["suspcious"].append({
                     "domain": root_domain,
                     "name": name
                })

            #Identify anything unsafe about the cookie
            insecurities = []
            if not secure:
                insecurities.append("Missing Secure flag")
            if not http_only:
                insecurities.append("Missing HttpOnly flag")
            if same_site.lower() == "none":
                insecurities.append("SameSite=None")
            if insecurities:
                 findings["suspcious"].append({
                     "domain": root_domain,
                     "name": name,
                     "issues": insecurities
                     })

        #Higher level flags
        if len(findings["suspcious"]) > 0:
            findings["flags"].append("Suspcious cookies detected")
        if len(findings["third_party"]) > 20:
            findings["flags"].append("High number of third-pary cookies")

        return findings 

    def build_cookie_timeline(self,cookies):
        timeline = []

        #Get the cookie data from cookie for each cookie
        for cookie in cookies:
            domain = cookie.get("domain", "")
            browser = cookie.get("browser", "Unknown")
            timestamp = (
                cookie.get("creationDate")
                or cookie.get("creation_time")
                or cookie.get("creation_utc")
            )
            #If there is no timestamp
            if not timestamp:
                continue
            #
            try:
                date_time = datetime.fromtimestamp(float(timestamp))

                timeline.append({
                    "timestamp": date_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "browser": browser,
                    "domain": domain,
                    "event": "Cookie Generated"

                })
            except Exception:
                continue

            #Organize the timeline for chronological order
            timeline.sort(key=lambda x: x["timestamp"])

        return timeline

    #Rip open session cookies for metadata analysis
    def analyze_session_cookies(self, cookies):

        #Build a few lists to store findings
        findings = {
            "active_sessions": [],
            "insecure_sessions": [],
            "long_lived_sessions": []
        }

        #Preset a list of keywords for matching
        keywords = [
            "sid",
            "ssid",
            "auth",
            "token",
            "session",
            "phpsessid",
            "token"
        ]

        #Comb through the cookies 
        for cookie in cookies:

            #Normalize all cookie names
            name = cookie.get("name", "").lower()

            #Find any names that match to keywords
            if any(n in name for n in keywords):

                #Add findings to list(s) 
                findings["active_sessions"].append({
                    "domain": cookie.get("domain"),
                    "cookie": cookie.get("name")
                })

                #If the cookie is insecure (determined on if missing either "secure" or "http_only")
                if(not cookie.get("secure") or not cookie.get("http_only")):

                    #Add findings to list(s)
                    findings["insecure_sessions"].append({
                        "domain": cookie.get("domain"),
                        "cookie": cookie.get("name")
                    })

                #Retrieve the cookies expiration 
                expiration = cookie.get("expiry")

                #Is the cookie long lived?
                if self.is_session_long_lived(expiration):

                    # If so add findings to list(s)
                    findings["long_lived_sessions"].append({
                        "domain": cookie.get("domain"),
                        "cookie": cookie.get("name")
                    })

        #Give back the findings
        return findings
    #Identify correlations between cookies across browsers
    def match_cookies_to_browsers(self, cookies):

        #Build dictionary for domains discovered to match with browsers
        domains = {}

        #Comb through cookies
        for cookie in cookies:

            #define the domain
            domain = cookie.get("domain")

            #define the brower
            browser = cookie.get("browser")

            #Dont break my code pass an empty domain
            if not domain:
                continue

            #if the found domain is not in the list
            if domain not in domains:

                #set its value to whatever set() does | read later
                domains[domain] = set()

            #Add the found data
            domains[domain].add(browser)

        #Outside for Loop
        #Build a dictionary for correlation between browsers and domains+
        correlations = {}

        #loop through the domains that are found across browsers
        for domain, browsers in domains.items():

            #Check list contains data | must contain more than 1 item
            if len(browsers) > 1:
                correlations[domain] = list(browsers)

        return correlations

    #Provide information about cookie count per browser
    def browser_stats(self, cookies):

        #Build a dictionary to hold stats for each browser
        stats = {}

        #Comb through cookies
        for cookie in cookies:

            #Get easch cookies browser
            browser = cookie.get("browser", "Unknown")

            #Add the cookie count for each browser
            stats[browser] = (stats.get(browser, 0) + 1)

        #Return the stats
        return stats

    #Load and run all functions and returned in format
    #Change cookie_file to cookies once extractor from dbs works
    def run_all_modules(self, cookie_file):

        #Load the cookie file and create cookies variable
        #Remove function once extractor works and let cookies be passed to function calls below
        #analyze_cookies "starts" the process (there is no neccessary order)
        cookies = self.load_cookies(cookie_file)

        #Create variable to hold analyzed cookies
        cookie_findings = self.analyze_cookies(cookies)

        #Create variable to hold cookie timeline
        timeline = self.build_cookie_timeline(cookies)

        #Create variable to hold cookie session information
        session = self.analyze_session_cookies(cookies)

        #Create variable to hold correlation information
        correlations = self.match_cookies_to_browsers(cookies)

        #Create variable to hold browser stats information
        stats = self.browser_stats(cookies)

        #Return the module information
        return {
            "cookies": cookie_findings,
            "timeline": timeline,
            "sessions": session,
            "correlations": correlations,
            "stats": stats
        }