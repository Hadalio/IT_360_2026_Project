import json
import subprocess
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
from urllib.parse import urlparse
class Forensic_tool:

    # OSINT Domain Lists
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

    def is_session_long_lived(self, expiry):
        if not expiry:
            return False 

        try: #Convert to int
            expiry = int(expiry)
        except:
            return False

        sus_time = 13253760000000000

        return expiry > sus_time

    def is_session_cookie(self,name):
        name = name.lower()
        session_keywords =["session", "sid", "sessid", "phpsessid", "jsessionid", "auth", "token"]
        return any(s in name for s in session_keywords)

    
    def normalize_cookie(self, cookie):
        return {
            "domain": cookie.get("domain") or cookie.get("host_key") or cookie.get("host") or "",
            "name": cookie.get("name", ""),
            "value": cookie.get("value") or cookie.get("encrypted_value") or "",
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


    def analyze_cookies(self, cookie_files):

        try:
            with open(cookie_files, "r") as f:
                cookies = json.load(f)
        except Exception as e:
            return {
            "error": f"Failed to load cookie file: {e}",
            "total_cookies": 0,
            "third_party": [],
            "suspcious": [],
            "flags": []
        }

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
                    issues.appednd("Session cookie missing Secure flag (Sent via HTTP)")
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

    def analyze_logs(self, log_file):
        #Come back to parse logs
        findings = {
            "processes": [],
            "modules": [],
            "flags": []
        }

        if log_file.lower().endswith(".evtx"):
            try:
                with Evtx(log_file) as evtx:
                    for xml, record in evtx_file_xml_view(evtx):
                        event_data = self.parse_evtx_event(xml)
                        if event_data:
                            findings["events"].append(event_data)


                            if self.is_suspicious_event(event_data):
                                findings["suspicious"].append(event_data)
            except Exception as e:
                findings["flags"].append(f"Failed to parse EVTX: {e}")
                return findings 
        else:
            try:
                with open(log_file, "r", errors="ignore") as f:
                    for line in f:
                        event_data = self.parse_plaintext_log(line)
                        if event_data:
                            findings["events"].append(event_data)
                            if self.is_suspicious_event(event_data):
                                findings["events"].append(event_data)

            except Exception as e:
                findings["flags"].append(f"Failed to parse plaintext log: {e}")
                return findings 
        if len(findings["suspicious"]) > 0:
            findings["flags"].append("Suspicous log events detected")

        if len(findings["events"]) < 10:
            findings["flags"].append("Unusually small number of log events")

        return findings 
    def parse_evtx_event(self, xml):
        try:
            event_id = self._extract_between(xml, "<EventID>", "</EventID>")
            timestamp = self._extract_between(xml, "<TimeCreated SystemTime=\"", "\"/>")
            provider = self._extract_between(xml, "<Provider Name=\"", "\"")

            return {
                "event_id": event_id,
                "timestamp": timestamp,
                "provider": provider,
                "raw": xml[:200]   # Store only the first 200 characters
            }
        except:
            return None
    def parse_plaintext_log(self, line):
        line = line.strip()
        if not line:
            return None

        return {
            "event_id": "text",
            "timestamp": None,
            "provider": "plaintext",
            "raw": line

        }

    def is_suspicious_event(self, event):
        suspicious_ids = [
            "4625", #Failed logon
            "4720", #user account created
            "1102", # audit logs cleared
            "4688", #new process created
            "4697", #service installed
            "7045", #service created
        ]

        raw = event.get("raw", "").lower()

        if event.get("event_id") in suspicious_ids:
            return True

        suspicious_keywords = [
            "failed", "error", "unauthorized",
            "malware", "attack", "breach",
            "cmd.exe", "powershell.exe"
        ]

        if any(keyword in raw for keyword in suspicious_keywords):
            return True
        return False

    def _extract_between(self, text, start, end):
        try:
            return text.split(start)[1].split(end)[0]
        except:
            return None

    def analyze_memory(self, memory):
        """
        Runs Volatility 3 against a memory dump and extracts high value artifacts.
        Returns structured findings compatible for report generation
        """
        findings = {
            "processes": [],
            "suspicious": [],
            "flags": []
        }

        try:
            #Run Volatility pslist
            result = subprocess.run(
                ["vol", "-f", memory, "windows.pslist"],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                findings["flags"].append("Volatility failed to run")
                findings["flags"].append(result.stderr.strip())
                return findings

            output = result.stdout.splitlines()
        except Exception as e:
            findings["flags"].append(f"Error running Volatility: {e}")
            return findings

        #Parse pslist output
        for line in output:
            #SKip headers
            if "PID" in line or "Offset" in line:
                continue
            parts = line.split()
            if len(parts) < 3:
                continue

            try:
                pid = parts[1]
                process_name = parts[-1]
            except:
                continue

            findings["processes"].append({
                "pid": pid,
                "name": process_name
            })

            #Detect suspicious processes
            suspicious_names = ["mimikatz.exe", "cmd.exe", "powershell.exe",
                                "nc.exe", "netcat", "svch0st.exe", "unknown.exe"
            ]

            if process_name.lower() in suspicious_names:
                findings["suspicious"].append({
                    "pid": pid,
                    "name": process_name
                })
        if len(findings["suspicious"]) > 0:
            findings["flags"].append("Suspicious processes detected")

        if len(findings["processes"]) < 5:
            findings["flags"].append("Unusually small process list (possible corruption)")

        return findings

    def run_all_modules(self, cookie_file, log_file, memory_file):
        return {
            "cookies": self.analyze_cookies(cookie_file),
            "memory": self.analyze_memory(memory_file),
            "log": self.analyze_logs(log_file)
        }