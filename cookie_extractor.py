import sqlite3
import os
import json
import base64
import shutil
from datetime import datetime, timedelta
import win32crypt
from Crypto.Cipher import AES


class CookieExtractor:

    def __init__(self):
        pass    

    def get_chrome_datetime(self,chromedate):
        """Return a `datetime.datetime` object from a chrome format datetime
        Since `chromedate` is formatted as the number of microseconds since January, 1601"""
        if chromedate != 86400000000 and chromedate:
            try:
                return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
            except Exception as e:
                print(f"Error: {e}, chromedate: {chromedate}")
                return chromedate
        else:
            return ""

    def get_encryption_key(self, local_state_path):
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)

        # decode the encryption key from Base64
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # remove 'DPAPI' str
        key = key[5:]
        # return decrypted key that was originally encrypted
        # using a session key derived from current user's logon credentials
        # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

    def decrypt_data(self,data, key):
        try:
            # get the initialization vector
            iv = data[3:15]
            data = data[15:]
            # generate cipher
            cipher = AES.new(key, AES.MODE_GCM, iv)
            # decrypt password
            return cipher.decrypt(data)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
            except:
                # not supported
                return ""


    #Main function to hanlde extraction of chromium based browser cookeis (Chrome, Edge, etc)
    def extract_chromium_cookies(self, browser_name, db_path,local_state_path):

        try:
            filename = f"{browser_name}_Cookies.db"

            shutil.copyfile(db_path, filename)
    
            db = sqlite3.connect(filename)  # connect to the database
   
            db.text_factory = lambda b: b.decode(errors="ignore")   # ignore decoding errors
            cursor = db.cursor()
            # get the cookies from `cookies` table
            cursor.execute("""
                SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value, is_secure, is_httponly
                FROM cookies""")
    
            key = self.get_encryption_key(local_state_path)
            #Create list for cookies discovered
            cookies = []
            for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value, is_secure, is_httponly in cursor.fetchall():
                if not value:
                    decrypted_value = self.decrypt_data(encrypted_value, key)
                else:
                # already decrypted
                    decrypted_value = value
                    #Add to the cookie list
                cookies.append({
                    "browser": browser_name,
                    "domain": host_key,
                    "name": name,
                    "value": decrypted_value,
                    "creation_time": str(self.get_chrome_datetime(creation_utc)),
                    "creation_utc": creation_utc,
                    "last_access": str(self.get_chrome_datetime(last_access_utc)),
                    "expiry": str(self.get_chrome_datetime(expires_utc)),
                    "expires_utc": expires_utc,
                    "secure": bool(is_secure),
                    "http_only": bool(is_httponly)
                    })
                        

            # close connection
            db.close()

            return cookies 
        except Exception as e:
            print(f"{browser_name} extraction failed: {e}")

            return []
    
    def extract_chrome(self):
        # local sqlite Chrome cookie database path
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "Default", "Network", "Cookies")

        local_state = os.path.join(os.environ["USERPROFILE"],"AppData", "Local", "Google", "Chrome", "User Data", "Local State")

        return self.extract_chromium_cookies("Chrome", db_path, local_state)

    def extract_edge(self):
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local","Microsoft", "Edge", "User Data", "Default", "Network", "Cookies")

        local_state = os.path.join(os.environ["USERPROFILE"],"AppData", "Local", "Microsoft", "Edge", "User Data", "Local State")

        return self.extract_chromium_cookies("Edge", db_path, local_state)

    def extract_firefox_cookies(self):
        print("Firefox extraction is work in progress")
        return []

    def extract_all(self):

        cookies = []

        cookies.extend(self.extract_chrome())
        cookies.extend(self.extract_edge())
        cookies.extend(self.extract_firefox_cookies())

        return cookies 


if __name__ == "__main__":
    extractor = CookieExtractor()

    cookies = extractor.extract_chrome()

    print(f"Cookies Found: {len(cookies)}")

    for cookie in cookies[:5]:
        print(cookie)