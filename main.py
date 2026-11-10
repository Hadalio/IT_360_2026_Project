# IT-360 SIEM & Digital Forensics
# Sean Sanders
# Project: Cookiescope
# Authors: Jake Cirks, Ryan Kotrba, Xander Beachy
###################################################
import os
from forensic_tool import CookieScope
from ollama_client import OllamaClient 

def main():
    #Create class objects
    tool = CookieScope()

    #Run modules
    results = tool.run_all_modules("cookies.json")

    #Create client
    client = OllamaClient(url="http://sushi.it.ilstu.edu:8080", api_key=os.environ.get("API_KEY"), model="llama3.3:latest")

    #Build report with results from modules
    report = client.generate_report(results)

    #Output the report
    print(report)

#Run it 
if __name__ == "__main__":
    main()



##############################
#       Sources Citied       
# https://thepythoncode.com/article/extract-chrome-cookies-python
