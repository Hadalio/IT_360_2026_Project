# IT-360 SIEM & Digital Forensics
# Sean Sanders
# Project: Cookiescope
# Authors: Jake Cirks, Ryan Kotrba, Xander Beachy
###################################################
#The following is a code sample from citied source one. 
import json
import os 
from forensic_tool import Forensic_tool
from report_builder import ReportBuilder
from ollama_client import Ollamaclient 

def main():
    #Create class objects
    tool = Forensic_tool()
    builder = ReportBuilder()

    #Run modules
    cookie_results = tool.analyze_cookies("cookies.json")
    log_results = tool.analyze_logs("logs.evtx")
    memory_results = tool.analyze_memory("MemoryDump_Lab1.raw")

    #Run modules
    results = {
        "cookies": cookie_results,
        "memory": memory_results,
        "logs": log_results
    }

    #Build report
    report = builder.build_report(results)



    print("=== Forensic Report ===")
    print(f"Summary: {report['summary']}")
    print("\nFlags:")
    for flag in report["flags"]:
        print(f" -{flag}")

    print("\nDetailed Findings:")
    for section_name, section_data in report["findings"].items():
        print(f"\n[{section_name.upper()}]")
        print(section_data)


    

    #Connect to Ollama for AI
    client = Ollamaclient(
        url = 'http://sushi.it.ilstu.edu:8080',
                api_key = os.environ.get('API_KEY'),   #Retrive the API key from the operating system environment
                model="llama3.3:latest")    # Can be changed to a model of your liking)

    
            

    forensic_analysis_prompt = f"""
            You are a digital forensics analysis engine. Using the cookie data I provide, 
            generate structured forensic outputs and a final written report. 
            COOKIE DATA (IN JSON): 
            #

            Perform the following tasks:


            1. Activity Timeline Reconstruction 
            - Convert all cookie timestamps to human‑readable format.
            - Reconstruct user activity chronologically based on creation, last access, and expiration times.
            - Identify meaningful behavioral patterns (logins, repeated visits, suspicious timing, anomalies).

            2. Session Cookie Identification
            - Detect cookies that represent authenticated sessions (e.g., sessionid, auth tokens, JWTs).
            - Flag insecure session attributes (missing HttpOnly, Secure, SameSite).
            - Highlight long‑lived or high‑risk session cookies.

            3. Suspicious Domain Flagging
            - Identify third‑party tracking domains.
            - Flag domains associated with malware, C2 infrastructure, or known abuse lists.
            - Provide reasoning for each flagged domain.
            
            4. Cross‑Browser Correlation
            - Compare cookies across Chrome, Edge, Firefox, etc.
            - Identify shared domains, identifiers, or patterns.
            - Highlight evidence of multi‑browser usage or anti‑forensic behavior.

            5. Final Forensic Report
            - Produce a structured, professional forensic report summarizing findings.

            Include sections for:

            Executive Summary

            Evidence Overview

            Timeline Analysis

            Session Analysis

            Suspicious Domains

            Cross‑Browser Correlation

            Key Findings & Recommendations

            Use clear headings, bullet points, and investigator‑friendly formatting.

            Output: Provide all analyses and the final report in one response. 
            """
    response = client.chat(forensic_analysis_prompt)
    print(response)

if __name__ == "__main__":
    main()
#End first source citied


##############################
#       Sources Citied       #
##############################
# https://thepythoncode.com/article/extract-chrome-cookies-python
#
#
#
#
#
#