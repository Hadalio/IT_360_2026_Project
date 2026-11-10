import json
import requests


#This is intended to be a framework for interacting with Ollama via API
class OllamaClient:

    #Build the constructor
    def __init__(self, url, api_key, model, timeout = 180):
        self.url = url
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    #Handle the authentication through the headers
    def chat_ai(self, message):

        #Build POST | Provide requirements from self
        response = requests.post(f"{self.url}/api/chat/completions",

        #Build the headers | See example_1.py (Source: AnonymousGroundHog)
        headers = {
        'Authorization': f'Bearer {self.api_key}',
        'Content-Type': 'application/json'
        },

        #Build json requirement
        json = {
            'model': self.model,
            'messages': [
                {
                    "role": "user",
                    "content": message
                }
            ]
        },

        timeout = self.timeout
        ) # End POST

        #Prepare payload 
        payload = response.json()

        #Return payload
        return payload["choices"][0]["message"]["content"]

    #Create a report using the Ai by passing through the findings "evidence" from the cookies. 
    def generate_report(self, findings):

        #Intialize the prompt and include the "evidence"
        prompt = f"""
            You are a Senior Digital Forensic Examiner
            Analyze ONLY the provide evidence.
            DO NOT INVENT FINDINGS.

            Evidence: 
            {json.dumps(findings, indent = 2)}

            Generate the following inteded for documenting observations and investigative leads:
            1. Executive Summary
            2. Examination Scope
                - What artifacts were analyzed
                - How many artifacts were analyzed
                - Browsers analyzed
            3. Significant Findings
                - Authentication activity
                - Session artifacts
                - Browser correlation findings
                - Tracking infrastructure
                - Fingerprinting infrastructure
                - Suspicious domains
            4. Timeline Analysis
                - Chronological observations from cookie creation timestamps
                - Any notable clusters of timestamps
            5. User Activity Assessment
                - Sites and services analyzed
                - Multi-browser authentication activities
                - Suspicious browsing patterns 
            6. Indicators of Concern
                - Known malicious domains
                - Suspicious TLDs
                - Insecure authentication cookies
                - Long lived authentication tokens 
            7. Investigative leads 
                - Artifacts that require further analysis
                - Domains that warrant additional analysis
                - Accounts or sessions that may warrant a follow up
            8. Conclussions
            """

        return self.chat_ai(prompt)