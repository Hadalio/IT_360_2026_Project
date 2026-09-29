import os
import json
import requests

#This is designed to be a class framework of API calls engaging with Ollama 


class Ollamaclient:
    ##############################################################
    #           Start the frame for the class                    #
    ##############################################################

    #Build the constructor
    def __init__(self, url: str, api_key: str, model: str,timeout: int = 180, history_file="history.json" ):
        self.url = url
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.history_file = history_file

        #Load converation history if it exists
        self.history = self._load_history() 


    #Handle the authentication through the headers
    def _headers(self) -> dict:
        headers = {
        'Authorization': f'Bearer {self.api_key}',
        'Content-Type': 'application/json'
        }
        return headers
    
    #Load any history if the file exists
    def _load_history(self):
        if os.path.exists(self.history_file):
            with open(self.history_file, "r") as f:
                return json.load(f)
        return []   #Return history 
    
    #Save any history to the file
    def _save_history(self):
        with open(self.history_file, "w") as f:
            json.dump(self.history, f, indent=2)

    #Usde to store summaries and not whole responses. This will help handle duplicate outputs due to how history is functioning. 
    def remember(self, content: str):
        #Store only the high level summaries, not raw scan data
        self.history.append({"role": "system", "content": content})
        self._save_history()
    
    ##############################################################
    #               Start of core chat methodoly                 #
    ##############################################################

    def chat(self, message: str, temperature: float = 0.2) -> str:
        endpoint_url = f"{self.url}/api/chat/completions"

        #Add the message to history 
        self.history.append({"role": "user", "content": message})

        data = {
            "model" : self.model,
            "messages": self.history, 
            "temperature" : temperature
        }

        try:
            response = requests.post(
                endpoint_url,
                headers = self._headers(), 
                json = data, 
                timeout = self.timeout
            )
            response.raise_for_status()
            payload = response.json()

            reply = payload["choices"][0]["message"]["content"]

            #Use the assistant for reply
            self.history.append({"role": "assistant", "content": reply})

            #Save the new updated history
            self._save_history()

            return reply 
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Ollama API request failed: {e}")     #show me the error!
        
    #Resets the chat history 
    def reset(self):
        self.history =[]   #Create new empty history
        self._save_history()    # Save the new empty history

    def trim_history(self, keep_pairs: int = 2):
        """
        Called at the end of each scan run to prevent history bloat.
        Keeps ALL system messages (summaries) and only the most recent
        user/assistant pairs.
    
        keep_pairs — how many recent user/assistant exchanges to keep
        """
        system_messages = [m for m in self.history if m.get("role") == "system"]
    
        # Get only user/assistant messages
        conversational = [m for m in self.history if m.get("role") != "system"]
    
        # Keep only the last N pairs (each pair = 1 user + 1 assistant = 2 messages)
        keep_count = keep_pairs * 2
        trimmed_conversational = conversational[-keep_count:] if len(conversational) > keep_count else conversational
    
        # Rebuild history: summaries first, then recent exchanges
        self.history = system_messages + trimmed_conversational
        self._save_history()
    
        removed = len(conversational) - len(trimmed_conversational)
        print(f"[+] History trimmed — removed {removed} old messages, kept {len(self.history)} total")