from forensic_tool import CookieScope
from ollama_client import OllamaClient
from cookie_extractor import CookieExtractor
import customtkinter as ctk
import json 
import os 


#Overall Gui theme 
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")



#Class constructor 
class CookieScopeGui(ctk.CTk):

    def __init__(self):
        super().__init__()

        #Creates a title for the "window" Gui
        self.title("CookieScope")

        #Establish frame size 
        self.geometry("1200x700")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        #Call the sidebar function | call a custom function as a "sidebar" is really a narrow frame
        self.create_sidebar()
        #Call main frame function and create it. 
        self.create_main_frame()

        self.status_label = ctk.CTkLabel(self, text="Ready")

        self.status_label.grid(row=1, column=0, columnspan=2, pady=5)

    #Build the sidebar here 
    def create_sidebar(self):

        #Create the frame 
        self.sidebar = ctk.CTkFrame(self, width = 250)

        #Creates a grid within frame 
        self.sidebar.grid(row=0, column=0, sticky = "ns" )

        #Creates a title using 24 size font in Arial Bold
        self.sidebar_title = ctk.CTkLabel(self.sidebar, text="CookieScope", font=("Arial", 24, "bold"))

        self.subtitle = ctk.CTkLabel(self.sidebar, text="Automated Browser Cookie \n Forensic Analysis")
        #Package the title of widget into Frame widget | .pack() handles that.
        self.sidebar_title.pack(pady=20)

        self.subtitle.pack(pady=5)

        #Add a button to analyze cookies which when clicked calls run_analysis -> CookieScope tools 
        self.analyze_button = ctk.CTkButton(self.sidebar, text="Acquire & Analyze Cookies", command=self.run_analysis)

        #Package the button into the sidebar widget 
        self.analyze_button.pack(padx=20, pady=10, fill="x")

        #A button to generate ai report which when clicked calls generate_report -> OllamaClient 
        self.report_button = ctk.CTkButton(self.sidebar, text="Generate Forensic Report", command=self.generate_report)

        #Package button into sidebar widget again
        self.report_button.pack(padx=20, pady=10, fill="x")

        #Create an export button 
        self.export_button = ctk.CTkButton(self.sidebar, text="Export Report", command=self.export_report)

        self.export_button.pack(padx=20, pady=10, fill="x")


    def create_main_frame(self):

        #Create the main frame | Largest frame to left as sidebar is for buttons / widgets 
        self.main_frame = ctk.CTkFrame(self)

        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        self.tabs = ctk.CTkTabview(self.main_frame)

        self.tabs.pack(fill="both", expand=True)

        #Add the tabs individually
        self.tabs.add("Dashboard")
        self.tabs.add("Cookie Timeline")
        self.tabs.add("Sessions")
        self.tabs.add("Browser Correlations")
        self.tabs.add("Forensic Report")

        self.dashboard_box = ctk.CTkTextbox(self.tabs.tab("Dashboard"))

        self.dashboard_box.pack(fill="both", expand=True)

        self.timeline_box = ctk.CTkTextbox(self.tabs.tab("Cookie Timeline"))

        self.timeline_box.pack(fill="both", expand=True)

        self.sessions_box = ctk.CTkTextbox(self.tabs.tab("Sessions"))

        self.sessions_box.pack(fill="both", expand=True)

        self.correlation_box = ctk.CTkTextbox(self.tabs.tab("Browser Correlations"))

        self.correlation_box.pack(fill="both", expand=True)

        self.report_box = ctk.CTkTextbox(self.tabs.tab("Forensic Report"))

        self.report_box.pack(fill="both", expand=True)


    def run_analysis(self):

        self.status_label.configure(text="Analyzing Cookie Evidence...")
        self.update()
        try:
            #Intialize Tool
            tool = CookieScope()

            extractor = CookieExtractor()

            cookies = extractor.extract_all()

            #Use the first one if ai not handling cookies analysis well | json file is much smaller 
            #self.results = tool.run_all_modules("cookies.json")
            self.results = tool.run_all_modules(cookies)
            self.results_findings = tool.build_report_findings(self.results)

            #Create nice formated cookie analysis results to output in outbox
            cookies = self.results.get("cookies", {})
            timeline = self.results.get("timeline", [])
            sessions = self.results.get("sessions", {})
            correlations = self.results.get("correlations", {})
            stats = self.results.get("stats", {})
            active_sessions = len(sessions.get("active_sessions", []))
            insecure_sessions = len(sessions.get("insecure_sessions", []))
            long_lived_sessions = len(sessions.get("long_lived_sessions", []))

            #Estbalish a risk score 
            risk_score = 0

            risk_score += len(sessions.get("insecure_sessions", [])) * 5

            risk_score += len(correlations) * 2

            if risk_score >= 50:
                risk_level = "Critical"
            elif risk_score >= 30:
                risk_level = "High"
            elif risk_score >= 10:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            #A beautified dashboard results view rather than raw json dump
            dashboard = f"""
        ============================
            CookieScope Dashboard                    
        ============================

        Evidence Summary
        ----------------
        Total Cookies Analyzed:
        {cookies.get('total_cookies', 'N/A')}

        Timeline of Events:
        {len(timeline)}

        Browser Statistics:
        -------------------
        {json.dumps(stats, indent=4)}
        

        Authentication Events
        ---------------------
        Active Sessions:
        {active_sessions}

        Insecure Sessions:
        {insecure_sessions}

        Long-Lived Sessions:
        {long_lived_sessions}

        Cross Browser Correlations
        --------------------------
        Domains Appearing in Multiple Browsers:
        {len(correlations)}

        Overall Risk Assessment:
        {risk_level}
        """
            #Show status after dashboard results run
            self.status_label.configure(text="Analysis Complete")

            self.dashboard_box.delete("1.0", "end")
            self.dashboard_box.insert("end", dashboard)

            timeline_text = ""

            for event in timeline:
                timeline_text += (f"{event.get('timestamp', 'Unknown')}\n"
                                  f"Domain: {event.get('domain', 'Unknown')}\n"
                                  f"Event: {event.get('event', 'Unknown')}\n"
                                  f"{'-' * 50}\n")

            self.timeline_box.delete("1.0", "end")

            self.timeline_box.insert("end", timeline_text)

            self.sessions_box.delete("1.0", "end")

            self.sessions_box.insert("end", json.dumps(sessions, indent=4))

            #Intalize variable for browser correlation 
            correlation_text = ""
            #Add data to the varialbe from the found correlations
            for domain, browsers in correlations.items():
                correlation_text += (f"{domain}\n"
                                     f"Browsers: "
                                     f"{', '.join(browsers)}\n\n")
            #Make sure the box empty 
            self.correlation_box.delete("1.0", "end")
            #Insert the texzt into the outbot
            self.correlation_box.insert("end", correlation_text)



                                

        #Error handling 
        except Exception as e:
            self.dashboard_box.delete("1.0", "end")

            self.dashboard_box.insert("end", f"Analysis Error:\n\n{e}")




    #function which uses the OllamaClient to generate report using the cookie results | Prompt for ai is on ollama_client.py 
    def generate_report(self):
        #If the generate button is pressed before cookies were analyzed there will be an error. Handle it by validating the results are populated. 
        #If not populated then inform user to run Cookie Analysis first.
        if not hasattr(self, "results"):

            self.report_box.delete("1.0", "end")
            self.report_box.insert("end", "Please run the Cookie Analysis before generating a report.")

            #Let user try again
            return 

        self.status_label.configure(text="Generating Forensic Report")
        self.update()
        
        try:
            #Initalize client
            client = OllamaClient(url="http://sushi.it.ilstu.edu:8080", api_key=os.environ.get("API_KEY"), model="llama3.3:latest")

            #Feed results to client for report generation
            report_data = {
                "cookie_summary": self.results["cookies"]["total_cookies"],
                "flags": self.results["cookies"]["flags"],
                "third_party_count": len(self.results["cookies"]["third_party"]),
                "sus_count": len(self.results["cookies"]["suspcious"]),
                "sample_sus": self.results["cookies"]["suspcious"][:20],
                "sessions": self.results["sessions"],
                "stats": self.results["stats"],
                "correlations": {
                    "count": len(self.results["correlations"]),
                    "examples": list(self.results["correlations"].items())[:20]
                },
                "timeline_summary": {
                    "event_count": len(self.results["timeline"]),
                    "first_100_events": self.results["timeline"][:100]
                }
            }

            payload = json.dumps(report_data, indent=2)
            print(f"Report size: {len(payload),}")
            print("Sus:", len(self.results["cookies"]["suspcious"]))
            print("3rd party:", len(self.results["cookies"]["third_party"]))
            print("Timeline:", len(self.results["timeline"]))
            report = client.generate_report(self.results_findings)

            self.status_label.configure(text="Forensic Report Ready")

            self.report_box.delete("1.0", "end")

            #Output results in output box 
            self.report_box.insert("end", report)

        #error handling in event OllamaClient has issues. 
        except Exception as e:
            self.report_box.delete("1.0", "end")
            
            self.report_box.insert("end", f"Report Generation Error:\n\n{e}")
            
        
    def export_report(self):

        report = self.report_box.get("1.0", "end")

        with open("forensic_report.txt", "w", encoding="utf-8") as f:
            f.write(report)
        self.status_label.configure(text="Report Exported")


if __name__ == "__main__":
    app = CookieScopeGui()

    app.mainloop()