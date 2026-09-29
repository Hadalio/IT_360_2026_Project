class ReportBuilder:
    def build_report(self, findings):
        
        return {
            "summary": "Automated Forensic Analysis Completed",
            "findings": findings,
            "flags": self.extract_flags(findings)

        }

    def extract_flags(self, findings):
        flags = []
        for section in findings.values():
            if "flags" in section:
                flags.extend(section["flags"])
        return flags 

        