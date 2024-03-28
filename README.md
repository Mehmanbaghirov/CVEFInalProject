# Project Name: CVE Report Generator

## Description
The CVE Report Generator is a tool designed to fetch and compile information about Common Vulnerabilities and Exposures (CVE) from various databases and generate a comprehensive report. It fetches data such as CVE ID, Common Weakness Enumeration (CWE) ID, Common Platform Enumeration (CPE) Name, CVSS v2 and v3 metrics, severity, and last modified date. Additionally, it searches for exploit scripts related to the CVE and includes them in the report if available.

## Dependencies
- Python 3.x
- requests
- beautifulsoup4
- fpdf
- python-docx

## Instructions for Running the Project
1. Clone the repository from [GitHub]([https://github.com/your_username/repo_name](https://github.com/Mehmanbaghirov/CVEFInalProject.git)).
2. Navigate to the project directory.
3. Install the required dependencies using pip:

## pip install -r requirements.txt
4. Run the `cve.py` script:

## python cve.py
5. Follow the prompts to enter the CVE ID.
6. The program will fetch the CVE data, generate a report, and save it in PDF, DOCX, and MD formats in the `REPORTS` directory.

## Group Members and Roles
- Mehman Baghirov - Project Lead, Backend Development
- Sema Aydemirli - Data Scraping, Documentation
- Vasif -  Development, Report Formatting
- Vural Ahmadli - Data Scraping, Documentation  

## Additional Instructions
- The report includes top references such as NIST NVD, Exploit DB, MITRE CVE Database, Vulners Database, and Vulmon Database.
- If an exploit script is available for the CVE, its link will be included in the report.
- The report is saved in PDF, DOCX, and MD formats for convenience.
- For any issues or suggestions, please open an issue on GitHub.


