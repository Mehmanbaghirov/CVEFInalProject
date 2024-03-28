import requests
from bs4 import BeautifulSoup
import webbrowser
import sqlite3
from fpdf import FPDF
from docx import Document  # Changed import to avoid conflict
import os

# Mehman's Part
# Function to create SQLite database and table
def create_database():
    conn = sqlite3.connect('cve_database.db')
    c = conn.cursor()
    
    # Create CVE table if not exists
    c.execute('''CREATE TABLE IF NOT EXISTS cve_info
                 (cve_id TEXT PRIMARY KEY,
                  cwe_id TEXT,
                  cpe_name TEXT,
                  cvss_v2_metrics REAL,
                  cvss_v2_severity TEXT,
                  cvss_v3_metrics REAL,
                  cvss_v3_severity TEXT,
                  last_mod_date TEXT)''')
    
    conn.commit()
    conn.close()

# Function to insert data into SQLite database
def insert_data(cve_info):
    conn = sqlite3.connect('cve_database.db')
    c = conn.cursor()
    
    # Insert CVE data
    c.execute('''INSERT OR REPLACE INTO cve_info
                 (cve_id, cwe_id, cpe_name, cvss_v2_metrics, cvss_v2_severity,
                  cvss_v3_metrics, cvss_v3_severity, last_mod_date)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
              cve_info)
    
    conn.commit()
    conn.close()

# Function to retrieve data from SQLite database
def get_data(cve_id):
    conn = sqlite3.connect('cve_database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM cve_info WHERE cve_id=?", (cve_id,))
    data = c.fetchone()
    conn.close()
    return data


# Vasif's Part
# Function to prompt user input
def get_user_input():
    cve_id = input("Enter CVE ID: ")
    return cve_id

# Function to scrape data from NIST NVD
def scrape_nist_nvd(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        cve_data = response.json()
        if 'vulnerabilities' in cve_data:
            return parse_cve_data(cve_data)
        else:
            print("Failed to retrieve CVE data from NIST NVD.")
    else:
        print("Failed to fetch data from NIST NVD.")
    return None, None, None, None, None, None, None, None

# Vural's Part
# Function to parse CVE data
def parse_cve_data(cve_data):
    if not cve_data or 'vulnerabilities' not in cve_data:
        print("Invalid CVE data format.")
        return None, None, None, None, None, None, None, None
    
    try:
        cve_info = cve_data['vulnerabilities'][0]['cve']
        cve_id = cve_info['id']
        
        descriptions = cve_info['descriptions']
        cwe_id = "N/A"  # Default value if CWE ID is not found
        for description in descriptions:
            if 'cwe' in description:
                cwe_id = description['cwe']['id']
                break
        
        configurations = cve_info.get('configurations', [])
        cpe_name = "N/A"  # Default value if CPE Name is not found
        if configurations:
            nodes = configurations[0].get('nodes', [])
            if nodes:
                cpe_match = nodes[0].get('cpeMatch', [])
                if cpe_match:
                    cpe_name = cpe_match[0].get('criteria', "N/A")

        cvss_v2_metrics = "N/A"
        cvss_v2_severity = "N/A"
        cvss_v3_metrics = "N/A"
        cvss_v3_severity = "N/A"

        metrics = cve_info.get('metrics', {})
        cvss_v2 = metrics.get('cvssMetricV2', [])
        if cvss_v2:
            cvss_v2_metrics = cvss_v2[0].get('cvssData', {}).get('baseScore', "N/A")
            cvss_v2_severity = cvss_v2[0].get('baseSeverity', "N/A")

        cvss_v3 = metrics.get('cvssMetricV3', [])
        if cvss_v3:
            cvss_v3_metrics = cvss_v3[0].get('cvssData', {}).get('baseScore', "N/A")
            cvss_v3_severity = cvss_v3[0].get('baseSeverity', "N/A")
        
        last_mod_date = cve_info.get('lastModified', "N/A")

        return cve_id, cwe_id, cpe_name, cvss_v2_metrics, cvss_v2_severity, cvss_v3_metrics, cvss_v3_severity, last_mod_date
    
    except KeyError as e:
        print(f"Error parsing CVE data: {e}")
        return None, None, None, None, None, None, None, None

# Sema's Part
# Function to open top references
def open_top_references(cve_id):
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
    references = [
        ("NIST NVD", f"https://nvd.nist.gov/vuln/detail/{cve_id}"),
        ("Exploit DB", f"https://www.exploit-db.com/search?cve={cve_id}"),
        ("MITRE CVE Database", f"https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-{cve_id}"),
        ("Vulners Database", f"https://vulners.com/search?query={cve_id}"),
        ("Vulmon Database", f"https://vulmon.com/vulnerabilitydetails?qid={cve_id}")
    ]
    for ref_name, url in references:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print(f"Opening {ref_name} link: {url}")
            webbrowser.open_new_tab(url)
        else:
            print(f"Failed to open {ref_name} link: {url}, Status code: {response.status_code}")

# Mehman's Part
# Function to check exploit script availability
def check_exploit_script(cve_id):
    url = f"https://ubuntu.com/security/cves/{cve_id}.json"
    response = requests.get(url)
    if response.status_code == 200:
        cve_info = response.json()
        if cve_info:
            print("CVE Information:")
            print(f"CVE ID: {cve_info.get('id', 'N/A')}")
            description = cve_info.get('description', 'N/A')
            print(f"Description: {description}")
            impact = cve_info.get('impact', {}).get('baseMetricV3', {}).get('baseSeverity', 'N/A')
            print(f"Impact: {impact}")
            cvss3_score = cve_info.get('cvss3', 'N/A')
            print(f"CVSS3 Score: {cvss3_score}")
            mitigation = cve_info.get('mitigation', 'N/A')
            print(f"Mitigation: {mitigation}")
            print("References:")
            for reference in cve_info.get('references', []):
                print(f"- {reference}")
            print("Related Bugs:")
            bugs = cve_info.get('bugs', [])
            if bugs:
                for bug in bugs:
                    print(f"- {bug}")
            else:
                print("No related bugs found.")
            print("Related Notices:")
            for notice in cve_info.get('notices', []):
                print(f"- {notice['title']}")
            # Add more fields as needed
        else:
            print("CVE information not found.")
    else:
        print(f"Failed to check exploit script. Status code: {response.status_code}")


# Vasif's Part
# Function to check for the availability of an exploit script on Exploit DB
def check_exploit_script(cve_id):
    url = f"https://www.exploit-db.com/search?cve={cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        # Check if exploit script exists
        exploit_link = soup.find('a', {'class': 'exploit-link'})
        if exploit_link:
            return exploit_link['href']
    return None



# Vural and Sama's Part
def generate_report(cve_id, cwe_id, cpe_name, cvss_v2_metrics, cvss_v2_severity, cvss_v3_metrics, cvss_v3_severity, last_mod_date, exploit_links, exploit_script_link):
    report = ""
    report += f"CVE ID: {cve_id}\n"
    report += f"CWE ID: {cwe_id}\n"
    report += f"CPE Name: {cpe_name}\n"
    report += f"CVSS v2 Metrics: {cvss_v2_metrics}\n"
    report += f"CVSS v2 Severity: {cvss_v2_severity}\n"
    report += f"CVSS v3 Metrics: {cvss_v3_metrics}\n"
    report += f"CVSS v3 Severity: {cvss_v3_severity}\n"
    report += f"Last Modified Date: {last_mod_date}\n"
    report += "Opening top references...\n"

    # Add top references links to the report
    report += "Top References:\n"
    for ref_name, url in [("NIST NVD", f"https://nvd.nist.gov/vuln/detail/{cve_id}"),
                          ("Exploit DB", f"https://www.exploit-db.com/search?cve={cve_id}"),
                          ("MITRE CVE Database", f"https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-{cve_id}"),
                          ("Vulners Database", f"https://vulners.com/search?query={cve_id}"),
                          ("Vulmon Database", f"https://vulmon.com/vulnerabilitydetails?qid={cve_id}")]:
        report += f"{ref_name}: {url}\n"

    # Add exploit links to the report
    if exploit_links:
        report += "\nExploit References:\n"
        exploit_references = "\n".join([f"- {link}" for link in exploit_links])
        report += f"{exploit_references}\n"

    # Add exploit script link to the report
    if exploit_script_link:
        report += f"Exploit Script Link: {exploit_script_link}\n"

    # Create directory structure
    directory = os.path.join("REPORTS", cve_id)
    if not os.path.exists(directory):
        os.makedirs(directory)

    # Save report to files inside the directory
    pdf_file = os.path.join(directory, f"{cve_id}_Report.pdf")
    docx_file = os.path.join(directory, f"{cve_id}_Report.docx")
    md_file = os.path.join(directory, f"{cve_id}_Report.md")

    with open(pdf_file, "w") as pdf:
        pdf.write(report)

    with open(docx_file, "w") as docx:
        docx.write(report)

    with open(md_file, "w") as md:
        md.write(report)

    print("Report saved successfully.")

    return report  # Return the report if needed for further processing



def main():
    create_database()  # Create database if not exists
    cve_id = get_user_input()
    
    # Check if data exists in database
    data = get_data(cve_id)
    if data:
        print("Data found in database.")
        cve_id, cwe_id, cpe_name, cvss_v2_metrics, cvss_v2_severity, cvss_v3_metrics, cvss_v3_severity, last_mod_date = data
    else:
        print("Data not found in database. Fetching from NIST NVD...")
        cve_id, cwe_id, cpe_name, cvss_v2_metrics, cvss_v2_severity, cvss_v3_metrics, cvss_v3_severity, last_mod_date = scrape_nist_nvd(cve_id)
        if cve_id:
            insert_data((cve_id, cwe_id, cpe_name, cvss_v2_metrics, cvss_v2_severity, cvss_v3_metrics, cvss_v3_severity, last_mod_date))
    
    if cve_id:
        exploit_links = open_top_references(cve_id)
        exploit_script_link = check_exploit_script(cve_id)  # Check for exploit script link
        report = generate_report(cve_id, cwe_id, cpe_name, cvss_v2_metrics, cvss_v2_severity, cvss_v3_metrics, cvss_v3_severity, last_mod_date, exploit_links, exploit_script_link)
        print(report)

if __name__ == "__main__":
    main()
