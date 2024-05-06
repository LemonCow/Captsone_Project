import re
from urllib.parse import urlparse, quote, parse_qs
from urllib3.util import Retry
import xml.etree.ElementTree as ET
import nvdlib
import html
from bs4 import BeautifulSoup
import requests
from datetime import datetime
import time
from requests.adapters import HTTPAdapter
import json
import subprocess
import shutil
import pyshark
import sys
import socket
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"


def load_config(config_file):
    with open(config_file, 'r') as f:
        return json.load(f)

def test_form_for_sql_injection(path, time_value):

    config_path = path
    config = load_config(config_path)

    # Update the configuration with login URL, username, and password
    config['login_url'] = login_url
    config['username'] = username
    config['password'] = password
    config['level'] = int(level)
    config['risk'] = int(risk)
    config['forms'] = forms
    config['crawl'] = int(crawl)

    log_filename = "sqlmap_log"  # Change this to the desired log file name
    print(forms)
    if forms == "Y":
        if username != "" and password != "":
            sqlmap_command = [
                "sqlmap",
                "-u", login_url,
                "-data", f"username=\"{username}\"&password=\"{password}\"",
                "--forms",  # Specify that the target is a web form
                "--batch",  # Run SQLMap in batch mode
                "--level", level,  # Set the testing level to maximum
                "--risk", risk,  # Set the risk factor to maximum
                "--crawl", crawl,
                "-f",
                "-o",
                "--smart",
                "--threads=10",
                "--purge",
                "--flush-session",
                "--random-agent",
                "--output", log_filename,
                "--skip-waf",
                "--timeout", "60"
                ]

        else:
                sqlmap_command = [
                "sqlmap",
                "-u", login_url,
                "--forms",  # Specify that the target is a web form
                "--batch",  # Run SQLMap in batch mode
                "--level", level,  # Set the testing level to maximum
                "--risk", risk,  # Set the risk factor to maximum
                "--crawl", crawl,
                "-f",
                "-o",
                "--smart",
                "--threads=10",
                "--purge",
                "--flush-session",
                "--random-agent",
                "--output", log_filename,
                "--skip-waf",
                "--timeout", "60"
                ]
    elif forms == "N":
        if username != "" and password != "":
            sqlmap_command = [
                "sqlmap",
                "-u", login_url,
                "-data", f"username=\"{username}\"&password=\"{password}\"",
                "--batch",  # Run SQLMap in batch mode
                "--level", level,  # Set the testing level to maximum
                "--risk", risk,  # Set the risk factor to maximum
                "--crawl", crawl,
                "-f",
                "-o",
                "--smart",
                "--threads=10",
                "--purge",
                "--flush-session",
                "--random-agent",
                "--output", log_filename,
                "--skip-waf",
                "--timeout", "60"
                ]
        else:
                sqlmap_command = [
                "sqlmap",
                "-u", login_url,
                "--batch",  # Run SQLMap in batch mode
                "--level", level,  # Set the testing level to maximum
                "--risk", risk,  # Set the risk factor to maximum
                "--crawl", crawl,
                "-f",
                "-o",
                "--smart",
                "--threads=10",
                "--purge",
                "--flush-session",
                "--random-agent",
                "--output", log_filename,
                "--skip-waf",
                "--timeout", "60"
            ]

    parsed_url = urlparse(login_url)
    domain_path = parsed_url.netloc
    ipaddr = socket.gethostbyname(domain_path)
    
    packets_filename = f"{time_value}_packets.pcap"
    tcpdump_command = ["sudo", "tcpdump", "-i", "eth0", "-f", "not port 22 and host " + ipaddr, "-w", packets_filename]
    tcpdump_process = subprocess.Popen(tcpdump_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    #electric, _ = tcpdump_process.communicate()
    #print(electric.decode())

    print("SQLMap Command:")
    print(" ".join(sqlmap_command))
    process = subprocess.Popen(sqlmap_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, _ = process.communicate()

    # Decode the output from bytes to string
    output = output.decode('utf-8')
    # Split the output into lines
    lines = output.splitlines()
    
    tcpdump_process.kill()
    print("done")
    for lines in reversed(lines):
       if "[CRITICAL]" in lines or "[ERROR]" in lines:
          return lines

def read_log_file(log_file_path):
    try:
        with open(log_file_path, 'r', encoding='utf-8') as log_file:
            log_contents = log_file.read()
            return log_contents
    except FileNotFoundError:
        print(f"Log file '{log_file_path}' not found.")
        return None

def write_log_contents_to_txt(log_contents, output_filename):
    try:
        with open(output_filename, 'w', encoding='utf-8') as txt_file:
            txt_file.write(log_contents)
        print(f"Log contents written to '{output_filename}'.")
    except Exception as e:
        print(f"Error writing log contents to '{output_filename}': {str(e)}")

def extract_data_and_create_xml(file_path, time_value):
   # Open the file and read its content
   with open(file_path, 'r') as file:
       content = file.readlines()

   # Initialize empty lists to store the extracted data
   types = []
   titles = []
   payloads = []

   # Iterate over the lines
   for line in content:
       # Check if the line contains 'Type:'
       if 'Type:' in line:
           # Extract the type and add it to the list
         types.append(str(line.split('Type: ')[1].split('\n')[0]))
         # Check if the line contains 'Title:'
       elif 'Title:' in line:
           # Extract the title and add it to the list
           titles.append(str(line.split('Title: ')[1].split('\n')[0]))
       # Check if the line contains 'Payload:'
       elif 'Payload:' in line:
           # Extract the payload and add it to the list
           payloads.append(str(line.split('Payload: ')[1].split('\n')[0]))

   # Create the root element
   root = ET.Element('sql_injection_report')

   # Create the Parameter element and append it to the root
   parameter = ET.SubElement(root, 'SQL_Query')

   # Iterate over the types, titles, and payloads
   for type_, title, payload in zip(types, titles, payloads):
       # Create the SQL_Results element and append it to the Parameter
       sql_results = ET.SubElement(parameter, 'SQL_Results')

       # Create the Type, Title, and Payload elements and append them to the SQL_Results
       ET.SubElement(sql_results, 'Type').text = type_
       ET.SubElement(sql_results, 'Title').text = title
       ET.SubElement(sql_results, 'Payload').text = payload

   # Write the XML data to a file
   tree = ET.ElementTree(root)
   tree.write('/var/www/html/' + time_value + '_sql_injection_report.xml')

def find_matching_cve_entries(root):
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
    cve_ids = []
    session = requests.Session()
    
    def make_request(query):
        """Helper function to make HTTP requests."""
        url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={quote(query)}"
        try:
            response = session.get(url)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            print(f"Request failed: {e}")
            return None

    for parameter in root.findall('SQL_Query'):
        for sql_injection_result in parameter.findall('SQL_Results'):
            payload_element = sql_injection_result.find('Payload')
            title_element = sql_injection_result.find('Title')
            
            # First attempt with payload
            response = make_request(payload_element.text)
            if response is None:
                continue

            soup = BeautifulSoup(response.text, 'html.parser')
            centerpane_div = soup.find(id='CenterPane')
            first_link = centerpane_div.find('a') if centerpane_div else None
            
            if first_link:
                href = first_link.get('href')
                parsed_url = urlparse(href)
                query_params = parse_qs(parsed_url.query)
                try:
                    cve_match = cve_pattern.search(query_params['name'][0])
                except KeyError:
                    cve_match = None

                if cve_match:
                    cve_id = cve_match.group()
                    cve_ids.append(cve_id)
                else:
                    # Second attempt with title
                    response = make_request(title_element.text)
                    if response is not None:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        centerpane_div = soup.find(id='CenterPane')
                        first_link = centerpane_div.find('a') if centerpane_div else None
                        if first_link:
                            href = first_link.get('href')
                            parsed_url = urlparse(href)
                            query_params = parse_qs(parsed_url.query)
                            try:
                                cve_match = cve_pattern.search(query_params['name'][0])
                            except KeyError:
                                cve_match = None

                            if cve_match:
                                cve_id = cve_match.group()
                                cve_ids.append(cve_id)
                            else:
                                print("No CVE identifier found with title.")
            else:
                print("No hyperlink found in the 'centerpane' div.")
    return cve_ids

def write_fail(filename):

    with open(filename, 'w') as html_file:
        html_file.write('<html>\n')
        html_file.write('<head>\n')
        html_file.write('<style>')
        html_file.write('body {')
        html_file.write('    display: flex;')
        html_file.write('    flex-direction: column-reverse;')
        html_file.write('    background-color: #b8a468; /* Use a more muted background color */')
        html_file.write('    font-family: Arial, Helvetica, sans-serif;')
        html_file.write('    font-size: large;')
        html_file.write('}')
        html_file.write('header {')
        html_file.write('   font-family: "Helvetica Neue", Arial, sans-serif;')
        html_file.write('   text-align: center;')
        html_file.write('   font-size: 2em;')
        html_file.write('   margin-bottom: 150px;')
        html_file.write('   display: flex;')
        html_file.write('   justify-content: center;')
        html_file.write('   flex-direction: row;')
        html_file.write('   box-shadow:  0  2px  4px rgba(0,  0,  0,  0.1); /* Shadow for depth *//')
        html_file.write('}')
        html_file.write('.navbar {')
        html_file.write('   width:  100%;')
        html_file.write('   background-color: #452f69; /* Set the background color here */')
        html_file.write('   position: fixed; /* Optional: Use this if you want the navbar to stay at the top */')
        html_file.write('   top:  0;')
        html_file.write('   left:  0;')
        html_file.write('   z-index:  2;')
        html_file.write('}')
        html_file.write('.navbar ul {')
        html_file.write('   padding:  0;')
        html_file.write('   margin:  0;')
        html_file.write('   list-style-type: none;')
        html_file.write('} ')
        html_file.write('.navbar li {')
        html_file.write('   display: inline-block; /* Display list items horizontally */')
        html_file.write('}')
        html_file.write('.navbar a {')
        html_file.write('   display: block;')
        html_file.write('   color: white;')
        html_file.write('   text-align: center;')
        html_file.write('   padding:  14px  16px;')
        html_file.write('   text-decoration: none;')
        html_file.write('   background-color: transparent; /* Make sure the background is transparent */')
        html_file.write('   transition: background-color  0.3s ease; /* Smooth hover effect */')
        html_file.write('}')
        html_file.write('.navbar li a:hover {')
        html_file.write('   background-color: #333;')
        html_file.write('}')
        html_file.write('</style>')
        html_file.write('<title>Matching CVE Results</title>\n')
        html_file.write('</head>\n')
        html_file.write('<body>\n')
        html_file.write('<header>')
        html_file.write('<div>')
        html_file.write('<nav class="navbar">')
        html_file.write('<ul id="menuBar">')
        html_file.write('<li><a href="https://www.savi-scanneronline.com/interface.html">Home</a></li>')
        html_file.write('<li><a href="https://www.savi-scanneronline.com/about.html">About</a></li>')
        html_file.write('<li><a href="https://www.savi-scanneronline.com/documentation.html">Documentation</a></li>')
        html_file.write('<li><a href="https://www.savi-scanneronline.com/creators.html">Creators</a></li>')
        html_file.write('<li><a href="https://www.savi-scanneronline.com/feedback.html">Feedback</a></li>')
        html_file.write('</ul>')
        html_file.write('</nav>')
        html_file.write('</div>')
        html_file.write('</header>')
        html_file.write('<a href = "https://www.savi-scanneronline.com/interface.html">Click here to return</a></html>')
        html_file.write('<h2 style="padding-top: 20%">No Vulnerabilities Found. Congratulations!</h2></body>')
        html_file.write('</html>')

def write_html(url, filename, xml_path, cve_data, time_value):
    # Create a session with retries
    session = requests.Session()
    retries = Retry(
        total=50,  # Number of retries
        backoff_factor=30,  # Time to wait between retries
        status_forcelist=[500,  502,  503,  504],  # HTTP status codes to retry on
    )
    session.mount('https://', HTTPAdapter(max_retries=retries))

    tree = ET.parse(xml_path)
    root = tree.getroot()

    ids = []
    descriptions = []
    dates = []
    scores = []
    solutions = []

    for cve_id in cve_data:
        while True:
            try:
                cve_details = nvdlib.searchCVE(cveId=cve_id)[0]
                id = cve_details.id
                description = html.escape(cve_details.descriptions[0].value)
                published_date = cve_details.published
                date_obj = datetime.strptime(published_date, "%Y-%m-%dT%H:%M:%S.%f")
                formatted_date = date_obj.strftime("%Y-%m-%d")
                cve_score = cve_details.score[1]
                solution = cve_details.references[0]
                solution_url = solution.url
                ids.append(id)
                descriptions.append(description)
                dates.append(formatted_date)
                scores.append(cve_score)
                solutions.append(solution_url)
                print(id, formatted_date, cve_score, solution_url)
                break  # Exit the retry loop if request succeeds
            except requests.exceptions.RequestException as e:
                print(f"Request failed: {e}. Retrying...")
                time.sleep(15)  # Wait before retrying
    one = []
    two = []
    three = []
    encoded_payloads = [] 
    for parameter in root.findall('SQL_Query'):
        for sql_injection_result in parameter.findall('SQL_Results'):
            test = sql_injection_result.find('Payload').text
            one.append(sql_injection_result.find('Type').text)
            two.append(sql_injection_result.find('Title').text)
            three.append(sql_injection_result.find('Payload').text)

            index = test.find('=')
            if index != -1:
                modified_payload = test[index+1:]
                encoded_payload = quote(modified_payload)
                encoded_payloads.append(encoded_payload)

    capture_path = f'/var/www/html/{time_value}_packets.pcap'
    Total = []
    Unique = []
    Path = []
    Method = []
    How = []
    Content = []
    for encoded_payload in encoded_payloads:
        capture = pyshark.FileCapture(capture_path, keep_packets=False, display_filter=f"http.request.uri contains \"{encoded_payload}\"")
        for packet in capture:
            data = packet.HTTP
            try:
                Total.append((data.Request_URI, data.Request_Method, data.Request_Version, data.Content_type))
            except: 
                Total.append((data.Request_URI, data.Request_Method, data.Request_Version, "None"))
            Path.append(data.Request_URI)
            Method.append(data.Request_Method)
            How.append(data.Request_Version)
            try: 
                Content.append(data.Content_type)
            except:
                Content.append("None")

    total_dict = {}
    for uri, method, version, content_type in Total:
        if (uri, method) not in total_dict:
            total_dict[(uri, method)] = ([], [])
        total_dict[(uri, method)][0].append(version)
        total_dict[(uri, method)][1].append(content_type)

    Total_unique = [(uri, method, versions, content_types) for (uri, method), (versions, content_types) in total_dict.items()]
    if len(Total_unique) != 0:
        Path = []
        Method = []
        How = []
        Content = []
        a, b, c, d = zip(*Total_unique)
        for item in a:
            Path.append(item)
        for item in b:    
            Method.append(item)
        for item in c:
            How.append(item)
        for item in d: 
            Content.append(item)

    # Open the HTML file for writing
    with open(filename, 'w') as html_file:
        html_file.write('<html>\n')
        html_file.write('<head>\n')
        html_file.write('<style>')
        html_file.write('body {')
        html_file.write('    display: flex;')
        html_file.write('    flex-direction: column-reverse;')
        html_file.write('    background-color: #b8a468; /* Use a more muted background color */')
        html_file.write('    font-family: Arial, Helvetica, sans-serif;')
        html_file.write('    font-size: large;')
        html_file.write('}')
        html_file.write('header {')
        html_file.write('   font-family: "Helvetica Neue", Arial, sans-serif;')
        html_file.write('   text-align: center;')
        html_file.write('   font-size: 2em;')
        html_file.write('   margin-bottom: 150px;')
        html_file.write('   display: flex;')
        html_file.write('   justify-content: center;')
        html_file.write('   flex-direction: row;')
        html_file.write('   box-shadow:  0  2px  4px rgba(0,  0,  0,  0.1); /* Shadow for depth *//')
        html_file.write('}')
        html_file.write('.navbar {')
        html_file.write('   width:  100%;')
        html_file.write('   background-color: #452f69; /* Set the background color here */')
        html_file.write('   position: fixed; /* Optional: Use this if you want the navbar to stay at the top */')
        html_file.write('   top:  0;')
        html_file.write('   left:  0;')
        html_file.write('   z-index:  2;')
        html_file.write('}')
        html_file.write('.navbar ul {')
        html_file.write('   padding:  0;')
        html_file.write('   margin:  0;')
        html_file.write('   list-style-type: none;')
        html_file.write('} ')                                
        html_file.write('.navbar li {')
        html_file.write('   display: inline-block; /* Display list items horizontally */')
        html_file.write('}')
        html_file.write('.navbar a {')
        html_file.write('   display: block;')
        html_file.write('   color: white;')
        html_file.write('   text-align: center;')
        html_file.write('   padding:  14px  16px;')
        html_file.write('   text-decoration: none;')
        html_file.write('   background-color: transparent; /* Make sure the background is transparent */')
        html_file.write('   transition: background-color  0.3s ease; /* Smooth hover effect */')
        html_file.write('}')
        html_file.write('.navbar li a:hover {')                                                                                                                                                
        html_file.write('   background-color: #333;')
        html_file.write('}')
        html_file.write('.home {')
        html_file.write('    border: 2px solid black;')
        html_file.write('    margin-top: 2%;')
        html_file.write('    padding-top: 2%;')
        html_file.write('    margin-bottom: 2%;')
        html_file.write('    background-color: white;')
        html_file.write('}')
        html_file.write('table {')
        html_file.write('    margin-bottom: 5%;')
        html_file.write('    background-color: white;')        
        html_file.write('}')
        html_file.write('.done {')
        html_file.write('    display: flex;')
        html_file.write('    flex-direction: column;')
        html_file.write('}')
        html_file.write('.bar-graph {')
        html_file.write('    display: flex;')
        html_file.write('    align-items: flex-end;')
        html_file.write('    justify-content: space-around;')
        html_file.write('}')
        html_file.write('.bar {')
        html_file.write('    height: 100px;')
        html_file.write('    width: 30px;')
        html_file.write('}')
        html_file.write('.high {')
        html_file.write('    background-color: #ff6347;')
        html_file.write('}')
        html_file.write('.med {')
        html_file.write('    background-color: #ffd700;')
        html_file.write('}')
        html_file.write('.low {')
        html_file.write('    background-color: #32cd32;')
        html_file.write('}')
        html_file.write('.extra {')
        html_file.write('    background-color: gray;')
        html_file.write('}')
        html_file.write('.legend {')
        html_file.write('    display: flex;')
        html_file.write('    align-items: flex-end;')
        html_file.write('    justify-content: space-around;')
        html_file.write('}')
        html_file.write('.help {')
        html_file.write('    display: flex;')
        html_file.write('    justify-content: center;')
        html_file.write('}')
        html_file.write('</style>')
        html_file.write('<title>Matching CVE Results</title>\n')
        html_file.write('</head>\n')
        html_file.write('<body>\n')
        
        
        totalnumber = 0
        high = 0
        medium = 0
        low = 0
        extra = 0
        i = 0

        if len(root) == 0:
            html_file.write('<header>')
            html_file.write('<div>')
            html_file.write('<nav class="navbar">')
            html_file.write('<ul id="menuBar">')
            html_file.write('<li><a href="https://www.savi-scanneronline.com/interface.html">Home</a></li>')
            html_file.write('<li><a href="https://www.savi-scanneronline.com/about.html">About</a></li>')
            html_file.write('<li><a href="https://www.savi-scanneronline.com/documentation.html">Documentation</a></li>')
            html_file.write('<li><a href="https://www.savi-scanneronline.com/creators.html">Creators</a></li>')
            html_file.write('<li><a href="https://www.savi-scanneronline.com/feedback.html">Feedback</a></li>')
            html_file.write('</ul>')
            html_file.write('</nav>')
            html_file.write('</div>')
            html_file.write('</header>')
            html_file.write('<a href = "https://www.savi-scanneronline.com/interface.html">Click here to return</a></html>')
            html_file.write('<h2 style="padding-top: 20%">No Vulnerabilities Found. Congratulations!</h2></body>')
            html_file.write('</html>')
        else:
            html_file.write('<div class="done">')
            html_file.write('<h2>Vulnerabilities found and their details</h2>')
            while i < len(ids):
                
                #html_file.write('<table border="1">\n')
                #html_file.write('<tr><th>CVE ID</th><th>Description</th><th>Published Date</th><th>CVE Score</th></tr>\n')
                #html_file.write(f'<tr><td>{ids[i]}</td><td><p>{descriptions[i]}</p></td><td>{dates[i]}</td><td>{scores[i]}</td></tr>\n')
                if scores[i] == None:
                    html_file.write('<table border="1" style="border: 3px solid gray">\n')
                    html_file.write('<tr><th>CVE ID</th><th>Description</th><th>Published Date</th><th>CVE Score</th></tr>\n')
                    html_file.write(f'<tr><td>{ids[i]}</td><td><p>{descriptions[i]}</p></td><td>{dates[i]}</td><td>{scores[i]}</td></tr>\n')
                    extra += 1
                    html_file.write('<tr><td colspan="8"><p style="color: gray;">N/A Risk: This vulnerability has no given score.</p><p>\n')
                    html_file.write(f'Type: {one[i]}</p>\n')
                    html_file.write(f'<p>Title: {two[i]}</p>\n')
                    html_file.write(f'<p>Payload: {three[i]}</p>\n')
                    html_file.write(f'<p>Path: {Path[i]}</p>\n')
                    html_file.write(f'<p>Method: {Method[i]}</p>\n')
                    html_file.write('<p>Potential fixes to patch this vulnerability: </p>\n')
                    html_file.write('<ul>\n')
                    html_file.write('<li>Validate and sanitize user inputs on both the client and server sides</li>\n')
                    html_file.write('<li>Minimize the use of inline scripts and styles. Instead, use external files or define them in the header</li>\n')
                    html_file.write('<li>Encode user-generated content before rendering it in web pages</li>\n')
                    html_file.write(f'<li>More potential solutions can be found on this website: <a href="https://www.savi-scanneronline.net/sql_fixes.html">here</a></li></td></tr>\n')
                    html_file.write('</table>\n')
                
                elif 0.0 < scores[i] < 3.9:
                    html_file.write('<table border="1" style="border: 3px solid green">\n')
                    html_file.write('<tr><th>CVE ID</th><th>Description</th><th>Published Date</th><th>CVE Score</th></tr>\n')
                    html_file.write(f'<tr><td>{ids[i]}</td><td><p>{descriptions[i]}</p></td><td>{dates[i]}</td><td>{scores[i]}</td></tr>\n')
                    low += 1
                    html_file.write('<tr><td colspan="8"><p style="color: green;">Low Risk: This vulnerability has a low risk score.</p><p>\n')
                    html_file.write(f'<strong>Type:</strong> {one[i]}</p>\n')
                    html_file.write(f'<p><strong>Title:</strong> {two[i]}</p>\n')
                    html_file.write(f'<p><strong>HTTP Info:</strong></p>\n')
                    html_file.write(f'<pre>Payload: {three[i]}\n')
                    html_file.write(f'Path: {Path[i]}\n')
                    html_file.write(f'Method: {Method[i]}\n')
                    html_file.write(f'How: {How[i]}\n')
                    html_file.write(f'Content: {Content[i]}</pre>\n')
                    html_file.write(f'<p><strong>Fix for given CVE:</strong> <a href = {solutions[i]}>{solutions[i]}</a></p>\n')
                    html_file.write('<p><strong>Potential fixes to patch this vulnerability: </strong></p>\n')
                    html_file.write('<ul>\n')
                    html_file.write('<li>Validate and sanitize user inputs on both the client and server sides</li>\n')
                    html_file.write('<li>Minimize the use of inline scripts and styles. Instead, use external files or define them in the header</li>\n')
                    html_file.write('<li>Encode user-generated content before rendering it in web pages</li>\n')
                    html_file.write(f'<li>More potential solutions can be found on this website: <a href="https://www.savi-scanneronline.com/sql_fixes.html">here</a></li></td></tr>\n')
                    html_file.write('</table>\n')
                elif 4.0 < scores[i] < 6.9:
                    html_file.write('<table border="1" style="border: 3px solid orange">\n')
                    html_file.write('<tr><th>CVE ID</th><th>Description</th><th>Published Date</th><th>CVE Score</th></tr>\n')
                    html_file.write(f'<tr><td>{ids[i]}</td><td><p>{descriptions[i]}</p></td><td>{dates[i]}</td><td>{scores[i]}</td></tr>\n')
                    medium += 1
                    html_file.write('<tr><td colspan="8"><p style="color: orange;">Medium Risk: This vulnerability has a medium risk score.</p><p>\n')
                    html_file.write(f'<strong>Type:</strong> {one[i]}</p>\n')
                    html_file.write(f'<p><strong>Title:</strong> {two[i]}</p>\n')
                    html_file.write(f'<p><strong>HTTP Info:</strong></p>\n')
                    html_file.write(f'<pre>Payload: {three[i]}\n')
                    html_file.write(f'Path: {Path[i]}\n')
                    html_file.write(f'Method: {Method[i]}\n')
                    html_file.write(f'How: {How[i]}\n')
                    html_file.write(f'Content: {Content[i]}</pre>\n')
                    html_file.write(f'<p><strong>Fix for given CVE:</strong> <a href = {solutions[i]}>{solutions[i]}</a></p>\n')
                    html_file.write('<p><strong>Potential fixes to patch this vulnerability: </strong></p>\n')
                    html_file.write('<ul>\n')
                    html_file.write('<li>Validate and sanitize user inputs on both the client and server sides</li>\n')
                    html_file.write('<li>Minimize the use of inline scripts and styles. Instead, use external files or define them in the header</li>\n')
                    html_file.write('<li>Encode user-generated content before rendering it in web pages</li>\n')
                    html_file.write(f'<li>More potential solutions can be found on this website: <a href="https://www.savi-scanneronline.com/sql_fixes.html">here</a></li></td></tr>\n')
                    html_file.write('</table>\n')
                elif 7.0 < scores[i] < 10.0:
                    html_file.write('<table border="1" style="border: 3px solid red">\n')
                    html_file.write('<tr><th>CVE ID</th><th>Description</th><th>Published Date</th><th>CVE Score</th></tr>\n')
                    html_file.write(f'<tr><td>{ids[i]}</td><td><p>{descriptions[i]}</p></td><td>{dates[i]}</td><td>{scores[i]}</td></tr>\n')
                    high += 1
                    html_file.write('<tr><td colspan="8"><p style="color: red;">High Risk: This vulnerability has a high risk score.</p><p>\n')
                    html_file.write(f'<strong>Type:</strong> {one[i]}</p>\n')
                    html_file.write(f'<p><strong>Title:</strong> {two[i]}</p>\n')
                    html_file.write(f'<p><strong>HTTP Info:</strong></p>\n')
                    html_file.write(f'<pre>Payload: {three[i]}\n')
                    html_file.write(f'Path: {Path[i]}\n')
                    html_file.write(f'Method: {Method[i]}\n')
                    html_file.write(f'How: {How[i]}\n')
                    html_file.write(f'Content: {Content[i]}</pre>\n')
                    html_file.write(f'<p><strong>Fix for given CVE:</strong> <a href = {solutions[i]}>{solutions[i]}</a></p>\n')
                    html_file.write('<p><strong>Potential fixes to patch this vulnerability: </strong></p>\n')
                    html_file.write('<ul>\n')
                    html_file.write('<li>Validate and sanitize user inputs on both the client and server sides</li>\n')
                    html_file.write('<li>Minimize the use of inline scripts and styles. Instead, use external files or define them in the header</li>\n')
                    html_file.write('<li>Encode user-generated content before rendering it in web pages</li>\n')
                    html_file.write(f'<li>More potential solutions can be found on this website: <a href="https://www.savi-scanneronline.com/sql_fixes.html">here</a></li></td></tr>\n')
                    html_file.write('</table>\n')
                i += 1
            html_file.write('</div>')
            if high == 0:
                htmp = 0.1
            else:
                htmp = high

            if medium == 0:
                mtmp = 0.1
            else:
                mtmp = medium
            if low == 0:
                ltmp = 0.1
            else:
                ltmp = low
            if extra == 0:
                etmp = 0.1
            else:
                etmp = extra

            totalnumber = high + low + medium + extra
            html_file.write('<div style="background-color: white;border: 2px solid black"><h2>Guide to interpret results</h2>')
            html_file.write('<h3>What are CVE IDs?</h3>')
            html_file.write('<p>According to CVE''s offical website, A list of records each containing an identification number, a description, and at least one public reference for publicly known cybersecurity vulnerabilities. In other words, its a way to categorize known vulnerabilities. Its use hear is to show you how what the scanner found is that it is likely you have the found CVEs on your system.</p>')
            html_file.write('<h3>What do the Sql types and titles mean?</h3>')
            html_file.write('<p>The SQL Types and Titles simply show you what type of sql query is being executed on your server, and the title gives more details to how that type of sql query attack is being executed. For example, you could be given a Blind sql type which is a way to discover what type of database the backend is running. The Title will give more details as to the query category used by sqlmap, such as a title containing Mysql in it.</p>')
            html_file.write('<h3>How to interpret the HTTP Data</h3>')
            html_file.write('<p>The Http data show what the data transfer from the scanner to the target looks like in packet form. It shows you what type of request is used, what the payload specifically was instead of just the Type or title, and some other details.</p>')
            html_file.write('</div>') 
            html_file.write('<div class="home">')
            html_file.write('<h2>Graph results</h2>')
            html_file.write('<div class="bar-graph">')
            html_file.write(f'        <div class="bar high" style="height: {(htmp / totalnumber) * 200};"></div>')
            html_file.write(f'        <div class="bar med"" style="height: {(mtmp / totalnumber) * 200};"></div>')
            html_file.write(f'        <div class="bar low" style="height: {(ltmp  / totalnumber) * 200};"></div>')
            html_file.write(f'        <div class="bar extra" style="height: {(etmp  / totalnumber) * 200};"></div>')
            html_file.write('</div>')
            html_file.write('<div class="legend">')
            html_file.write(f'<div>High Risk: {high}</div>')
            html_file.write(f'<div>Medium Risk: {medium}</div>')
            html_file.write(f'<div>Low risk: {low}</div>')
            html_file.write(f'<div>N/A risk: {extra}</div>')
            html_file.write('</div>')
            html_file.write(f'<p class="help">Total number of vulnerabilites found:  {totalnumber}</p>')
            html_file.write('</div>')
            html_file.write('<div>')
            html_file.write('<header>')
            html_file.write('<div class="navbar">')
            html_file.write('<nav>')
            html_file.write('<ul id="menuBar">')
            html_file.write('<li><a href="https://www.savi-scanneronline.com/interface.html">Home</a></li>')
            html_file.write('<li><a href="https://www.savi-scanneronline.com/about.html">About</a></li>')
            html_file.write('<li><a href="https://www.savi-scanneronline.com/documentation.html">Documentation</a></li>')
            html_file.write('<li><a href="https://www.savi-scanneronline.com/creators.html">Creators</a></li>')
            html_file.write('<li><a href="https://www.savi-scanneronline.com/feedback.html">Feedback</a></li>')
            html_file.write('</ul>')
            html_file.write('</nav>')
            html_file.write('</div>')
            html_file.write('</header>')
            html_file.write(f'<h1>Scan results for: {url}</h1>\n')
            html_file.write('<p>Once you leave this page, the results will be lost</p>')
            html_file.write('<form action="https://www.savi-scanneronline.com:5000/download" method="get">')
            html_file.write(f'<button type="submit" name="file_type" value="sql-html_{time_value}">Download HTML File</button>')
            html_file.write(f'<button type="submit" name="file_type" value="sql-xml_{time_value}">Download XML File</button>')
            html_file.write(f'<button type="submit" name="file_type" value="sql-pcap_{time_value}">Download PCAP File</button>')
            html_file.write('</form>')
            html_file.write('</div>')
            html_file.write('</body>\n')
            html_file.write('</html>\n')

if __name__ == "__main__":
    
    
    if len(sys.argv) < 1:
        print("Need time value")
        sys.exit(1)

    time_value = sys.argv[1]

    config_path = "/var/www/html/config.json"
    config = load_config(config_path)

    login_url = config['login_url']
    username = config['username']
    password = config['password']
    level = config['level']
    risk = config['risk']
    forms = config['forms']
    crawl = config['crawl']

    parsed_url = urlparse(login_url)
    domain_path = parsed_url.netloc
    print(domain_path)
    
    path = f'/var/www/html/{time_value}_sql_injection_report.xml'

    try:
        result = test_form_for_sql_injection("/var/www/html/config.json", time_value)
        print(result)
        if "[ERROR]" in result or "[CRITICAL]" in result:
            with open(f'/var/www/html/{time_value}_Results.txt', 'w', encoding='utf-8') as results_txt_file:
                results_txt_file.write('')
                results_txt_file.write(result)
    except Exception as e:
            print("Oof")

    if login_url.find("http://"):
        temp = urlparse(login_url).netloc
    elif login_url.find("https://"):
        temp = urlparse(login_url).netloc

    if login_url.find(":"):
        new = temp.split(":")
        newnew = new[0]
        temp = newnew
    
    
    try:
        results_txt_path = f'/var/www/html/sqlmap_log/{temp}/log'
        with open(results_txt_path, 'r', encoding='utf-8') as results_txt_file:
            log_contents = results_txt_file.read()

        if log_contents:
            print("Log file contents:")
            write_log_contents_to_txt(log_contents, f'/var/www/html/{time_value}_Results.txt')

        extract_data_and_create_xml(f'/var/www/html/{time_value}_Results.txt', time_value)


        tree = ET.parse(path)
        root = tree.getroot()

        cve_ids = find_matching_cve_entries(root)

        # Assuming write_html can handle a list of dictionaries
        write_html(domain_path, "/var/www/html/" + time_value + "_matching_cve_results.html", path, cve_ids, time_value)

        shutil.rmtree("sqlmap_log")

    except Exception as e:
        if result is not None:
            if "[ERROR]" in result or "[CRITICAL]" in result or "[WARNING]" in result:
                with open(f'/var/www/html/{time_value}_Results.txt', 'w', encoding='utf-8') as results_txt_file:
                    results_txt_file.write('')
                    print(results_txt_file.write(result))
                    print(result)
            else:
                print("Skip")
        else:
            with open(f'/var/www/html/{time_value}_Results.txt', 'w', encoding='utf-8') as results_txt_file:
                    results_txt_file.write('')
            write_fail("/var/www/html/" + time_value + "_matching_cve_results.html")
            print("Write fail done")

        


