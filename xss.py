import re
import subprocess
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
import socket
import sys

def load_config(config_file):
    with open(config_file, 'r') as f:
        return json.load(f)
    
def test_form_for_xss_injection(path, time_value):
    
    parsed_url = urlparse(login_url)
    domain_path = parsed_url.netloc
    ipaddr = socket.gethostbyname(domain_path)
    packets_filename = f"{time_value}_packets2.pcap"
    tcpdump_command = ["sudo", "tcpdump", "-i", "eth0", "-f", "not port 22 and host " + ipaddr, "-w", packets_filename]
    tcpdump_process = subprocess.Popen(tcpdump_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    
    command = ['wapiti', '-u', login_url, '-l', '2', '-f', 'xml', '-m', 'xss,permanentxss', '--o', f'{time_value}_XSSReport.xml', 
            '--flush-attacks', '--flush-session', '--max-scan-time', '30', '--max-attack-time', '30']    
    print(" ".join(command))
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, _ = process.communicate()
    tcpdump_process.kill()
    
    print("done")


def parse_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    return root

def find_entries(root):
    xpath_expression = "./vulnerabilities/vulnerability[@name='Cross Site Scripting']/entries/entry"
    entries = root.findall(xpath_expression)
    if not entries:
        print("No entries found for Cross Site Scripting vulnerabilities.")
        return []
    
    return entries

def make_request(query):
    url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={quote(query)}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None

def find_matching_cve_entries(entries):
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
    cve_ids = []
    
    for entry in entries:
        path = entry.find('path').text
        parameter = entry.find('parameter').text
        response = make_request("XSS " + path + " parameter " + parameter)
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
                print("No CVE identifier found with payload.")
    return cve_ids

def is_capitalized(word):
    return word[0].isupper()

def write_html(url, filename, xml_path, cve_data, time_value):
    # Create a session with retries
    session = requests.Session()
    retries = Retry(
        total=50,  # Number of retries
        backoff_factor=15,  # Time to wait between retries
        status_forcelist=[403, 500,  502,  503,  504],  # HTTP status codes to retry on
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
        html_file.write('.shrink {')
        html_file.write('    width: 50%;')
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
        html_file.write('pre {')
        html_file.write('    font-size: medium;')
        html_file.write('}')
        html_file.write('</style>')
        html_file.write('<title>Matching CVE Results</title>\n')
        html_file.write('<body>\n')

        totalnumber = 0
        high = 0
        medium = 0
        low = 0
        extra = 0
        i = 0

        one = []
        two = []
        five = []
        six = []
        seven = []
        help = find_entries(root)
        if help == []:
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
            html_file.write('<a href = "https://www.savi-scanneronline.com/interface.html" >Click here to return</a></html>')
            html_file.write('<h2 style="padding-top: 20%">No Vulnerabilities Found. Congratulations!</h2></body>')
            html_file.write('</html>')
        else:
            html_file.write('<div class="done">')
            html_file.write('<h2>Vulnerabilities found and their details</h2>')
            for entry in help:
                one.append(entry.find('method').text)
                two.append(entry.find('path').text)
                five.append(entry.find('info').text)
                six.append(entry.find('http_request').text.strip() if entry.find('http_request') is not None else "")
                seven.append(entry.find('curl_command').text.strip() if entry.find('curl_command') is not None else "")    
            while i < len(ids):
               
                content = six[i]

                words = content.split()
                
                formatted_parts = []
                for index, word in enumerate(words):
                    if index + 1 < len(words) and is_capitalized(words[index + 1]):
                        formatted_parts.append(word + "<br>")
                    else:
                        formatted_parts.append(word + " ")

                formatted_content = "".join(formatted_parts)
                

                if scores[i] == None:
                    html_file.write('<table border="1" style="border: 3px solid gray">\n')
                    html_file.write('<tr><th>CVE ID</th><th>Description</th><th>Published Date</th><th>CVE Score</th></tr>\n')
                    html_file.write(f'<tr><td>{ids[i]}</td><td><p>{descriptions[i]}</p></td><td>{dates[i]}</td><td>{scores[i]}</td></tr>\n')
                    extra += 1
                    html_file.write('<tr><td colspan="8"><p style="color: gray;">N/A Risk: This vulnerability has no given score.</p><p>\n')
                    html_file.write(f'<strong>Method:</strong> {one[i]}</p>\n')
                    html_file.write(f'<p><strong>Path:</strong> {two[i]}</p>\n')
                    html_file.write(f'<p><strong>Info:</strong> {five[i]}</p>\n')
                    html_file.write(f'<p><strong>HTTP Info:</strong></p>\n')
                    html_file.write(f'<pre>{formatted_content}</pre>\n')
                    html_file.write(f'<p><strong>Curl Command:</strong></p> <pre>{seven[i]}</pre>\n')                    
                    html_file.write('<p>Potential fixes to patch this vulnerability: </p>\n')
                    html_file.write('<ul>\n')
                    html_file.write('<li>Validate and sanitize user inputs on both the client and server sides</li>\n')
                    html_file.write('<li>Minimize the use of inline scripts and styles. Instead, use external files or define them in the header</li>\n')
                    html_file.write('<li>Encode user-generated content before rendering it in web pages</li>\n')
                    html_file.write(f'<li>More potential solutions can be found on this website: <a href="https://www.savi-scanneronline.com/xml_fixes.html">here</a></li></td></tr>\n')
                    html_file.write('</table>\n')
                elif 0.0 < scores[i] < 3.9:
                    html_file.write('<table border="1" style="border: 3px solid green">\n')
                    html_file.write('<tr><th>CVE ID</th><th>Description</th><th>Published Date</th><th>CVE Score</th></tr>\n')
                    html_file.write(f'<tr><td>{ids[i]}</td><td><p>{descriptions[i]}</p></td><td>{dates[i]}</td><td>{scores[i]}</td></tr>\n')
                    low += 1
                    html_file.write('<tr><td colspan="8"><p style="color: green;">Low Risk: This vulnerability has a low risk score.</p><p>\n')
                    html_file.write(f'<strong>Method:</strong> {one[i]}</p>\n')
                    html_file.write(f'<p><strong>Path:</strong> {two[i]}</p>\n')
                    html_file.write(f'<p><strong>Info:</strong> {five[i]}</p>\n')
                    html_file.write(f'<p><strong>HTTP Info:</strong></p>\n')
                    html_file.write(f'<pre>{formatted_content}</pre>\n')
                    html_file.write(f'<p><strong>Curl Command:</strong></p> <pre>{seven[i]}</pre>\n')             
                    html_file.write(f'<p><strong>Fix for given CVE:</strong> <a href = {solutions[i]}>{solutions[i]}</a></p>\n')
                    html_file.write('<p>Potential fixes to patch this vulnerability: </p>\n')
                    html_file.write('<ul>\n')
                    html_file.write('<li>Validate and sanitize user inputs on both the client and server sides</li>\n')
                    html_file.write('<li>Minimize the use of inline scripts and styles. Instead, use external files or define them in the header</li>\n')
                    html_file.write('<li>Encode user-generated content before rendering it in web pages</li>\n')
                    html_file.write(f'<li>More potential solutions can be found on this website: <a href="https://www.savi-scanneronline.com/xml_fixes.html">here</a></li></td></tr>\n')
                    html_file.write('</table>\n')
                elif 4.0 < scores[i] < 6.9:
                    html_file.write('<table border="1" style="border: 3px solid orange">\n')
                    html_file.write('<tr><th>CVE ID</th><th>Description</th><th>Published Date</th><th>CVE Score</th></tr>\n')
                    html_file.write(f'<tr><td>{ids[i]}</td><td><p>{descriptions[i]}</p></td><td>{dates[i]}</td><td>{scores[i]}</td></tr>\n')
                    medium += 1
                    html_file.write('<tr><td colspan="8"><p style="color: orange;">Medium Risk: This vulnerability has a medium risk score.</p><p>\n')
                    html_file.write(f'<strong>Method:</strong> {one[i]}</p>\n')
                    html_file.write(f'<p><strong>Path:</strong> {two[i]}</p>\n')
                    html_file.write(f'<p><strong>Info:</strong> {five[i]}</p>\n')
                    html_file.write(f'<p><strong>HTTP Info:</strong></p>\n')
                    html_file.write(f'<pre>{formatted_content}</pre>\n')
                    html_file.write(f'<p><strong>Curl Command:</strong></p> <pre>{seven[i]}</pre>\n')
                    html_file.write(f'<p><strong>Fix for given CVE:</strong> <a href = {solutions[i]}>{solutions[i]}</a></p>\n')
                    html_file.write('<p>Potential fixes to patch this vulnerability: </p>\n')
                    html_file.write('<ul>\n')
                    html_file.write('<li>Validate and sanitize user inputs on both the client and server sides</li>\n')
                    html_file.write('<li>Minimize the use of inline scripts and styles. Instead, use external files or define them in the header</li>\n')
                    html_file.write('<li>Encode user-generated content before rendering it in web pages</li>\n')
                    html_file.write(f'<li>More potential solutions can be found on this website: <a href="https://www.savi-scanneronline.com/xml_fixes.html">here</a></li></td></tr>\n')
                    html_file.write('</table>\n')
                elif 7.0 < scores[i] < 10.0:
                    html_file.write('<table border="1" style="border: 3px solid red">\n')
                    html_file.write('<tr><th>CVE ID</th><th>Description</th><th>Published Date</th><th>CVE Score</th></tr>\n')
                    html_file.write(f'<tr><td>{ids[i]}</td><td><p>{descriptions[i]}</p></td><td>{dates[i]}</td><td>{scores[i]}</td></tr>\n')
                    high += 1
                    html_file.write('<tr><td colspan="8"><p style="color: red;">High Risk: This vulnerability has a high risk score.</p><p>\n')
                    html_file.write(f'<strong>Method:</strong> {one[i]}</p>\n')
                    html_file.write(f'<p><strong>Path:</strong> {two[i]}</p>\n')
                    html_file.write(f'<p><strong>Info:</strong> {five[i]}</p>\n')
                    html_file.write(f'<p><strong>HTTP Info:</strong></p>\n')
                    html_file.write(f'<pre>{formatted_content}</pre>\n')
                    html_file.write(f'<p><strong>Curl Command:</strong></p> <pre>{seven[i]}</pre>\n')                        
                    html_file.write(f'<p><strong>Fix for given CVE:</strong> <a href = {solutions[i]}>{solutions[i]}</a></p>\n')
                    html_file.write('<p>Potential fixes to patch this vulnerability: </p>\n')
                    html_file.write('<ul>\n')
                    html_file.write('<li>Validate and sanitize user inputs on both the client and server sides</li>\n')
                    html_file.write('<li>Minimize the use of inline scripts and styles. Instead, use external files or define them in the header</li>\n')
                    html_file.write('<li>Encode user-generated content before rendering it in web pages</li>\n')
                    html_file.write(f'<li>More potential solutions can be found on this website: <a href="https://www.savi-scanneronline.com/xml_fixes.html">here</a></li></td></tr>\n')
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
            html_file.write('<h3>What do the Curl command and Path data mean?</h3>')
            html_file.write('<p>The Curl command is simply a tool that enables data exchange between a device and a server through a terminal. The results here show the curl command generated to find the particular vulnerability found. The Path variable shows where on the website from the base url that the vulnerability was found, for example with a base url of google it could find a vulnerability in the path /home/ or in other words https://www.google.com/home/.</p>')
            html_file.write('<h3>How to interpret the HTTP Data</h3>')
            html_file.write('<p>The Http data show what the data transfer from the scanner to the target looks like in packet form. It shows you what type of request is used, what the payload specifically was instead of just the Type or title, and some other details.</p>')
            html_file.write("</div>")
            html_file.write('<div class="home">')
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
            html_file.write(f'<button type="submit" name="file_type" value="xss-html_{time_value}">Download HTML File</button>')
            html_file.write(f'<button type="submit" name="file_type" value="xss-xml_{time_value}">Download XML File</button>')
            html_file.write(f'<button type="submit" name="file_type" value="xss-pcap_{time_value}">Download PCAP File</button>')
            html_file.write('</form>')
            html_file.write('</div>')
            html_file.write('</body>\n')
            html_file.write('</html>\n')

if __name__ == "__main__":
    
    if len(sys.argv) < 1:
        print("Need time value")
        sys.exit(1)

    time_value = sys.argv[1]
    
    config_path = "/var/www/html/config2.json"
    config = load_config(config_path)
    login_url = config['login_url']

    test_form_for_xss_injection(login_url, time_value)
    
    parsed_url = urlparse(login_url)
    domain_path = parsed_url.netloc
    print(domain_path)
    
    xml_file_path = f'/var/www/html/{time_value}_XSSReport.xml'
    root = parse_xml(xml_file_path)
    entries = find_entries(root)
    
    cve_ids = find_matching_cve_entries(entries)

    write_html(domain_path, time_value + '_xss_results.html', xml_file_path, cve_ids, time_value)
    

