import json
from flask import Flask, render_template, request, send_file, make_response
import subprocess
import os
import zipfile
from flask import Flask, request, session, send_file, make_response
from flask import jsonify
from urllib.parse import urlparse, urlunparse
from flask_cors import CORS
import ssl
from werkzeug.utils import secure_filename
import pyshark
import sys
import time
import psutil

app = Flask(__name__)
app.secret_key = 'Goodluckgettingin111231321321'

def is_process_running(process_name):
    """Check if there is any running process that contains the given name process_name."""
    for proc in psutil.process_iter():
        try:
            # Check if process name contains the given name string.
            if process_name.lower() in proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False

def wait_for_process_to_finish(process_name):
    """Wait for a process to finish."""
    while is_process_running(process_name):
        time.sleep(1) # Wait for 1 second before checking again

@app.errorhandler(500)
def internal_server_error(error):
    url = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <style>
	body {{
		display: flex;
        justify-content: center;
        align-items: center;
        flex-direction: column;
        background-color: #b8a468; /* Use a more muted background color */
        font-family: Arial, Helvetica, sans-serif;
        font-size: large;
    }}
    header {{
           font-family: 'Helvetica Neue', Arial, sans-serif;
           text-align: center;
           font-size: 2em;
           padding: 30px;
           display: flex;
           justify-content: center;
           flex-direction: row;
           box-shadow:  0  2px  4px rgba(0,  0,  0,  0.1);
    }}
    .navbar {{
            width: 100%;
            background-color: #452f69; /* Set the background color here */
            position: fixed; /* Optional: Use this if you want the navbar to stay at the top */
            top: 0;
            left: 0;
            z-index: 2;
    }}
    .navbar ul {{
               padding: 0;
               margin: 0;
               list-style-type: none;
    }}
    .navbar li {{
               display: inline-block; /* Display list items horizontally */
    }}
    .navbar a {{
              display: block;
              color: white;
              text-align: center;
              padding: 14px 16px;
              text-decoration: none;
              background-color: transparent; /* Make sure the background is transparent */
              transition: background-color 0.3s ease; /* Smooth hover effect */
    }}
    .navbar li a:hover {{
                       background-color: #333;
    }}
    </style>
    <title>Messed Up URL</title>
    </head>
    <body>
    <header>
    <div>
    <nav class="navbar">
    <ul id="menuBar">
    <li><a href="https://www.savi-scanneronline.com/interface.html">Home</a></li>
    <li><a href="https://www.savi-scanneronline.com/about.html">About</a></li>
    <li><a href="https://www.savi-scanneronline.com/documentation.html">Documentation</a></li>
    <li><a href="https://www.savi-scanneronline.com/creators.html">Creators</a></li>
    <li><a href="https://www.savi-scanneronline.com/feedback.html">Feedback</a></li>
    </ul>
    </nav>
    </div>
    </header>
    <h1>Unexpected error</h1>
    <p>An unexpected error as occured. Please go back and try the scan again and make sure the url is valid.</p>
    <a href="https://www.savi-scanneronline.com/interface.html">Back to Configuration</a>
    </body>
    </html>
    """
    return url


def validate_url(url):
   parsed_url = urlparse(url)
   if bool(parsed_url.netloc) and bool(parsed_url.scheme):
       return True
   return False

def load_config(config_file):
    with open(config_file, 'r') as f:
        return json.load(f)

def save_config(config, config_file):
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)


@app.route('/download', methods=['GET'])
def download_file():
    

    default = session.get('time')

    file_paths = {
            'sql-html_' + default: '/var/www/html/' + default + '_matching_cve_results.html',
            'sql-xml_' + default: '/var/www/html/' + default + '_sql_injection_report.xml',
            'sql-pcap_' + default: '/var/www/html/' + default + '_packets.pcap',
            'xss-html_'+ default: '/var/www/html/' + default + '_xss_results.html',
            'xss-xml_'+ default: '/var/www/html/' + default + '_XSSReport.xml',
            'xss-pcap_'+ default: '/var/www/html/' + default + '_packets2.pcap',
            'csrf-html_'+ default: '/var/www/html/' + default + '_csrf_results.html',
            'csrf-xml_'+ default: '/var/www/html/'+ default + '_CSRFReport.xml',
            'csrf-pcap_'+ default: '/var/www/html/'+ default + '_packets3.pcap'
            }

    file_type = request.args.get('file_type')

    if file_type not in file_paths:
        abort(400, description='Invalid file type')
    
    file_name = secure_filename(file_paths[file_type].split('/')[-1])
    return send_file(file_paths[file_type], as_attachment=True) 


@app.route('/update_config', methods=['POST'])
def update_config():
    if request.method == 'POST':
        attack_type = request.form.get('attack_type')
        
        if attack_type == "xss":
            login_url = request.form.get('login_url')
            if not validate_url(login_url):
                    Invalid_url = f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                        <style>
                        body {{
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            flex-direction: column;
                            background-color: #b8a468; /* Use a more muted background color */
                            font-family: Arial, Helvetica, sans-serif;
                            font-size: large;
                        }}
                        header {{
                            font-family: 'Helvetica Neue', Arial, sans-serif;
                            text-align: center;
                            font-size: 2em;
                            padding: 30px;
                            display: flex;
                            justify-content: center;
                            flex-direction: row;
                            box-shadow:  0  2px  4px rgba(0,  0,  0,  0.1);
                        }}
                        .navbar {{
                            width: 100%;
                            background-color: #452f69; /* Set the background color here */
                            position: fixed; /* Optional: Use this if you want the navbar to stay at the top */
                            top: 0;
                            left: 0;
                            z-index: 2;
                        }}
                        .navbar ul {{
                            padding: 0;
                            margin: 0;
                            list-style-type: none;
                        }}
                        .navbar li {{
                            display: inline-block; /* Display list items horizontally */
                        }}
                        .navbar a {{
                            display: block;
                            color: white;
                            text-align: center;
                            padding: 14px 16px;
                            text-decoration: none;
                            background-color: transparent; /* Make sure the background is transparent */
                            transition: background-color 0.3s ease; /* Smooth hover effect */
                        }}
                        .navbar li a:hover {{
                            background-color: #333;
                        }}
                        </style>
                        <title>Messed Up URL</title>
                        </head>
                        <body>
                            <header>
                                <div>
                                    <nav class="navbar">
                                        <ul id="menuBar">
                                        <li><a href="https://www.savi-scanneronline.com/interface.html">Home</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/about.html">About</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/documentation.html">Documentation</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/creators.html">Creators</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/feedback.html">Feedback</a></li>
                                        </ul>
                                    </nav>
                                </div>
                            </header>
                            <h1>Invalid URL</h1>
                            <p>The following url is formatted incorrectly: {login_url}.</p>
                            <a href="https://www.savi-scanneronline.com/interface.html">Back to Configuration</a>
                        </body>
                        </html>
                        """
                    return Invalid_url
            else: 
                config_path = "/var/www/html/config2.json"
                config = load_config(config_path)
                time_value = request.form.get('time')
                session['time'] = time_value
                
                config['login_url'] = login_url
                save_config(config, config_path)

                test_script_directory = "/var/www/html"
                test_script_path = os.path.join(test_script_directory, "xss.py")

            process_name = "wapiti"

            if is_process_running(process_name):
                print("wait")
                wait_for_process_to_finish(process_name)
                print("done now running script")
                time.sleep(10)
                subprocess.run(["python3", test_script_path, time_value], cwd=test_script_directory)
            else:
                print("run immediate")
                subprocess.run(["python3", test_script_path, time_value], cwd=test_script_directory)

            html_file_path = f"/var/www/html/{time_value}_xss_results.html"


            return send_file(html_file_path, as_attachment=False)

        if attack_type == "csrf":
            login_url = request.form.get('login_url')

            if not validate_url(login_url):
                    Invalid_url = f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                        <style>
                        body {{
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            flex-direction: column;
                            background-color: #b8a468; /* Use a more muted background color */
                            font-family: Arial, Helvetica, sans-serif;
                            font-size: large;
                        }}
                        header {{
                            font-family: 'Helvetica Neue', Arial, sans-serif;
                            text-align: center;
                            font-size: 2em;
                            padding: 30px;
                            display: flex;
                            justify-content: center;
                            flex-direction: row;
                            box-shadow:  0  2px  4px rgba(0,  0,  0,  0.1);
                        }}
                        .navbar {{
                            width: 100%;
                            background-color: #452f69; /* Set the background color here */
                            position: fixed; /* Optional: Use this if you want the navbar to stay at the top */
                            top: 0;
                            left: 0;
                            z-index: 2;
                        }}
                        .navbar ul {{
                            padding: 0;
                            margin: 0;
                            list-style-type: none;
                        }}
                        .navbar li {{
                            display: inline-block; /* Display list items horizontally */
                        }}
                        .navbar a {{
                            display: block;
                            color: white;
                            text-align: center;
                            padding: 14px 16px;
                            text-decoration: none;
                            background-color: transparent; /* Make sure the background is transparent */
                            transition: background-color 0.3s ease; /* Smooth hover effect */
                        }}
                        .navbar li a:hover {{
                            background-color: #333;
                        }}
                        </style>
                        <title>Messed Up URL</title>
                        </head>
                        <body>
                            <header>
                                <div>
                                    <nav class="navbar">
                                        <ul id="menuBar">
                                        <li><a href="https://www.savi-scanneronline.com/interface.html">Home</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/about.html">About</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/documentation.html">Documentation</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/creators.html">Creators</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/feedback.html">Feedback</a></li>
                                        </ul>
                                    </nav>
                                </div>
                            </header>
                            <p>The following url is formatted incorrectly: {login_url}.</p>
                            <a href="https://www.savi-scanneronline.com/interface.html">Back to Configuration</a>
                        </body>
                        </html>
                        """
                    return Invalid_url
            else:
                config_path = "/var/www/html/config3.json"
                config = load_config(config_path)
                time_value = request.form.get('time')
                session['time'] = time_value
                
                config['login_url'] = login_url
                save_config(config, config_path)

                test_script_directory = "/var/www/html"
                test_script_path = os.path.join(test_script_directory, "csrf.py")

            process_name = "wapiti"

            if is_process_running(process_name):
                print("wait")
                wait_for_process_to_finish(process_name)
                print("done now running script")
                time.sleep(10)
                subprocess.run(["python3", test_script_path, time_value], cwd=test_script_directory)
            else:
                print("run immediate")
                subprocess.run(["python3", test_script_path, time_value], cwd=test_script_directory)

            html_file_path = f"/var/www/html/{time_value}_csrf_results.html"


            return send_file(html_file_path, as_attachment=False)

        if attack_type == "sql":
            login_required = request.form.get('login_required')

            if (login_required == "yes"):
                # Extract the login URL, username, and password from the form data
                login_url = request.form.get('login_url')
                username = request.form.get('username')
                password = request.form.get('password')
                level = request.form.get("level")
                risk = request.form.get("risk")
                forms = request.form.get("forms")
                crawl = request.form.get("crawl")

                if username == "" or password == "":
                    No_password = f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                        <style>
                        body {{
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            flex-direction: column;
                            background-color: #b8a468; /* Use a more muted background color */
                            font-family: Arial, Helvetica, sans-serif;
                            font-size: large;
                        }}
                        header {{
                            font-family: 'Helvetica Neue', Arial, sans-serif;
                            text-align: center;
                            font-size: 2em;
                            padding: 30px;
                            display: flex;
                            justify-content: center;
                            flex-direction: row;
                            box-shadow:  0  2px  4px rgba(0,  0,  0,  0.1);
                        }}
                        .navbar {{
                            width: 100%;
                            background-color: #452f69; /* Set the background color here */
                            position: fixed; /* Optional: Use this if you want the navbar to stay at the top */
                            top: 0;
                            left: 0;
                            z-index: 2;
                        }}
                        .navbar ul {{
                            padding: 0;
                            margin: 0;
                            list-style-type: none;
                        }}
                        .navbar li {{
                            display: inline-block; /* Display list items horizontally */
                        }}
                        .navbar a {{
                            display: block;
                            color: white;
                            text-align: center;
                            padding: 14px 16px;
                            text-decoration: none;
                            background-color: transparent; /* Make sure the background is transparent */
                            transition: background-color 0.3s ease; /* Smooth hover effect */
                        }}
                        .navbar li a:hover {{
                            background-color: #333;
                        }}
                        </style>
                        <title>Messed Up Login</title>
                        </head>
                        <body>
                            <header>
                                <div>
                                    <nav class="navbar">
                                        <ul id="menuBar">
                                        <li><a href="https://www.savi-scanneronline.com/interface.html">Home</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/about.html">About</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/documentation.html">Documentation</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/creators.html">Creators</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/feedback.html">Feedback</a></li>
                                        </ul>
                                    </nav>
                                </div>
                            </header>
                            <h1>The scan will not run unless provided something if the website requires credentials</h1>
                            <p>The scan did not produce any results. Please check your configuration and try again.</p>
                            <a href="https://www.savi-scanneronline.com/interface.html">Back to Configuration</a>
                        </body>
                        </html>
                        """
                    return No_password
                
                elif not validate_url(login_url):
                    Invalid_url = f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                        <style>
                        body {{
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            flex-direction: column;
                            background-color: #b8a468; /* Use a more muted background color */
                            font-family: Arial, Helvetica, sans-serif;
                            font-size: large;
                        }}
                        header {{
                            font-family: 'Helvetica Neue', Arial, sans-serif;
                            text-align: center;
                            font-size: 2em;
                            padding: 30px;
                            display: flex;
                            justify-content: center;
                            flex-direction: row;
                            box-shadow:  0  2px  4px rgba(0,  0,  0,  0.1);
                        }}
                        .navbar {{
                            width: 100%;
                            background-color: #452f69; /* Set the background color here */
                            position: fixed; /* Optional: Use this if you want the navbar to stay at the top */
                            top: 0;
                            left: 0;
                            z-index: 2;
                        }}
                        .navbar ul {{
                            padding: 0;
                            margin: 0;
                            list-style-type: none;
                        }}
                        .navbar li {{
                            display: inline-block; /* Display list items horizontally */
                        }}
                        .navbar a {{
                            display: block;
                            color: white;
                            text-align: center;
                            padding: 14px 16px;
                            text-decoration: none;
                            background-color: transparent; /* Make sure the background is transparent */
                            transition: background-color 0.3s ease; /* Smooth hover effect */
                        }}
                        .navbar li a:hover {{
                            background-color: #333;
                        }}
                        </style>
                        <title>Messed Up URL</title>
                        </head>
                        <body>
                            <header>
                                <div>
                                    <nav class="navbar">
                                        <ul id="menuBar">
                                        <li><a href="https://www.savi-scanneronline.com/interface.html">Home</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/about.html">About</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/documentation.html">Documentation</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/creators.html">Creators</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/feedback.html">Feedback</a></li>
                                        </ul>
                                    </nav>
                                </div>
                            </header>
                            <h1>Invalid URL</h1>
                            <p>The following url is formatted incorrectly: {login_url}.</p>
                            <a href="https://www.savi-scanneronline.com/interface.html">Back to Configuration</a>
                        </body>
                        </html>
                        """
                    return Invalid_url
                
                else:
                    config_path = "/var/www/html/config.json"
                    config = load_config(config_path)

                    # Update the configuration with login URL, username, password, and other values
                    config['login_url'] = login_url
                    config['username'] = username
                    config['password'] = password
                    config['level'] = level
                    config['risk'] = risk
                    config['forms'] = forms
                    config['crawl'] = crawl

                # Validate the login URL
            elif (login_required == "no"):
                # Extract the login URL, username, and password from the form data
                login_url = request.form.get('login_url')
                username = request.form.get('username')
                password = request.form.get('password')
                level = request.form.get("level")
                risk = request.form.get("risk")
                forms = request.form.get("forms")
                crawl = request.form.get("crawl")


                if not validate_url(login_url):
                    Invalid_url = f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                        <style>
                        body {{
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            flex-direction: column;
                            background-color: #b8a468; /* Use a more muted background color */
                            font-family: Arial, Helvetica, sans-serif;
                            font-size: large;
                        }}
                        header {{
                            font-family: 'Helvetica Neue', Arial, sans-serif;
                            text-align: center;
                            font-size: 2em;
                            padding: 30px;
                            display: flex;
                            justify-content: center;
                            flex-direction: row;
                            box-shadow:  0  2px  4px rgba(0,  0,  0,  0.1);
                        }}
                        .navbar {{
                            width: 100%;
                            background-color: #452f69; /* Set the background color here */
                            position: fixed; /* Optional: Use this if you want the navbar to stay at the top */
                            top: 0;
                            left: 0;
                            z-index: 2;
                        }}
                        .navbar ul {{
                            padding: 0;
                            margin: 0;
                            list-style-type: none;
                        }}
                        .navbar li {{
                            display: inline-block; /* Display list items horizontally */
                        }}
                        .navbar a {{
                            display: block;
                            color: white;
                            text-align: center;
                            padding: 14px 16px;
                            text-decoration: none;
                            background-color: transparent; /* Make sure the background is transparent */
                            transition: background-color 0.3s ease; /* Smooth hover effect */
                        }}
                        .navbar li a:hover {{
                            background-color: #333;
                        }}
                        </style>
                        <title>Messed Up URL</title>
                        </head>
                        <body>
                            <header>
                                <div>
                                    <nav class="navbar">
                                        <ul id="menuBar">
                                        <li><a href="https://www.savi-scanneronline.com/interface.html">Home</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/about.html">About</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/documentation.html">Documentation</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/creators.html">Creators</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/feedback.html">Feedback</a></li>
                                        </ul>
                                    </nav>
                                </div>
                            </header>
                            <h1>Invalid URL</h1>
                            <p>The following url is formatted incorrectly: {login_url}.</p>
                            <a href="https://www.savi-scanneronline.com/interface.html">Back to Configuration</a>
                        </body>
                        </html>
                        """
                    return Invalid_url
                else:
                    config_path = "/var/www/html/config.json"
                    config = load_config(config_path)

                    # Update the configuration with login URL, username, password, and other values
                    config['login_url'] = login_url
                    config['username'] = ""
                    config['password'] = ""
                    config['level'] = level
                    config['risk'] = risk
                    config['forms'] = forms
                    config['crawl'] = crawl

                    
            save_config(config, config_path)
            time_value = request.form.get('time')
            session['time'] = time_value
            test_script_directory = "/var/www/html"
            test_script_path = os.path.join(test_script_directory, "sql_v3.py")
    
            # Run Test.py using subprocess from the specified directory
            #subprocess.run(["python3", test_script_path, time], cwd=test_script_directory)
            
            process_name = "sqlmap"
            if is_process_running(process_name):
                print("wait")
                wait_for_process_to_finish(process_name)
                print("done now running script")
                time.sleep(10)
                subprocess.run(["python3", test_script_path, time_value], cwd=test_script_directory)
            else:
                print("Immediate")
                subprocess.run(["python3", test_script_path, time_value], cwd=test_script_directory)
            
            # Get the paths to the matching HTML and XML files
            html_file_path = os.path.join(test_script_directory, time_value + "_matching_cve_results.html")
            xml_file_path = os.path.join(test_script_directory, time_value + "_sql_injection_report.xml")

            results_file_path = f'/var/www/html/{time_value}_Results.txt'
            with open(results_file_path, 'r', encoding='utf-8') as results_txt_file:
                results_txt_contents = results_txt_file.read()
                if "[ERROR]" in results_txt_contents or "[CRITICAL]" in results_txt_contents: # Check if the contents contain the string "Error"
                        SQL_end = f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                        <style>
                        body {{
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            flex-direction: column;
                            background-color: #b8a468; /* Use a more muted background color */
                            font-family: Arial, Helvetica, sans-serif;
                            font-size: large;
                        }}
                        header {{
                            font-family: 'Helvetica Neue', Arial, sans-serif;
                            text-align: center;
                            font-size: 2em;
                            padding: 30px;
                            display: flex;
                            justify-content: center;
                            flex-direction: row;
                            box-shadow:  0  2px  4px rgba(0,  0,  0,  0.1);
                        }}
                        .navbar {{
                            width: 100%;
                            background-color: #452f69; /* Set the background color here */
                            position: fixed; /* Optional: Use this if you want the navbar to stay at the top */
                            top: 0;
                            left: 0;
                            z-index: 2;
                        }}
                        .navbar ul {{
                            padding: 0;
                            margin: 0;
                            list-style-type: none;
                        }}
                        .navbar li {{
                            display: inline-block; /* Display list items horizontally */
                        }}
                        .navbar a {{
                            display: block;
                            color: white;
                            text-align: center;
                            padding: 14px 16px;
                            text-decoration: none;
                            background-color: transparent; /* Make sure the background is transparent */
                            transition: background-color 0.3s ease; /* Smooth hover effect */
                        }}
                        .navbar li a:hover {{
                            background-color: #333;
                        }}
                        </style>
                        <title>Messed Up URL</title>
                        </head>
                        <body>
                            <header>
                                <div>
                                    <nav class="navbar">
                                        <ul id="menuBar">
                                        <li><a href="https://www.savi-scanneronline.com/interface.html">Home</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/about.html">About</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/documentation.html">Documentation</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/creators.html">Creators</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/feedback.html">Feedback</a></li>
                                        </ul>
                                    </nav>
                                </div>
                            </header>
                            <h1>SQL Results</h1>
                            <p>SQL found the following: {results_txt_contents}.</p>
                            <p>Go back and do the suggested changes.</p>
                            <a href="https://www.savi-scanneronline.com/interface.html">Back to Configuration</a>
                        </body>
                        </html>
                        """
                        return SQL_end       
            
            if os.path.exists(html_file_path) and os.path.exists(xml_file_path):

        

                config['login_url'] = ""
                config['username'] = ""
                config['password'] = ""
                config['level'] = ""
                config['risk'] = ""
                config['forms'] = ""
                config['crawl'] = ""
                save_config(config, config_path)

            return send_file(html_file_path, as_attachment=False)
        elif attack_type == "default": 
            No_attack = f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                        <style>
                        body {{
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            flex-direction: column;
                            background-color: #b8a468; /* Use a more muted background color */
                            font-family: Arial, Helvetica, sans-serif;
                            font-size: large;
                        }}
                        header {{
                            font-family: 'Helvetica Neue', Arial, sans-serif;
                            text-align: center;
                            font-size: 2em;
                            padding: 30px;
                            display: flex;
                            justify-content: center;
                            flex-direction: row;
                            box-shadow:  0  2px  4px rgba(0,  0,  0,  0.1);
                        }}
                        .navbar {{
                            width: 100%;
                            background-color: #452f69; /* Set the background color here */
                            position: fixed; /* Optional: Use this if you want the navbar to stay at the top */
                            top: 0;
                            left: 0;
                            z-index: 2;
                        }}
                        .navbar ul {{
                            padding: 0;
                            margin: 0;
                            list-style-type: none;
                        }}
                        .navbar li {{
                            display: inline-block; /* Display list items horizontally */
                        }}
                        .navbar a {{
                            display: block;
                            color: white;
                            text-align: center;
                            padding: 14px 16px;
                            text-decoration: none;
                            background-color: transparent; /* Make sure the background is transparent */
                            transition: background-color 0.3s ease; /* Smooth hover effect */
                        }}
                        .navbar li a:hover {{
                            background-color: #333;
                        }}
                        </style>
                        <title>Messed Up URL</title>
                        </head>
                        <body>
                            <header>
                                <div>
                                    <nav class="navbar">
                                        <ul id="menuBar">
                                        <li><a href="https://www.savi-scanneronline.com/interface.html">Home</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/about.html">About</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/documentation.html">Documentation</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/creators.html">Creators</a></li>
                                        <li><a href="https://www.savi-scanneronline.com/feedback.html">Feedback</a></li>
                                        </ul>
                                    </nav>
                                </div>
                            </header>
                <h1>Select attack</h1>
                <p>Go back and please select an attack type.</p>
                <a href="https://www.savi-scanneronline.com/interface.html">Back to Configuration</a>
            </body>
            </html>
            """
            return No_attack

    #elif request.method == 'GET':

     #   oof = request.args.get('page')
      #  if oof:
       #     return render_page(oof)



if __name__ == "__main__":

    CORS(app)
    app.run(ssl_context='adhoc', host='0.0.0.0', debug=True)
    
