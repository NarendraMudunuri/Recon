from flask import Flask, request, render_template, url_for
import requests
import json
import whois
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.firefox.options import Options

recon = Flask(__name__)

api_key = 'api_key' # api key of virus total

@recon.route('/', methods=['GET','POST'])
def home():

    l = []
    count = 0
    message = []
    message2 = []

    whois_message = []
    netcraft_message1 = []
    netcraft_message2 = []
    netcraft_message3 = []
    length = None

    if request.method == 'POST':
        btn = request.form.get('button')

        if btn == 'url':
            domain = request.form.get('url')
            url = 'https://www.virustotal.com/api/v3/urls'
            payload = {'url': domain}
            headers = {
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded",
                "X-Apikey": api_key
            }

            res = requests.post(url, headers=headers, data=payload)
            resp = res.json()
            
            get_id = resp['data']['id']
            get_id = get_id.split('-')
            url2 = f'https://www.virustotal.com/api/v3/urls/{get_id[1]}'

            req = requests.get(url2, headers=headers)

            resp2 = req.json()
            
            d = resp2['data']['attributes']['last_analysis_results']
            
            for engine in d:
                r = resp2['data']['attributes']['last_analysis_results'][f'{engine}']
                result = r['result']
                if result == "clean":
                    count = count + 1
                    l.append(f"{engine}")
            harmless = resp2['data']['attributes']['last_analysis_stats']['harmless']
            malicious = resp2['data']['attributes']['last_analysis_stats']['malicious']
            suspicious = resp2['data']['attributes']['last_analysis_stats']['suspicious']
            timeout = resp2['data']['attributes']['last_analysis_stats']['timeout']
            undetected = resp2['data']['attributes']['last_analysis_stats']['undetected']
            sha = resp2['data']['attributes']['last_http_response_content_sha256']
            last_url = resp2['data']['attributes']['last_final_url']
            message = [f'{harmless}', f'{malicious}', f'{suspicious}', f'{timeout}', f'{undetected}', f'{sha}', f'{last_url}']

        if btn == 'ip':
            domain = request.form.get('ip')

            url1 = f"https://www.virustotal.com/api/v3/ip_addresses/{domain}/analyse"

            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }

            response = requests.post(url1, headers=headers)

            resp = response.json()

            get_id = resp['data']['id']

            url2 = f"https://www.virustotal.com/api/v3/ip_addresses/{domain}"

            res = requests.get(url2, headers=headers)
            r = res.json()
            data = r['data']['attributes']['last_analysis_stats']

            harmless = data['harmless']
            suspicious = data['suspicious']
            malicious = data['malicious']
            undetected = data['undetected']
            timeout = data['timeout']
            message2 = [f'{malicious}', f'{suspicious}', f'{undetected}', f'{harmless}', f'{timeout}']
        
        # results = l, clean_count = count

        if btn == 'domain':
            
            domain = request.form.get("domain")

            w = whois.whois(domain)

            domain_name = w['domain_name']
            registrar = w['registrar']
            url_api = w['registrar_url']
            dnssec = w['dnssec']

            name_servers = w['name_servers']
            status = w['status']
            creation_date = w['creation_date']
            expire_date = w['expiration_date']
            updated_date = w['updated_date']

            name = w['name']
            registrant_org = w['org']
            
            address = w['address']
            city = w['city']
            state = w['state']
            country = w['country']
            zip_code = w['registrant_postal_code']

            whois_message = [
                f'{domain_name}', 
                f'{registrar}', 
                f'{url_api}',
                f'{dnssec}',
                f'{name_servers}',
                f'{status}',
                f'{creation_date}',
                f'{expire_date}',
                f'{updated_date}',
                f'{name}',
                f'{registrant_org}',
                f'{address}',
                f'{city}',
                f'{state}',
                f'{country}',
                f'{zip_code}',
                ]
            
        if btn == 'netcraft':
            
            domain = request.form.get("netcraft_domain")
            url = f"https://sitereport.netcraft.com/?url={domain}"

            headers = {
                "User-Agent": "Mozilla/5.0"
            }

            res = requests.get(url, headers=headers)
            netcraft = BeautifulSoup(res.text, "lxml")

            # find table
            table = netcraft.find("div", { "class": "section_content"} )

            # extract rows
            rows = table.find_all(["tr"])

            # loop through rows
            
            for row in rows:
                cells = row.find_all(["th", "td"]) # Get both header and data cells
                cell_text = [cell.get_text(strip=True) for cell in cells]
                netcraft_message1.append(cell_text)
                
            # find 2 table
            table2 = netcraft.find("section", { "id": "network_table_section"} )

            # extract rows
            rows1 = table2.find_all(["tr"])

            # loop through rows
            data2 = []
            for row1 in rows1:
                cells = row1.find_all(["th", "td"]) # Get both header and data cells
                cell_text = [cell.get_text(strip=True) for cell in cells]
                netcraft_message2.append(cell_text)

            # set chrome or firefox options

            options = Options()
            options.add_argument("--headless") # Run in headless mode

            # Run firefox/chrome in headless mode
            driver = webdriver.Firefox(options=options)

            # open the target page
            driver.get(f"https://searchdns.netcraft.com/?host=*.{domain[3:]}")

            # get fully rendered html
            html = driver.page_source

            # parse the html using beautifulsoup
            soup = BeautifulSoup(html, 'lxml')

            t = soup.find('table', {'class': "results-table table--collapsible links"})

            s = t.find_all(['tr'])
            for row in s:
                cells = row.find_all(['th','td'])
                cell_text = [cell.get_text(strip=True) for cell in cells]
                netcraft_message3.append(cell_text)

    return render_template(
        'index.html', 
        message=message, 
        message2=message2, 
        results = l, 
        count = count,
        whois_message = whois_message,
        netcraft = netcraft_message1,
        netcraft2 = netcraft_message2,
        netcraft3 = netcraft_message3,
        l = len(netcraft_message3)
        )

if __name__ == "__main__":
    recon.run(host='0.0.0.0', port=5555, debug=True)