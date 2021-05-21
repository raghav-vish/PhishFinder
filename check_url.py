from extract_feature import *
import requests

url = sys.argv[1]

import pandas as pd
df = pd.read_csv('already.csv')
d=dict(df.values)
if(url in d):
    res=d[url]
    do()
    print(res)
    exit()
    
writer = csv.writer(open('already.csv', "a", newline='\n'))

try:
    page_response = requests.get(url, timeout=5)
except:
    print('error getting response 1!!!')
    exit()

try:
    
    soup = BeautifulSoup(page_response.content, 'html.parser')
    status = []
    hostname = url
    h = [(x.start(0), x.end(0)) for x in re.finditer('https://|http://|www.|https://www.|http://www.', hostname)]
    z = int(len(h))
    if z != 0:
        y = h[0][1]
        hostname = hostname[y:]
        h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
        z = int(len(h))
        if z != 0:
            hostname = hostname[:h[0][0]]

    status.append(SSLfinal_State(url))

    dns = 1
    try:
        domain = whois.whois(url)
    except:
        dns = -1

    if dns == -1:
        status.append(1)
    else:
        status.append(domain_registration_length(domain))

    print("test")
    status.append(url_of_anchor(soup, domain))
    status.append(links_in_tags(soup, domain))
    status.append(redirect(url))

    if dns == -1:
        status.append(1)
    else:
        res = age_of_domain(domain)
        res = res/483.33
        status.append(res)

    status.append(web_traffic(url))
    

    print(status)
    API_KEY = "VWYq3Edd4x3sKzbSCutoG6Hv1sk4Li_J9Cc7iRPP6BV7" #.vish1 account
    token_response = requests.post('https://iam.cloud.ibm.com/identity/token', data={"apikey": API_KEY, "grant_type": 'urn:ibm:params:oauth:grant-type:apikey'})
    mltoken = token_response.json()["access_token"]

    header = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + mltoken}

    payload_scoring = {"input_data": [{"fields": ["sslfinal_state", "domain_registation_length", "url_of_anchor", "links_in_tags", "redirect", "age_of_domain", "web_traffic"], "values": [status]}]}
    response_scoring = requests.post('https://jp-tok.ml.cloud.ibm.com/ml/v4/deployments/c4a5532a-7716-4969-a40f-a43bae2f01d9/predictions?version=2021-05-17', json=payload_scoring, headers={'Authorization': 'Bearer ' + mltoken})

    print("Scoring response")
    res=response_scoring.json()
    print(res)
    writer.writerow([url,res])

except:
    print('error getting features!!!')
    exit()