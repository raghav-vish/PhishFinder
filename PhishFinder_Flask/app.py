from flask import Flask, render_template, url_for, request, redirect
import requests
import bs4
import pandas as pd
import csv
from extract_feature import *

def beautify(res, url):
	finres=int(res[71])
	if(finres==0):
		chance=float(res[75:82])*100
		chance2=float(res[95:102])*100
		res2=' is a legitimate website'
	elif(finres==1):
		chance=float(res[75:82])*100
		chance2=float(res[97:104])*100
		res2=' is a Phishing website'
	return res2, chance, chance2

def do(url):
	writer = csv.writer(open('already.csv', "a", newline='\n'))
	try:
		page_response = requests.get(url, timeout=5)
	except:
		return 'Error getting response'

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
		#API_KEY = "Ba9vlGX18fV3pfKiUDbOonFHKHxKkUym5ZA_ohqWhw3h" #vitstudent acccount
		API_KEY = "VWYq3Edd4x3sKzbSCutoG6Hv1sk4Li_J9Cc7iRPP6BV7" #.vish1 account
		#API_KEY = "2V8H55CnVTUJejpGFs7RKDgU_s9ApqDg__QfHyJLWhQ9" #.vish2 account
		token_response = requests.post('https://iam.cloud.ibm.com/identity/token', data={"apikey": API_KEY, "grant_type": 'urn:ibm:params:oauth:grant-type:apikey'})
		mltoken = token_response.json()["access_token"]
		header = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + mltoken}

		payload_scoring = {"input_data": [{"fields": ["sslfinal_state", "domain_registation_length", "url_of_anchor", "links_in_tags", "redirect", "age_of_domain", "web_traffic"], "values": [status]}]}

		response_scoring = requests.post('https://jp-tok.ml.cloud.ibm.com/ml/v4/deployments/48f2349d-909e-42d1-8bf6-57d73b8138a9/predictions?version=2021-05-19', json=payload_scoring, headers={'Authorization': 'Bearer ' + mltoken})
		res=response_scoring.json()
		writer.writerow([url,res])
		return str(res)
	except:
		return 'Error getting features'


app=Flask(__name__)


@app.route("/", methods=['POST', 'GET'])
def search():
	title=0
	if(request.method=='POST'):
		title = request.form['url']
	df = pd.read_csv('already.csv')
	d=dict(df.values)
	if(title==0):
		return render_template("index.html")
		res='-'*120
	if(title in d):
		res=d[title]
		addtofile()
	else:
		res=do(title)
	res2, chance, chance2=beautify(res,title)
	return render_template("results.html", url=title, res2=res2, chance=chance, chance2=chance2)



@app.route("/")
def index():
	return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)