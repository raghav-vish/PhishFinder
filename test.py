import pandas as pd
def beautify(res, url):
	finres=int(res[71])
	if(finres==0):
		chance=res[75:93]
		res2=f'{url} is a legitimate website ({chance} probability)'
	elif(finres==1):
		chance=res[96:115]
		res2=f'{url} is a Phishing website ({chance} probability)'
	return res2

#title=sys.argv[1]
title='https://jollybeef.xyz/amazonEaster/tb.php?_t=1620630672'
#title='https://www.google.com'
df = pd.read_csv('already.csv')
d=dict(df.values)
res=d[title]
beautify(res,title)