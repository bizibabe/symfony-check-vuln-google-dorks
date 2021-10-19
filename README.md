# symfony-check-vuln-google-dorks

## Legal disclaimer:

Usage of Symphony Google Dorks Checker Tool for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.

## Installation

```bash
$ git clone https://github.com/bizibabe/symfony-check-vuln-google-dorks.git
$ cd symfony-check-vuln-google-dorks
$ python3 -m pip install -r requirements.txt
```

## How to use this script

1. Create a Google Gmail account (possible to ban)
2. Connect on your new Gmail account / refresh  
3. python3 check_symfony.py --starturl 0 --nburl 20 -c YOUR_GOOGLE_COOKIE

```bash
usage: check_symfony.py [-h] [--nburl NBURL] [--starturl STARTURL] [--cookie COOKIE] [--all] [--jmp]

        This tool allows you to scan the configuration of Symfony developer mode using Google Dorks.

        By default the first 10 urls are scanned.

optional arguments:
  -h, --help            show this help message and exit
  --nburl NBURL, -n NBURL
                        Specifies the total number of urls to scan
  --starturl STARTURL, -s STARTURL
                        Specifies which url to start from on Google
  --cookie COOKIE, -c COOKIE
                        Cookie from your google account to bypass the captcha
  --all, -a             Google Dorks paylods to increase targets but many more false positives
  --jmp, -j             Do not use the token bruteforce method

```

<img src="images/output.png" width="500px">  

## Bypass captcha

1. Reload your Chrome browser and check if you have been detected as a bot  
2. Pass the check  
3. Put your new Google account cookie with -c option  

## After use

Once you find vulnerable websites, you can take things a step further !  
Token + Fragment + internal url = __RCE__ 

### Best scanner for single url
(https://github.com/synacktiv/eos/)  

### RCE tool (token + fragment + internal url)
(https://github.com/ambionics/symfony-exploits)  

