- Directory Fuzzing
    - (-w) wordlists
    - (-u) URL
    - `ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ`
    - `ffuf -w <SNIP> -u http://SERVER_IP:PORT/FUZZ`
    - `ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ`
- Page Fuzzing
    - Identify .html .aspx .php or etc
    - Server type from http header
        - Apache php
        - IIS .asp
    - Extension fuzzing
        - `ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ`
        - `FUZZ_1.FUZZ_2`
        - `index.*,`
        - `ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ`
    - `ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php`
- Recursive Fuzzing
    - recursion flag
    - recursion-depth 1
    - When using recursion in ffuf, we can specify our extension with -e .php
    - v to output the full URLs
    - `ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v`

## Domain Fuzzing

- DNS Records
    - `sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'`
- Sub-domain fuzzing
    - `ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u [https://FUZZ.inlanefreight.com/](https://fuzz.inlanefreight.com/)`
- Vhost Fuzzing
    - The key difference between VHosts and sub-domains is that a VHost is basically a 'sub-domain' served on the same server and has the same IP, such that a single IP could be serving two or more different websites.
    - VHosts may or may not have public DNS records.
    - `fuzzing HTTP headers, specifically the Host: header.`
    - `ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u [http://academy.htb](http://academy.htb/):PORT/ -H 'Host: FUZZ.academy.htb'`
    - different response size as all academy.htb will be 200OK
- Filtering Results
    - by default by their HTTP code, which filters out code 404 NOT FOUND
    - we can filter it out with -fs 900.
    - `ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u [http://academy.htb](http://academy.htb/):PORT/ -H 'Host: FUZZ.academy.htb' -fs 900`

## Parameter Fuzzing

- [http://admin.academy.htb](http://admin.academy.htb/):PORT/admin/admin.php
- Tip: Fuzzing parameters may expose unpublished parameters that are publicly accessible. Such parameters tend to be less tested and less secured, so it is important to test such parameters for the web vulnerabilities we discuss in other modules.
- GET Request Fuzzing
    - [`http://admin.academy.htb](http://admin.academy.htb/):PORT/admin/admin.php?param1=key`
    - `/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt`
    - `ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u [http://admin.academy.htb](http://admin.academy.htb/):PORT/admin/admin.php?FUZZ=key -fs xxx`
- POST
    - To fuzz the data field with ffuf, we can use the -d flag, as we saw previously in the output of ffuf -h. We also have to add -X POST to send POST requests.
    - Tip: In PHP, "POST" data "content-type" can only accept "application/x-www-form-urlencoded". So, we can set that in "ffuf" with "-H 'Content-Type: application/x-www-form-urlencoded'".
    - `ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u [http://admin.academy.htb](http://admin.academy.htb/):PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`
    - `curl [http://admin.academy.htb](http://admin.academy.htb/):PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'`
- Value Fuzzing
    - Custom Wordlist
    - We'll start with a wordlist containing all numbers from 1-1000
    - `for i in $(seq 1 1000); do echo $i >> ids.txt; done`
    - `ffuf -w ids.txt:FUZZ -u [http://admin.academy.htb](http://admin.academy.htb/):PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`