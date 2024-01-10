Adding CA cert to linux
Copy `sudp cp foo.crt /usr/local/share/ca-certificates/foo.crt` 
Update `sudo update-ca-certificates` 

Copying from server to local host 
`scp -P <port> username@server-ip:directory-location local`
