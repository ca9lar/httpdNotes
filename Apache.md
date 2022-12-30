##### Useful links 
https://www.digitalocean.com/community/tutorials/how-to-troubleshoot-common-site-issues-on-a-linux-server

##### Command to manage the Apache webserver
```sh
apache2ctl (Debian)
httpd (Red Hat)
```

##### Start the Apache webserver daemon httpd
```sh
apache2ctl start
```

##### Display a brief status report
```sh
apache2ctl status
```

##### Display a detailed status report
```sh
apache2ctl fullstatus
```

##### Gracefully restart Apache; currently open connections are not aborted
```sh
apache2ctl graceful
```

##### Gracefully stop Apache; currently open connections are not aborted
```sh
apache2ctl graceful-stop
```

##### Test the configuration file, reporting any syntax error
```sh
apache2ctl configtest
```

##### List all loaded and shared modules
```sh
apache2ctl -M
httpd -M
```

##### Default document root directory
```sh
/var/www/html
```

##### Default document root directory for users' websites
```sh
$HOME/public_html
```

Web content must be readable by the user/group the Apache process runs as. For security reasons, it should be owned and
writable by the superuser or the webmaster user/group, not the Apache user/group.

##### Apache configuration file
```sh
/etc/httpd/conf/httpd.conf	(Red Hat)
/etc/apache2/httpd.conf		(Debian adn SUSE)
```

==================================================================================================== 
#### Methods of MPM (Multi-Processing Modules) operation of the Apache webserver
==================================================================================================== 
'prefork MPM'
A number of child processes is spawned in advance, with each child serving one connection.
Highly reliable due to Linux memory protection that isolates each child process

'worker MPM'
Multiple child processes spawn multiple threads, with each thread serving one connection.
More scalable but prone to deadlocks if third-party non-threadsafe modules are loaded
==================================================================================================== 

==================================================================================================== 
#### HTTPS
==================================================================================================== 
A secure web server (using HTTP over SSL i.e. HTTPS) hands over its public key to the client when the latter connects to it via port 443. The server s public key is signed by a CA (Certification Authority), whose validity is ensured by theroot certificates stored into the client s browser.
The openssl command and its user-friendly CA.pl script are the tools of the OpenSSL crypto library that can be usedto accomplish all public key crypto operations e.g. generate key pairs, Certificate Signing Requests, self-signed certificates.
Virtual hosting with HTTPS requires assigning an unique IP address for each virtual host; this because the SSL handshake (during which the server sends its certificate to the client s browser) takes place before the client sends the Host: header (which tells which virtual host the client wants to talk to).
A workaround for this is SNI (Server Name Indication) that makes the browser send the hostname in the first message of the SSL handshake. Another workaround is

# Configuration file for OpenSSL
```sh
/etc/ssl/openssl.cnf
```

# Configuration file for the mod_ssl module
```sh
/etc/httpd/conf.d/ssl.conf (Red Hat)
```
==================================================================================================== 

==================================================================================================== 
#### Apache configuration
==================================================================================================== 
'httpd.conf'

##### Name and port (if omitted, uses default HTTP port 80) of server
ServerName www.mysite.org:80

##### Root directory for config and log files
ServerRoot /etc/httpd

##### Contact address that the server includes in any HTTP error messages to the client. Can be an email address or an URL
ServerAdmin webmaster@mysite.org

##### Number of servers to start initially
StartServers 5

##### Minimum and maximum number of idle child server processes
MinSpareServers 5
MaxSpareServers 10

##### Max number of simultaneous requests that will be served; clients above this limit will get a HTTP error 503 - Service Unavailable.
'Prefork MPM': max number of child processes launched to serve requests. 
'Worker MPM': max total number of threads available to serve requests

MaxClients 256			(before v2.3.13)
MaxRequestWorkers 256		(after v2.3.13)

# Prefork MPM: max configured value for MaxRequestWorkers.
'Worker MPM' in conjunction with ThreadLimit, max configured value for MaxRequestWorkers
ServerLimit 256

# Worker MPM: number of threads created by each child process
ThreadsPerChild 25

# Worker MPM: max configured value for ThreadsPerChild
ThreadLimit 64

# Load the module mime_module by linking in the object file or library modules/mod_mime.so
LoadModule mime_module modules/mod_mime.so

# Make the server accept connections on the specified IP addresses (optional) and ports
Listen 10.17.1.1:80
Listen 10.17.1.5:8080

# User and group the Apache process runs as. For security reasons, this should not be root
User nobody
Group nobody
==================================================================================================== 
#### Main configuration directives
==================================================================================================== 
##### Directory in filesystem that maps to the root of the website
DocumentRoot /var/www/html

##### Map the URL http://www.mysite.org/image/ to the directory /mydir/pub/image in the filesystem. This allows Apache to serve content placed outside of the document root
Alias /image /mydir/pub/image

##### Media types file. The path is relative to ServerRoot
TypesConfig conf/mime.types

##### Map the specified filename extensions onto the specified content type. These entries adds to or override the entries from the media types file conf/mime.types
AddType image/jpeg jpeg jpg jpe

##### Redirect to a URL on the same host. 
	Status can be:
			permanent	return a HTTP status 301 - Moved Permanently
			temp		return a HTTP status 302 - Found (i.e. the resource was temporarily moved)
			seeother	return a HTTP status 303 - See Other
			gone		return a HTTP status 410 - Gone
		If status is omitted, default status temp is used

Redirect permanent /foo /bar

##### Redirect to a URL on a different host
Redirect /foo http://www.example.com/foo

##### Name of the distributed configuration file, which contains directives that apply to the document directory it is in and to all its subtrees
AccessFileName .htaccess

	Specify which global directives a .htaccess file can override:
		AuthConfig		authorization directives for directory protection
		FileInfo		document type and metadata
		Indexes			directory indexing
		Limit			host access control
		Options			specific directory features
		All			all directives
		None			no directive
==================================================================================================== 

==================================================================================================== 
#### Virtual hosts directives
==================================================================================================== 
##### Specify which IP address will serve virtual hosting. The argument can be an IP address, an address:port pair, or * for all IP addresses of the server. The argument will be repeated in the relevant <VirtualHost> directive
NameVirtualHost *

##### The first listed virtual host is also the default virtual host. It inherits those main settings that does not override. This virtual host answers to http://www.mysite.org , and also redirects there all HTTP requests on the domain mysite.org
```sh
<VirtualHost *:80>
	ServerName www.mysite.org
	ServerAlias mysite.org *.mysite.org
	DocumentRoot /var/www/vhosts/mysite
</VirtualHost>
````
# Name-based virtual host http://www.mysite2.org . Multiple name-based virtual hosts can share the same IP address; DNS must be configured accordingly to map each name to the correct IP address. Cannot be used with HTTPS
```sh
<VirtualHost *:80>
	ServerAdmin webmaster@www.mysite2.org
	ServerName www.mysite2.org
	DocumentRoot /var/www/vhosts/mysite2
	ErrorLog /var/www/logs/mysite2
</VirtualHost>
```
	
# Port-based virtual host answering to connections on port 8080. In this case the config file must contain a Listen 8080 directive
```sh
<VirtualHost *:8080>
	ServerName www.mysite3.org
	DocumentRoot /var/www/vhosts/mysite3
</VirtualHost>
```
# IP-based virtual host answering to http://10.17.1.5
```sh
<VirtualHost 10.17.1.5:80>
	ServerName www.mysite4.org
	DocumentRoot /var/www/vhosts/mysite4
</VirtualHost>
```
==================================================================================================== 
#### Logging directives
==================================================================================================== 
##### Specify the format of a log
```sh
LogFormat "%h %l %u %t \"%r\" %>s %b"
```
##### Specify a nickname (here, "common") for a log format. 
```sh
# This one is the CLF (Common Log Format) defined as such: 
	%h	IP address of the client host
	%l	Identity of client as determined by identd
	%u	User ID of client making the request
	%t	Timestamp the server completed the request
	%r	Request as done by the user
	%s	Status code sent by the server to the client
	%b	Size of the object returned, in bytes
```
# Set up a log filename, with the format or (as in this case) the nickname specified
```sh
CustomLog /var/log/httpd/access_log common
```
# Set up a log filename, with format determined by the most recent LogFormat directive which did not define a nickname
```sh
TransferLog /var/log/httpd/access_log
```
# Organize log rotation every 24 hours
```sh
TransferLog "|rotatelogs access_log 86400"
```
# Disable DNS hostname lookup to save network traffic. Hostnames can be resolved later by processing the log file: 'logresolve <access_log >accessdns_log'
```sh
HostnameLookups Off
```
==================================================================================================== 
#### Limited scope directives
==================================================================================================== 
##### Limit the scope of the specified directives to the directory /var/www/html/foobar and its subdirectories
```sh
<Directory "/var/www/html/foobar">
	[list of directives]
</Directory>
```
##### Limit the scope of the specified directive to the URL http://www.mysite.org/foobar/ and its subdirectories
```sh
<Location /foobar>
	[list of directives]
</Location>
```
==================================================================================================== 
#### Directory protection directives
==================================================================================================== 
##### Name of the realm. The client will be shown the realm name and prompted to enter an user and password
```sh
<Directory "/var/www/html/protected">
	AuthName "Protected zone"
```
##### Type of user authentication: Basic, Digest, Form, or None
	```sh
AuthType Basic
``` 
##### User database file. Each line is in the format user:encrypted_password 
##### To add an user jdoe to the database file, use the command: htpasswd -c /var/www/.htpasswd jdoe (will prompt for his password)
```sh
AuthUserFile "/var/www/.htpasswd"
```
##### Group database file. Each line contains a groupname followed by all member usernames: mygroup: jdoe ksmith mgreen
```sh
AuthGroupFile "/var/www/.htgroup"
```
##### Control who can access the protected resource. 
```sh
valid-user 	any user in the user database file
user jdoe	only the specified user
roup mygroup	only the members of the specified group

	equire valid-user
```
##### Control which host can access the protected resource
```sh
	Allow from 10.13.13.0/24
```
##### Set the access policy concerning user and host control.
```sh
All	both Require and Allow criteria must be satisfied
Any	any of Require or Allow criteria must be satisfied

Satisfy Any

##### Control the evaluation order of Allow and Deny directives.
```sh
Allow,Deny 	First, all Allow directives are evaluated; at least one must match, or the request is rejected. Next, all Deny directives are evaluated; if any matches, the request is rejected. Last, any requests which do not match an Allow or a Deny directive are denied

		Deny,Allow	First, all Deny directives are evaluated; if any match, the request is denied unless it also matches an Allow directive. Any requests which do not match any Allow or Deny directives are permitted
```
</Directory>
==================================================================================================== 
#### SSL/TLS directives (module mod_ssl)
==================================================================================================== 
##### SSL server certificate
```sh
SSLCertificateFile \
/etc/httpd/conf/ssl.crt/server.crt
```
##### SSL server private key (for security reasons, this file must be mode 600 and owned by root)
```sh
SSLCertificateKeyFile \
/etc/httpd/conf/ssl.key/server.key
```
##### Directory containing the certificates of CAs. Files in this directory are PEM-encoded and accessed via symlinks to hash filenames
```sh
SSLCACertificatePath \
/usr/local/apache2/conf/ssl.crt/
```
##### Certificates of CAs. Certificates are PEM-encoded and concatenated in a single bundle file in order of preference
```sh
SSLCACertificateFile \
/usr/local/apache2/conf/ssl.crt/ca-bundle.crt
```
##### Certificate chain of the CAs. Certificates are PEM-encoded and concatenated from the issuing CA certificate of the server certificate to the root CA certificate. Optional
```sh
SSLCertificateChainFile \
/usr/local/apache2/conf/ssl.crt/ca.crt
```
##### Enable the SSL/TLS Protocol Engine
```sh
SSLEngine on
```
##### SSL protocol flavors that the client can use to connect to server. 
```sh
Possible values are:
	SSLv2 (deprecated)
	SSLv3
	TLSv1
	TLSv1.1
	TLSv1.2
	All	(all the above protocols)

SSLProtocol +SSLv3 +TLSv1.2
```
##### Cipher suite available for the SSL handshake (key exchange algorithms, authentication algorithms, cipher/encryption algorithms, MAC digest algorithms) 
```sh
SSLCipherSuite \
ALL:!aDH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP

# Server response header field to send back to client.
	Possible values are:
		Prod 				sends Server: Apache
		Major				sends Server: Apache/2
		Minor 				sends Server: Apache/2.4
		Minimal 			sends Server: Apache/2.4.2
		OS 				sends Server: Apache/2.4.2 (Unix)
		Full 	(or not specified)	sends Server: Apache/2.4.2 (Unix) PHP/4.2.2 MyMod/1.2

ServerTokens Full
```
##### Trailing footer line on server-generated documents.
```sh
Possible values are:
		Off				no footer line (default)
		On				server version number and ServerName
		EMail 				as above, plus a mailto link to ServerAdmin

ServerSignature Off
```
##### Certificate verification level for client authentication.
```sh
Possible values are:
	none				no client certificate is required 
	require 			the client needs to present a validcertificate
	optional 			the client may present a valid certificate (this option is unusedas it doesn't work on all browsers)
	optional_no_ca 			the client may present a valid certificate but it doesnt need to be successfully verifiable (this option has not much purpose and is used only for SSL testing)

SSLVerifyClient none
```
# Enable TRACE requests
TraceEnable on
==================================================================================================== 

# Use apache buddy to analyze current settings
curl -sL https://raw.githubusercontent.com/richardforth/apache2buddy/master/apache2buddy.pl | perl

# One liner
echo -e "-------------------------------------------------------------------------------------------------------------------------"; date; echo -e "\nUptime & Load Average:"; w | head -1; echo -e "\nApache MaxClients Settings:";grep -i maxclients /etc/httpd/conf/httpd.conf | grep -v "#"; echo -e "\nCurrent Apache MaxClients Stats:"; pstree -G | grep httpd; echo -e "\nScanning recent error logs for MaxClients reached:";grep -i maxclients /var/log/httpd/error_log; echo -e "\nCurrent Memory Situation: "; free -m | head -4; echo -e "\n"; ps aux | grep httpd | awk '{ct=ct+1; sum=sum+$6} END { avg=sum/ct; print "Total httpd processes " ct " Avg apache usage (MB) " avg/1024}'; echo -e "\nConnections to server: "; netstat -pant | sed -e 's/::ffff://g' | awk -F' *|:' ' $5 ~ /80/ {print $6 } ' | sort | uniq -c | sort -rn | head; echo -e "\nMySQL Connections Stats:"; mysql -e "show status like 'max%';"; mysql -e "show global variables like 'max_connections';"; mysql -e "show global variables like 'wait_timeout';"; mysqladmin processlist; echo -e "-------------------------------------------------------------------------------------------------------------------------"

# Check the access logs for number of connections
for i in `ls -1 *-access_log`; do echo "*********** Checking $i Log ***************"; grep "`date +%d/%b`" /var/log/httpd/$i | cut -d[ -f2 | cut -d] -f1 | awk -F: '{print $2":00"}' | sort -n | uniq -c; done

########################### < Apache Stuff > ###########################
 
 <REWRITE for non-www to www >
     RewriteEngine on
     RewriteCond %{HTTP_HOST} ^domain\.com [NC]
     RewriteRule ^(.*)$ http://www.domain.com/$1 [L,R=301]
 </REWRITE>
 More documentation at http://www.webweaver.nu/html-tips/web-redirection.shtml
 
 SHOW RUNNING MODULES
         httpd -t -D DUMP_MODULES
 
 MOST POPULAR IP/PAGES
         tail -5000 /var/log/httpd/access_log | awk '{print $1, $7}' | sort | uniq -c | sort -rn | head -10
         tail -5000 /var/log/httpd/access_log | awk '{print $7}' | sort | uniq -c | sort -rn | head -n 20

BLOCK AN IP ADDRESS TO ACCESS TO SITE:
	ip route add blackhole <IP>

 SHOW THE TOP 10 HITS sorted by IP address:
 
grep "12/Jan/2018:15:" /var/www/html/*/logs/2018-01-12_access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head        

 ALL HITS DURING AN HOUR
         grep -c 24/May/2010:21 /var/log/httpd/access_log

 TOP REQUESTS WITHIN A TIME FRAME:
sed -n '/12\/Jan\/2018:18/,/12\/Jan\/2018:22:59/p' /var/log/httpd/access_log | awk '{print $1,$2,$7,$8}' | sort | uniq -c | sort -nr | head -20
 
  40401 w.it.net 86.188.XX.XX "POST /aac/index.php
  40217 c.r.com 162.13.XX.XX "POST /webservice/index.php
  32030 w.r.net 86.188.XX.XX "OPTIONS /aac/index.php

 APACHE MEMORY USAGE        
         ps -eo rsz,args | grep httpd | awk ' { SUM += $1 } END { print "Memory used by Apache = "SUM/1024 " Megs" "\nNumber of process runing = " NR "\nAverage of each process mem usage = " SUM/1024/NR " Megs"} '
 
#################################################################################
# some examples of more simple rewrite configurations
==========================================================
Rewrite one domain to another
-------------------------
RewriteEngine on
RewriteCond %{HTTP_HOST} ^(www.)?example.com [NC]
RewriteRule ^(.*)$ http://www.google.com$1 [R=301,L]
-------------------------

Redirect a path to a new domain
-------------------------

Redirect 301 /path http://www.example.com
Redirect 301 /otherpath/somepage.php http://other.example.com
-------------------------

Rewrite page with query string, and strip query string
-------------------------
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteCond %{REQUEST_FILENAME} !-l
RewriteCond %{REQUEST_URI} ^/pages/pages\.php$
RewriteCond %{QUERY_STRING} ^page=[0-9]*$
RewriteRule ^.*$ http://www.example.com/path/? [R=301,L]
-------------------------

Force all URL’s to be lowercase
Please note, this must be in the Apache VirtualHost config, it will not work in the .htaccess.
-------------------------
RewriteEngine On
RewriteMap lc int:tolower
RewriteCond %{REQUEST_URI} [A-Z]
RewriteRule (.*) ${lc:$1} [R=301,L]
-------------------------
==========================================================
