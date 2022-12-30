#### Configuration files
```sh
/etc/httpd/conf/httpd.conf
/etc/apache2/apache2.conf
```

#### VHOST configurations usually under
```sh
/etc/httpd/vhost.d/
```

#### Check Number of Connections (Change 22 23 00 if you want)
```sh
go to /var/log/httpd 

intDay=22; strMonth="Feb"; intYear="2017"; strLogFile=access_log; for loopLogFile in $(ls -1htr $strLogFile*); do echo "--------------------------- $loopLogFile -------------------------"; for loopDay in $intDay; do for strHour in 03 04 05; do for loopMinutes in {0..5}; do echo -en "$strMonth $intDay; $strHour:"$loopMinutes"0 - $strHour:"$loopMinutes"9:59..." ; zgrep -c "$loopDay/$strMonth/$intYear:$strHour:$loopMinutes" $loopLogFile; done; done; done; done;
```

#### Top 10 Ips:
```sh
grep "04/May/2017" /var/log/httpd/access_log | awk '{print $1}' | sort | uniq -c | sort -rn | head
```

##### Check to see how many httpd processes are open
```sh
go into "r-sysmon" or "recap" folder then run
```

##### Rsysmon
```sh
for i in {82..78}; do t=$(head -1 ps.log.$i); echo -n "$t: "; grep -c httpd ps.log.$i; done
```

##### Monitor Number of open httpd processes and Memory info in the same time
```sh
watch -n 1 "echo -n 'Apache Processes: ' && ps -C httpd --no-headers | wc -l && free -hm"
grep httpd -c ps.log.{1..45}
```

##### top 10 IP address accessing your Apache web server for domain, just run the following command.
```sh
awk '{ print $1}' access_log | sort | uniq -c | sort -nr | head -n 10
```

##### Check Server MaxClient Settings:
```sh
egrep -i 'serverlimi|maxclien' /etc/httpd/conf/httpd.conf
cat /etc/apache2/mods-enabled/mpm_prefork.conf
```

##### Check if server is hitting its MaxClient limit:
```sh
ps faux | grep http[d] | grep -v root -c
50
```

##### Run Apache Buddy:
```sh
curl -skL apachebuddy.pl | perl
curl -sL https://raw.githubusercontent.com/richardforth/apache2buddy/master/apache2buddy.pl | perl
```

##### Httpd status
```sh
/etc/init.d/httpd status
/etc/init.d/httpd fullstatus
```

##### Check configuration (Virtual Server's info as well)
```sh
httpd -S
httpd -S 2>&1 | grep 443
```

##### Check Access log for return codes
```sh
cat /var/log/httpd/access_log | cut -d ' ' -f 1-6,8-9 | grep 403
```

##### On eliner
```sh
echo -e "-------------------------------------------------------------------------------------------------------------------------"; date; echo -e "\nUptime & Load Average:"; w | head -1; echo -e "\nApache MaxClients Settings:";grep -i maxclients /etc/httpd/conf/httpd.conf | grep -v "#"; echo -e "\nCurrent Apache MaxClients Stats:"; pstree -G | grep httpd; echo -e "\nScanning recent error logs for MaxClients reached:";grep -i maxclients /var/log/httpd/error_log; echo -e "\nCurrent Memory Situation: "; free -m | head -4; echo -e "\n"; ps aux | grep httpd | awk '{ct=ct+1; sum=sum+$6} END { avg=sum/ct; print "Total httpd processes " ct " Avg apache usage (MB) " avg/1024}'; echo -e "\nConnections to server: "; netstat -pant | sed -e 's/::ffff://g' | awk -F' *|:' ' $5 ~ /80/ {print $6 } ' | sort | uniq -c | sort -rn | head; echo -e "\nMySQL Connections Stats:"; mysql -e "show status like 'max%';"; mysql -e "show global variables like 'max_connections';"; mysql -e "show global variables like 'wait_timeout';"; mysqladmin processlist; echo -e "-------------------------------------------------------------------------------------------------------------------------"
```
