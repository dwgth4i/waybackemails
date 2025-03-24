# Usage

```
python3 waybackemails.py -d <domain>
```

# Description

This tool will take all subdomains from rapidDNS, crt.sh, alienvault, waybackurls and write into a text file. After gathering all of them, it will send a request to each entry and perform a regex check for email pattern and get all of them into a CSV file with email,domain headers.

NOTE: The file info.txt will include the possible accounts founded along with the emails.