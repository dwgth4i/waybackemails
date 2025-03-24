import requests
import re

email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
account_pattern = r"(?<!\w)@\w{2,}"

def process_domain(domain, csv_writer=None):
    """Fetch emails and usernames from a domain, write emails to CSV if enabled."""
    domain = domain.strip()
    url = "https://" + domain  

    try:
        r = requests.get(url, timeout=5)
        emails = set(re.findall(email_pattern, r.text))
        usernames = set(re.findall(account_pattern, r.text))

        result = None
        if emails or usernames:
            result = f"Findings in {domain}:\n"
            if emails:
                result += "".join(f"  • Email: {email}\n" for email in emails)
                # Write emails to CSV if a writer is provided
                if csv_writer:
                    for email in emails:
                        csv_writer.writerow([email, domain])
            
            if usernames:
                result += "".join(f"  • Possible Account: {username}\n" for username in usernames)
            result += "\n"

        return result

    except requests.RequestException as e:
        with open(f"./error.txt", "a") as f:
            f.write(f"Error fetching {domain}: {e}\n")
    return None
