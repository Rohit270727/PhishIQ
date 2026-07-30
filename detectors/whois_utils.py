import socket
import datetime

socket.setdefaulttimeout(4)

def get_domain_age_days(domain):
    try:
        import whois
        core_domain = domain.split(":")[0]
        parts = core_domain.split(".")
        if len(parts) > 2:
            core_domain = ".".join(parts[-2:])

        w = whois.whois(core_domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return None

        if isinstance(creation, str):
            return None

        if creation.tzinfo is not None:
            now = datetime.datetime.now(creation.tzinfo)
        else:
            now = datetime.datetime.now()

        age_days = (now - creation).days
        return age_days
    except Exception:
        return None
