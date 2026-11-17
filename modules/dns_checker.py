import dns.resolver

def check_dns(domain, selector="google"):
    results = {"domain": domain, "spf": None, "dmarc": None, "dkim": None}
    
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        for rdata in txt_records:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                results["spf"] = txt
    except Exception as e:
        results["spf"] = f"Error: {str(e)}"

    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_records:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                results["dmarc"] = txt
    except Exception as e:
        results["dmarc"] = f"Error: {str(e)}"

    try:
        dkim_records = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
        for rdata in dkim_records:
            txt = rdata.to_text().strip('"')
            if "DKIM1" in txt or "p=" in txt:
                results["dkim"] = txt
    except Exception as e:
        results["dkim"] = f"Error: {str(e)}"

    return results