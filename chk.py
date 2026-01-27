from vulnscan import ensure_url_scheme, get_ip_address


domain_name = input("\nEnter the target domain : ")
domain_name = ensure_url_scheme(domain_name)


ip_address = get_ip_address(domain_name)

if ip_address:
    print('IP Address : ', ip_address)
else:
    print('Could not resolve IP address. Continuing with domain name.')
