import socket
import dns.resolver 
import requests

def whois_query(domain):
    whois_servers = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "info": "whois.afilias.net",
        "io": "whois.nic.io",
        "ai": "whois.ai",
        "app": "whois.nic.google",
        "dev": "whois.nic.dev",
        "design": "whois.nic.design",
        "blog": "whois.nic.blog",
        "us": "whois.nic.us",
        "uk": "whois.nic.uk",
        "ca": "whois.cira.ca",
        "au": "whois.auda.org.au",
        "nz": "whois.srs.net.nz",
        "jp": "whois.jprs.jp",
        "kr": "whois.kr",
        "cn": "whois.cnnic.cn",
        "in": "whois.registry.in",
        "br": "whois.registro.br",
        "mx": "whois.mx",
        "eu": "whois.eu",
        "fr": "whois.nic.fr",
        "de": "whois.denic.de",
        "nl": "whois.domain-registry.nl",
        "ru": "whois.tcinet.ru",
        "se": "whois.iis.se",
        "no": "whois.norid.no",
        "fi": "whois.fi",
        "dk": "whois.dk-hostmaster.dk",
        "my": "whois.mynic.my",
        "sg": "whois.sgnic.sg",
        "id": "whois.id",
        "hk": "whois.hkirc.hk",
        "tw": "whois.twnic.net.tw",
        "th": "whois.thnic.co.th",
        "ph": "whois.dot.ph",
        "vn": "whois.vnnic.vn",
        "la": "whois.nic.la",
        "tv": "whois.nic.tv",
        "ws": "whois.nic.ws",
        "fm": "whois.nic.fm",
        "nu": "whois.iis.nu",
        "tk": "whois.dot.tk",
        "pw": "whois.nic.pw",
        "uz": "whois.cctld.uz",
        "kg": "whois.domain.kg",
        "ae": "whois.aeda.net.ae",
        "sa": "saudinic.net.sa",
        "qa": "whois.registry.qa",
        "eg": "whois.egregistry.eg",
        "za": "co.za",
        "ng": "whois.nic.net.ng",
        "ke": "whois.kenic.or.ke",
      
    }

   
    additional_servers = {
        "lu": "whois.dns.lu",
        "be": "whois.dns.be",
        "at": "whois.nic.at",
        "ch": "whois.nic.ch",
        "it": "whois.nic.it",
        "es": "whois.nic.es",
        "pt": "whois.dns.pt",
        "pl": "whois.dns.pl",
        "cz": "whois.nic.cz",
        "hu": "whois.nic.hu",
        "ro": "whois.rotld.ro",
        "gr": "whois.ripe.net",
        "tr": "whois.nic.tr",
        "ir": "whois.nic.ir",
        "ru": "whois.tcinet.ru",
        "bg": "whois.register.bg",
        "hr": "whois.dns.hr",
        "si": "whois.register.si",
        "sk": "whois.sk-nic.sk",
        "lv": "whois.nic.lv",
        "lt": "whois.domreg.lt",
        "ee": "whois.tld.ee",
        "md": "whois.md",
        "by": "whois.cctld.by",
        "ua": "whois.ua",
        "rs": "whois.rnids.rs",
        "ba": "whois.dns.ba",
        "al": "whois.ripe.net",
        "mk": "whois.marnet.mk",
        "me": "whois.nic.me",
        "is": "whois.isnic.is",
        "fo": "whois.nic.fo",
        "gg": "whois.gg",
        "je": "whois.je",
        "im": "whois.nic.im",
        "gg": "whois.nic.gg",
        "je": "whois.channelisles.net",
        "sh": "whois.nic.sh",
        "ac": "whois.nic.ac",
        "io": "whois.nic.io",
        "tm": "whois.nic.tm",
        "mf": "whois.nic.mf",
        "aero": "whois.aero",
        "coop": "whois.nic.coop",
        "museum": "whois.museum",
        "int": "whois.iana.org",
        "arpa": "whois.iana.org",
      
    }

    whois_servers.update(additional_servers)  

    domain_parts = domain.split(".")
    if len(domain_parts) < 2:
        print("Format domain tidak valid")
        return

    extension = domain_parts[-1]
    if extension not in whois_servers:
        print(f"Tidak ada server WHOIS yang diketahui untuk ekstensi domain: {extension}")
        return

    whois_server = whois_servers[extension]
    whois_port = 43

    try:
        ip_addresses = dns.resolver.resolve(domain, 'A')
        ip = ip_addresses[0].to_text()
        port = socket.getservbyname('http', 'tcp')

        print(f"IP Address: {ip}")
        print(f"Port: {port}")

        with socket.create_connection((whois_server, whois_port)) as s:
            s.sendall((f"{domain}\r\n").encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            decoded_response = response.decode()

            parsed_info = parse_whois_response(decoded_response)
            display_whois_info(parsed_info)

            geolocation_info = get_geolocation_info(ip)
            display_geolocation_info(geolocation_info)
    except (socket.error, socket.timeout, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        print(f"Error terjadi saat mengambil informasi: {e}")

def parse_whois_response(response):
    parsed_info = {}
    lines = response.splitlines()
    for line in lines:
        line = line.strip()
        if line:
            key_value = line.split(":")
            if len(key_value) > 1:
                key = key_value[0].strip()
                value = ":".join(key_value[1:]).strip()
                parsed_info[key] = value
    return parsed_info

def display_whois_info(info):
    if info:
        print("Informasi WHOIS:")
        for key, value in info.items():
            print(f"{key}: {value}")
    else:
        print("Tidak ada informasi WHOIS yang ditemukan.")

def get_geolocation_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        geolocation_info = response.json()
        return geolocation_info
    except requests.RequestException as e:
        print(f"Gagal mendapatkan informasi geolokasi: {e}")
        return None

def display_geolocation_info(geolocation_info):
    if geolocation_info:
        print("Informasi Geolokasi:")
        print(f"Negara: {geolocation_info['country']}")
        print(f"Kota: {geolocation_info['city']}")
        print(f"Koordinat: {geolocation_info['lat']}, {geolocation_info['lon']}")
        print(f"Kode Pos: {geolocation_info['zip']}")
    else:
        print("Tidak ada informasi geolokasi yang ditemukan.")

if __name__ == "__main__":
    domain_name = input("Masukkan nama domain: ")
    whois_query(domain_name)