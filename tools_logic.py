import subprocess
import dns.resolver
import socket
import ssl
import whois
import requests
import whois


import whois

def get_whois(domain):
    try:
        w = whois.query(domain)
        if w is None:
            return f"Домен {domain} не найден"
        result = f"Domain: {w.name}\n"
        result += f"Registrar: {w.registrar}\n"
        result += f"Creation Date: {w.creation_date}\n"
        result += f"Expiration Date: {w.expiration_date}\n"
        result += f"Name Servers: {', '.join(w.name_servers) if w.name_servers else '—'}\n"
        return result
    except Exception as e:
        return f"Ошибка: {str(e)}"

def get_dns_records(domain, record_type='A'):
    """Возвращает DNS-записи указанного типа"""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except Exception as e:
        return [f"Ошибка: {str(e)}"]

def get_ssl_info(domain):
    """Возвращает информацию о SSL-сертификате"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return {"error": str(e)}