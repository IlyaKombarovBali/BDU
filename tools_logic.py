import subprocess
import dns.resolver
import socket
import ssl

def get_whois(domain):
    """Возвращает вывод whois для домена"""
    try:
        result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=10)
        return result.stdout if result.returncode == 0 else f"Ошибка: {result.stderr}"
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