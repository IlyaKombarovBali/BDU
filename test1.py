import requests
import json

# API endpoint with token and IP
url = 'https://api.2ip.io/193.233.63.39?token=np34wtt2fgt28ove&lang=ru'

try:
    # Send GET request
    response = requests.get(url)
    # Raise an exception for bad HTTP status codes
    response.raise_for_status()
    # Ответ api.2ip.io — см. документацию; ключи как в реальном JSON
    data = response.json()
    ip = data.get("ip")
    city = data.get("city")
    region = data.get("region")
    country = data.get("country")
    code = data.get("code")
    emoji = data.get("emoji")
    lat = data.get("lat")
    lon = data.get("lon")
    timezone = data.get("timezone")
    asn = data.get("asn") or {}
    asn_id = asn.get("id")
    asn_name = asn.get("name")
    asn_hosting = asn.get("hosting")

    print(
        f"IP: {ip}\n"
        f"Страна: {country} ({code}) {emoji or ''}\n"
        f"Регион: {region}\n"
        f"Город: {city}\n"
        f"Координаты: {lat}, {lon}\n"
        f"Часовой пояс: {timezone}\n"
        f"ASN: {asn_id} \nИнтернет провайдер: {asn_name}"
    )

except requests.exceptions.RequestException as e:
    print(f"Request error: {e}")
except json.JSONDecodeError as e:
    print(f"Не JSON в ответе: {e}")