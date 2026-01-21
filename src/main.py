import os
import json
import pandas as pd
import requests
import time
import logging

# Configuración de logging
logging.basicConfig(level=logging.INFO)

# Cargar variables de entorno
from dotenv import load_dotenv
load_dotenv()

VT_API_KEY = os.getenv('VT_API_KEY')
BASE_URL_COUNTRIES = os.getenv('BASE_URL_COUNTRIES')

# Función para consultar la API de VirusTotal

def query_virustotal(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
    "accept": "application/json",
    "x-apikey": VT_API_KEY
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Lanza un error si el status_code no es 200
        data = response.json()
        return {
            'reputation': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0),
            'harmless': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('harmless', 0),
            'malicious': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0),
            'suspicious': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('suspicious', 0),
            'undetected': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('undetected', 0),
            'campos': data.get('data', {}).get('attributes', {}).get('country', None),
            'owners': data.get('data', {}).get('attributes', {}).get('as_owner', None),
            'analis': data.get('data', {}).get('attributes', {}).get('last_analysis_results', {}).get('Acronis', {}).get('category', None),
            'resul': data.get('data', {}).get('attributes', {}).get('last_analysis_results', {}).get('Acronis', {}).get('result', None)
        }
    except requests.exceptions.HTTPError as err:
        logging.error(f'Error en la consulta de VirusTotal para {ip}: {err}')
        return None
    except Exception as e:
        logging.error(f'Error inesperado para {ip}: {e}')
        return None
    
# Función para consultar la API de países

def query_country(country):
    url = f'{BASE_URL_COUNTRIES}/{country}'
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        return {
            'region': data.get('region'),
            'capital': data.get('capital')
        }
    except requests.exceptions.HTTPError as err:
        logging.error(f'Error en la consulta de país para {country}: {err}')
        return None
    except Exception as e:
        logging.error(f'Error inesperado para {country}: {e}')
        return None