import os
from dotenv import load_dotenv
import requests
from requests.exceptions import Timeout, ConnectionError
from requests import RequestException
from requests import HTTPError
from requests import Timeout
from requests import ConnectionError
from requests import RequestException
from django.views.decorators.csrf import csrf_exempt
load_dotenv()
import json
from django.http import JsonResponse


def consultar_deepseek(prompt: str) -> str:
    url = "https://api.deepseek.com/chat/completions"
    headers = {
        "Authorization": "Bearer sk-c297943ae3584467915805bc3c12f1de",  #{os.getenv('DEEPSEEK_API_KEY')} XDDDDD
        "Content-Type": "application/json"
    }

    payload = {
        "model": "deepseek-chat",  # o "deepseek-coder" si usas el modelo para código
        "messages": [
            {"role": "system", "content": "Eres un asistente útil que responde en español."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,
        "max_tokens": 5000
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=70)

        # Manejar errores HTTP con claridad
        if response.status_code == 402:
            return "Tu cuenta de DeepSeek no tiene crédito o acceso habilitado. Verifica tu plan en https://platform.deepseek.com"

        response.raise_for_status()

        data = response.json()
        return data["choices"][0]["message"]["content"].strip()

    except requests.exceptions.Timeout:
        return "Tiempo de espera agotado al contactar DeepSeek."

    except requests.exceptions.ConnectionError as conn_err:
        return f"No se pudo establecer conexión con DeepSeek. {str(conn_err)}"

    except requests.exceptions.HTTPError as http_err:
        return f"Error HTTP: {http_err.response.status_code} - {http_err.response.text}"

    except requests.exceptions.RequestException as req_err:
        return f"Error de solicitud: {str(req_err)}"

    except Exception as e:
        return f"Error inesperado: {str(e)}"
    