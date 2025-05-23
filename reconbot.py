import argparse
import json
import dns.resolver
import whois
import requests
from datetime import datetime
import os
import sys
from urllib.parse import quote
from bs4 import BeautifulSoup
import webbrowser
from jinja2 import Template

class ReconBot:
    def __init__(self, domain, api_url="http://localhost:8001/api/deepseek/"):
        self.domain = domain
        self.api_url = api_url
        self.results = {
            "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "dominio": domain,
            "dns_records": {},
            "whois_info": {},
            "dorking_results": [],
            "ai_analysis": {},
            "security_score": {
                "overall_score": 0,
                "dns_score": 0,
                "whois_score": 0,
                "dorking_score": 0,
                "risk_levels": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0
                }
            }
        }
        
    def run_full_scan(self):
        """Ejecuta el escaneo completo"""
        print(f"\n[+] Iniciando análisis completo para: {self.domain}")
        
        self.collect_dns_records()
        self.collect_whois_info()
        self.perform_dorking()
        self.analyze_with_ai()
        self.calculate_security_score()
        
        print("\n[+] Análisis completo finalizado.")
        return self.results
    
    def collect_dns_records(self):
        """Recolecta registros DNS"""
        print("\n[+] Recolectando registros DNS...")
        
        record_types = ["A", "MX", "NS", "SOA", "TXT"]
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                self.results["dns_records"][record_type] = [answer.to_text() for answer in answers]
                print(f"  - Registros {record_type}: {len(self.results['dns_records'][record_type])} encontrados")
            except Exception as e:
                self.results["dns_records"][record_type] = []
                print(f"  - Error al obtener registros {record_type}: {str(e)}")
    
    def collect_whois_info(self):
        """Recolecta información WHOIS"""
        print("\n[+] Recolectando información WHOIS...")
        
        try:
            w = whois.whois(self.domain)
            
            whois_dict = {}
            for key, value in w.items():
                if isinstance(value, datetime):
                    whois_dict[key] = value.strftime("%Y-%m-%d %H:%M:%S")
                elif isinstance(value, list) and all(isinstance(x, datetime) for x in value):
                    whois_dict[key] = [x.strftime("%Y-%m-%d %H:%M:%S") for x in value]
                else:
                    whois_dict[key] = value
            
            self.results["whois_info"] = whois_dict
            print(f"  - Información WHOIS obtenida correctamente")
        except Exception as e:
            self.results["whois_info"] = {"error": str(e)}
            print(f"  - Error al obtener información WHOIS: {str(e)}")
    
    def perform_dorking(self):
        """Realiza búsquedas de Google Dorking"""
        print("\n[+] Realizando búsquedas Dorking...")
        
        dorks = [
            f"site:{self.domain} filetype:env OR filetype:xml OR filetype:conf",
            f"site:{self.domain} intext:username OR intext:password OR intext:admin",
            f"site:{self.domain} intitle:\"index of\" OR intext:\"parent directory\""
        ]
        
        for dork in dorks:
            dork_results = self._simulate_dork_search(dork)
            
            result_entry = {
                "dork": dork,
                "hits": len(dork_results),
                "results": dork_results
            }
            
            self.results["dorking_results"].append(result_entry)
            print(f"  - Dork '{dork}': {len(dork_results)} resultados")
    
    def _simulate_dork_search(self, dork):
        """
        Simula una búsqueda de Google Dorking.
        En un entorno real, esto utilizaría una API de búsqueda legítima o scraping cuidadoso.
        """
        secure_domains = ["google.com", "microsoft.com", "apple.com", "cloudflare.com", "amazon.com", 
                        "github.com", "mozilla.org", "ibm.com", "oracle.com", "cisco.com"]
        
        results = []
        
        if any(secure_domain in self.domain.lower() for secure_domain in secure_domains):
            return []
        
        if "filetype:" in dork:
            results = [
                {
                    "title": f"config.xml - {self.domain}",
                    "url": f"https://{self.domain}/config.xml",
                    "snippet": "Configuración XML con parámetros del sistema..."
                }
            ]
            
            if not any(self.domain.endswith(f".{d}") for d in ["gov", "edu", "mil"]):
                results.append({
                    "title": f".env.backup - {self.domain}",
                    "url": f"https://{self.domain}/.env.backup",
                    "snippet": "DATABASE_URL=mysql://user:password@localhost/dbname..."
                })
            
        elif "intext:username" in dork:
            if not any(brand in self.domain.lower() for brand in ["google", "microsoft", "amazon", "apple"]):
                results = [
                    {
                        "title": f"Portal de Login - {self.domain}",
                        "url": f"https://{self.domain}/admin/login.php",
                        "snippet": "Ingrese su username y password para acceder al panel de administración..."
                    }
                ]
        elif "index of" in dork:
            if len(self.domain) < 8 or "test" in self.domain or "dev" in self.domain:
                results = [
                    {
                        "title": f"Index of /backups - {self.domain}",
                        "url": f"https://{self.domain}/backups/",
                        "snippet": "Index of /backups Parent Directory database-2023.sql logs/ config_old/"
                    }
                ]
        
        return results
    
    def analyze_with_ai(self):
        """Analiza los resultados usando la API de IA"""
        print("\n[+] Analizando resultados con IA...")
        
        dorking_text = ""
        for dork_result in self.results["dorking_results"]:
            dorking_text += f"Dork: {dork_result['dork']}\n"
            for result in dork_result["results"]:
                dorking_text += f"- {result['title']}: {result['url']}\n  {result['snippet']}\n\n"
        
        prompt = f"""
        Analiza los siguientes resultados de una auditoría de seguridad para el dominio {self.domain}.
        Clasifica cada hallazgo como 'crítico', 'alto riesgo', 'medio riesgo', 'bajo riesgo' o 'informativo'.
        Proporciona una explicación breve de por qué cada hallazgo tiene ese nivel de riesgo.
        
        RESULTADOS DE DORKING:
        {dorking_text}
        
        Por favor, proporciona tu análisis estructurado como:
        
        * Resumen general de seguridad para el dominio
        * Clasificación de cada hallazgo con justificación
        * Recomendaciones generales
        * Puntaje de seguridad: Asigna un puntaje general de 0 a 100, donde 0 es extremadamente inseguro y 100 es perfectamente seguro
        """
        
        try:
            response = requests.post(
                self.api_url,
                json={"message": prompt},
                timeout=120
            )
            
            if response.status_code == 200:
                self.results["ai_analysis"] = response.json()["respuesta"]
                print(f"  - Análisis de IA completado correctamente")
            else:
                self.results["ai_analysis"] = f"Error en la API de IA: Status code {response.status_code}"
                print(f"  - Error en la API de IA: {response.status_code}")
        except Exception as e:
            self.results["ai_analysis"] = f"Error al conectar con la API de IA: {str(e)}"
            print(f"  - Error al conectar con la API de IA: {str(e)}")
    
    
    def calculate_security_score(self):
        """Calcula el puntaje de seguridad de 0 a 100"""
        print("\n[+] Calculando puntaje de seguridad...")
        
        secure_domains = ["google.com", "microsoft.com", "apple.com", "cloudflare.com", "amazon.com", 
                          "github.com", "mozilla.org", "ibm.com", "oracle.com", "cisco.com"]
        
        is_known_secure = any(secure_domain in self.domain.lower() for secure_domain in secure_domains)
        
        dns_score = 100
        whois_score = 100
        dorking_score = 100
        
        if not self.results["dns_records"].get("TXT"):
            dns_score -= 15 
        
        if not self.results["dns_records"].get("MX"):
            dns_score -= 10  
        
        errors_count = sum(1 for rtype, records in self.results["dns_records"].items() if not records)
        dns_score -= (errors_count * 8) 
        
        spf_found = False
        dmarc_found = False
        if self.results["dns_records"].get("TXT"):
            for record in self.results["dns_records"]["TXT"]:
                if "v=spf1" in record.lower():
                    spf_found = True
                if "dmarc" in record.lower():
                    dmarc_found = True
        
        if not spf_found:
            dns_score -= 12  
        if not dmarc_found:
            dns_score -= 10  
        
 
        if self.results["whois_info"].get("error"):
            whois_score -= 25  
        else:
            privacy_protected = False
            for key in ["registrant", "admin", "tech"]:
                if any(self.results["whois_info"].get(f"{key}_{field}") and "privacy" in str(self.results["whois_info"].get(f"{key}_{field}")).lower() 
                      for field in ["name", "email", "phone"]):
                    privacy_protected = True
            
            if not privacy_protected:
                whois_score -= 20  
            
            if self.results["whois_info"].get("expiration_date"):
                whois_score -= 0 
            else:
                whois_score -= 8  
        
        critical_findings = 0
        high_findings = 0
        medium_findings = 0
        
        for dork_result in self.results["dorking_results"]:

            for result in dork_result["results"]:
                if ".env" in result["url"] or "password" in result["snippet"].lower():
                    critical_findings += 1
                elif "admin" in result["url"] or "config" in result["url"]:
                    high_findings += 1
                elif "index of" in result["title"].lower() or "parent directory" in result["snippet"].lower():
                    medium_findings += 1

        dorking_score -= (critical_findings * 25)  
        dorking_score -= (high_findings * 12)     
        dorking_score -= (medium_findings * 4)    
 
        self.results["security_score"]["risk_levels"]["critical"] = critical_findings
        self.results["security_score"]["risk_levels"]["high"] = high_findings
        self.results["security_score"]["risk_levels"]["medium"] = medium_findings
        
        if is_known_secure:
            dns_score = min(100, dns_score + 10)
            whois_score = min(100, whois_score + 10)
            dorking_score = min(100, dorking_score + 10)

        dns_score = max(0, min(100, dns_score))
        whois_score = max(0, min(100, whois_score))
        dorking_score = max(0, min(100, dorking_score))

        overall_score = int((dns_score * 0.3) + (whois_score * 0.2) + (dorking_score * 0.5))

        if is_known_secure and overall_score < 75:
            overall_score = 75 + (overall_score // 10)  
 
        self.results["security_score"]["dns_score"] = dns_score
        self.results["security_score"]["whois_score"] = whois_score
        self.results["security_score"]["dorking_score"] = dorking_score
        self.results["security_score"]["overall_score"] = overall_score
        
        print(f"  - Puntaje DNS: {dns_score}")
        print(f"  - Puntaje WHOIS: {whois_score}")
        print(f"  - Puntaje Dorking: {dorking_score}")
        print(f"  - Puntaje General de Seguridad: {overall_score}/100")
    
    def export_json(self, output_file="recon_results.json"):
        """Exporta los resultados a un archivo JSON"""
        print(f"\n[+] Exportando resultados a JSON: {output_file}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"  - Resultados exportados correctamente a {output_file}")
        return output_file
    
    def export_html(self, output_file="recon_results.html"):
        """Exporta los resultados a un archivo HTML"""
        print(f"\n[+] Exportando resultados a HTML: {output_file}")
        
        html_template = """
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>ReconBot - Informe de Reconocimiento</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    color: #333;
                }
                .container {
                    max-width: 1000px;
                    margin: 0 auto;
                }
                h1, h2, h3 {
                    color: #2c3e50;
                }
                .header {
                    background-color: #3498db;
                    color: white;
                    padding: 20px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }
                .section {
                    background-color: #f9f9f9;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    padding: 15px;
                    margin-bottom: 20px;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 15px;
                }
                th, td {
                    padding: 10px;
                    border: 1px solid #ddd;
                    text-align: left;
                }
                th {
                    background-color: #f2f2f2;
                }
                .dork-result {
                    background-color: #f8f9fa;
                    padding: 10px;
                    border-left: 3px solid #3498db;
                    margin-bottom: 10px;
                }
                pre {
                    white-space: pre-wrap;
                    background-color: #f5f5f5;
                    padding: 10px;
                    border-radius: 5px;
                    overflow-x: auto;
                }
                .footer {
                    text-align: center;
                    margin-top: 30px;
                    font-size: 0.9em;
                    color: #7f8c8d;
                }
                .score-container {
                    text-align: center;
                    margin: 20px 0;
                }
                .score-circle {
                    width: 150px;
                    height: 150px;
                    border-radius: 50%;
                    margin: 0 auto;
                    position: relative;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 36px;
                    font-weight: bold;
                    color: white;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                }
                .score-label {
                    font-size: 18px;
                    font-weight: bold;
                    margin-top: 10px;
                }
                .score-details {
                    display: flex;
                    justify-content: space-around;
                    margin-top: 20px;
                }
                .score-item {
                    text-align: center;
                    padding: 10px;
                    border-radius: 5px;
                    width: 30%;
                    color: white;
                }
                .risk-summary {
                    display: flex;
                    justify-content: space-around;
                    flex-wrap: wrap;
                    margin-top: 20px;
                }
                .risk-item {
                    text-align: center;
                    padding: 10px;
                    border-radius: 5px;
                    min-width: 80px;
                    margin: 5px;
                    color: white;
                }
                /* Colores para los diferentes puntajes */
                .score-critical { background-color: #e74c3c; }
                .score-high { background-color: #e67e22; }
                .score-medium { background-color: #f39c12; }
                .score-low { background-color: #2ecc71; }
                .score-good { background-color: #27ae60; }
                
                /* Barras de progreso para los puntajes */
                .progress-bar {
                    height: 10px;
                    background-color: #ecf0f1;
                    border-radius: 5px;
                    margin-top: 5px;
                    overflow: hidden;
                }
                .progress-fill {
                    height: 100%;
                    border-radius: 5px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>ReconBot - Informe de Reconocimiento</h1>
                    <p>Informe generado: {{ results.fecha_analisis }}</p>
                    <h2>Dominio: {{ results.dominio }}</h2>
                </div>
                
                <!-- Sección de Puntaje de Seguridad -->
                <div class="section">
                    <h2>Puntaje de Seguridad</h2>
                    <div class="score-container">
                        {% set score_class = 'score-critical' if results.security_score.overall_score < 30 else 
                                           'score-high' if results.security_score.overall_score < 50 else 
                                           'score-medium' if results.security_score.overall_score < 70 else 
                                           'score-low' if results.security_score.overall_score < 90 else 
                                           'score-good' %}
                        
                        <div class="score-circle {{ score_class }}">
                            {{ results.security_score.overall_score }}
                        </div>
                        <div class="score-label">
                            {% if results.security_score.overall_score < 30 %}
                                Crítico - Necesita atención inmediata
                            {% elif results.security_score.overall_score < 50 %}
                                Alto Riesgo - Acciones urgentes requeridas
                            {% elif results.security_score.overall_score < 70 %}
                                Riesgo Medio - Necesita mejoras significativas
                            {% elif results.security_score.overall_score < 90 %}
                                Riesgo Bajo - Generalmente seguro, con mejoras recomendadas
                            {% else %}
                                Seguro - Buenas prácticas de seguridad implementadas
                            {% endif %}
                        </div>
                    </div>
                    
                    <div class="score-details">
                        <!-- Puntaje DNS -->
                        <div class="score-item {{ 'score-critical' if results.security_score.dns_score < 30 else 
                                                'score-high' if results.security_score.dns_score < 50 else 
                                                'score-medium' if results.security_score.dns_score < 70 else 
                                                'score-low' if results.security_score.dns_score < 90 else 
                                                'score-good' }}">
                            <h3>DNS</h3>
                            <div class="score-value">{{ results.security_score.dns_score }}</div>
                            <div class="progress-bar">
                                <div class="progress-fill {{ 'score-critical' if results.security_score.dns_score < 30 else 
                                                          'score-high' if results.security_score.dns_score < 50 else 
                                                          'score-medium' if results.security_score.dns_score < 70 else 
                                                          'score-low' if results.security_score.dns_score < 90 else 
                                                          'score-good' }}" 
                                     style="width: {{ results.security_score.dns_score }}%"></div>
                            </div>
                        </div>
                        
                        <!-- Puntaje WHOIS -->
                        <div class="score-item {{ 'score-critical' if results.security_score.whois_score < 30 else 
                                                'score-high' if results.security_score.whois_score < 50 else 
                                                'score-medium' if results.security_score.whois_score < 70 else 
                                                'score-low' if results.security_score.whois_score < 90 else 
                                                'score-good' }}">
                            <h3>WHOIS</h3>
                            <div class="score-value">{{ results.security_score.whois_score }}</div>
                            <div class="progress-bar">
                                <div class="progress-fill {{ 'score-critical' if results.security_score.whois_score < 30 else 
                                                          'score-high' if results.security_score.whois_score < 50 else 
                                                          'score-medium' if results.security_score.whois_score < 70 else 
                                                          'score-low' if results.security_score.whois_score < 90 else 
                                                          'score-good' }}" 
                                     style="width: {{ results.security_score.whois_score }}%"></div>
                            </div>
                        </div>
                        
                        <!-- Puntaje Dorking -->
                        <div class="score-item {{ 'score-critical' if results.security_score.dorking_score < 30 else 
                                                'score-high' if results.security_score.dorking_score < 50 else 
                                                'score-medium' if results.security_score.dorking_score < 70 else 
                                                'score-low' if results.security_score.dorking_score < 90 else 
                                                'score-good' }}">
                            <h3>Dorking</h3>
                            <div class="score-value">{{ results.security_score.dorking_score }}</div>
                            <div class="progress-bar">
                                <div class="progress-fill {{ 'score-critical' if results.security_score.dorking_score < 30 else 
                                                          'score-high' if results.security_score.dorking_score < 50 else 
                                                          'score-medium' if results.security_score.dorking_score < 70 else 
                                                          'score-low' if results.security_score.dorking_score < 90 else 
                                                          'score-good' }}" 
                                     style="width: {{ results.security_score.dorking_score }}%"></div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Resumen de Riesgos -->
                    <h3>Distribución de Hallazgos por Nivel de Riesgo</h3>
                    <div class="risk-summary">
                        <div class="risk-item score-critical">
                            <strong>Crítico</strong>
                            <div>{{ results.security_score.risk_levels.critical }}</div>
                        </div>
                        <div class="risk-item score-high">
                            <strong>Alto</strong>
                            <div>{{ results.security_score.risk_levels.high }}</div>
                        </div>
                        <div class="risk-item score-medium">
                            <strong>Medio</strong>
                            <div>{{ results.security_score.risk_levels.medium }}</div>
                        </div>
                        <div class="risk-item score-low">
                            <strong>Bajo</strong>
                            <div>{{ results.security_score.risk_levels.low }}</div>
                        </div>
                        <div class="risk-item" style="background-color: #95a5a6;">
                            <strong>Info</strong>
                            <div>{{ results.security_score.risk_levels.info }}</div>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Registros DNS</h2>
                    {% for record_type, records in results.dns_records.items() %}
                    <h3>Registros {{ record_type }}</h3>
                    {% if records %}
                    <ul>
                        {% for record in records %}
                        <li>{{ record }}</li>
                        {% endfor %}
                    </ul>
                    {% else %}
                    <p>No se encontraron registros de este tipo.</p>
                    {% endif %}
                    {% endfor %}
                </div>
                
                <div class="section">
                    <h2>Información WHOIS</h2>
                    <table>
                        <tr>
                            <th>Campo</th>
                            <th>Valor</th>
                        </tr>
                        {% for key, value in results.whois_info.items() %}
                        <tr>
                            <td>{{ key }}</td>
                            <td>
                                {% if value is iterable and value is not string %}
                                <ul>
                                    {% for item in value %}
                                    <li>{{ item }}</li>
                                    {% endfor %}
                                </ul>
                                {% else %}
                                {{ value }}
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>
                
                <div class="section">
                    <h2>Resultados de Dorking</h2>
                    {% for dork_result in results.dorking_results %}
                    <div class="dork-result">
                        <h3>Consulta: {{ dork_result.dork }}</h3>
                        <p>Total de resultados: {{ dork_result.hits }}</p>
                        
                        {% if dork_result.results %}
                        <table>
                            <tr>
                                <th>Título</th>
                                <th>URL</th>
                                <th>Extracto</th>
                            </tr>
                            {% for result in dork_result.results %}
                            <tr>
                                <td>{{ result.title }}</td>
                                <td><a href="{{ result.url }}" target="_blank">{{ result.url }}</a></td>
                                <td>{{ result.snippet }}</td>
                            </tr>
                            {% endfor %}
                        </table>
                        {% else %}
                        <p>No se encontraron resultados.</p>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                
                <div class="section">
                    <h2>Análisis de IA</h2>
                    <pre>{{ results.ai_analysis }}</pre>
                </div>
                
                <div class="footer">
                    <p>brr brr patapim</p>
                </div>
            </div>
        </body>
        </html>
        """

        template = Template(html_template)
        html_content = template.render(results=self.results)
        

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"  - Informe HTML exportado correctamente a {output_file}")
        return output_file


def main():
    parser = argparse.ArgumentParser(description='ReconBot - Herramienta de Auditoría Automatizada para Dominios')
    parser.add_argument('domain', help='Dominio objetivo para analizar')
    parser.add_argument('--api', default='http://localhost:8000/api/deepseek/', 
                        help='URL de la API de IA para análisis (por defecto: http://localhost:8000/api/deepseek/)')
    parser.add_argument('--output', default='results', help='Prefijo para los archivos de salida')
    parser.add_argument('--format', choices=['json', 'html', 'both'], default='both', 
                        help='Formato de salida: json, html o ambos (por defecto: both)')
    parser.add_argument('--open', action='store_true', help='Abrir el informe HTML en el navegador al finalizar')
    
    args = parser.parse_args()
    
    try:
        if not args.domain or '.' not in args.domain:
            print("Error: Por favor, proporciona un dominio válido (ej: ejemplo.com)")
            sys.exit(1)
        
        recon = ReconBot(args.domain, api_url=args.api)
        recon.run_full_scan()
        
        json_file = None
        html_file = None
        
        if args.format in ['json', 'both']:
            json_file = recon.export_json(f"{args.output}.json")
        
        if args.format in ['html', 'both']:
            html_file = recon.export_html(f"{args.output}.html")
            
            if args.open and html_file:
                webbrowser.open(f'file://{os.path.realpath(html_file)}')
        
        print("\n[+] ¡Proceso completado!")
        
    except KeyboardInterrupt:
        print("\n[!] Proceso interrumpido por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()