import os
import ipaddress
import socket
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl
import httpx
from dotenv import load_dotenv

# Carrega variáveis de ambiente (útil para testes locais com .env)
load_dotenv()

app = FastAPI(title="Web Proxy Seguro", version="1.0.0")

# Monta arquivos estáticos para o frontend
app.mount("/static", StaticFiles(directory="static"), name="static")

# Configuração de Domínios Permitidos (ex: "example.com,api.github.com")
ALLOWED_DOMAINS_ENV = os.getenv("ALLOWED_DOMAINS", "")
ALLOWED_DOMAINS = [d.strip().lower() for d in ALLOWED_DOMAINS_ENV.split(",") if d.strip()]

class ProxyRequest(BaseModel):
    url: HttpUrl

def is_safe_ip(ip_str: str) -> bool:
    """Valida se o endereço IP é público e seguro contra SSRF."""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Bloqueia loopback, privados, link-local, multicast, reservados, etc.
        if (
            ip.is_loopback or
            ip.is_private or
            ip.is_link_local or
            ip.is_multicast or
            ip.is_reserved or
            ip.is_unspecified
        ):
            return False
        
        # Bloqueio específico para o IP de metadados da nuvem (AWS/GCP/Azure: 169.254.169.254)
        if ip_str == "169.254.169.254":
            return False
            
        return True
    except ValueError:
        return False

def validate_target_url(url_str: str):
    """Validação completa de URL, esquema, domínio e resolução DNS."""
    parsed = urlparse(url_str)
    
    # 1. Validar Esquema (Apenas HTTP e HTTPS)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Esquema não permitido. Use apenas HTTP ou HTTPS.")
    
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Endereço de destino inválido.")
    
    hostname_lower = hostname.lower()

    # 2. Validar Lista de Domínios Autorizados
    if ALLOWED_DOMAINS:
        matched = any(
            hostname_lower == domain or hostname_lower.endswith(f".{domain}")
            for domain in ALLOWED_DOMAINS
        )
        if not matched:
            raise HTTPException(
                status_code=403, 
                detail=f"Acesso negado: O domínio '{hostname}' não está na lista de autorizados."
            )
    else:
        raise HTTPException(
            status_code=500, 
            detail="Erro de configuração do servidor: Nenhum domínio autorizado foi definido."
        )

    # 3. Resolução DNS e Proteção contra DNS Rebinding / SSRF por IP
    try:
        # Obtém todos os endereços IP associados ao hostname
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Não foi possível resolver o endereço de destino (DNS falhou).")

    for family, _, _, _, sockaddr in addr_info:
        ip_addr = sockaddr[0]
        if not is_safe_ip(ip_addr):
            raise HTTPException(
                status_code=403, 
                detail=f"Acesso bloqueado: O destino resolve para um endereço IP restrito ou privado ({ip_addr})."
            )

@app.post("/api/proxy")
async def proxy_request(payload: ProxyRequest):
    target_url = str(payload.url)
    
    # Executa validações de segurança rigorosas
    validate_target_url(target_url)

    # Limites de requisição e timeout rigorosos
    timeout_config = httpx.Timeout(10.0, connect=5.0)
    
    try:
        # Importante: follow_redirects=False para evitar bypass de SSRF via redirecionamento
        async with httpx.AsyncClient(timeout=timeout_config, follow_redirects=False) as client:
            response = await client.get(target_url)
            
            # Sanitiza cabeçalhos internos ou sensíveis antes de retornar
            excluded_headers = {"set-cookie", "server", "x-powered-by", "via"}
            headers = {
                k: v for k, v in response.headers.items() 
                if k.lower() not in excluded_headers
            }
            
            # Limita tamanho máximo da resposta para evitar esgotamento de memória (ex: 2MB)
            content = response.content
            if len(content) > 2 * 1024 * 1024:
                raise HTTPException(status_code=413, detail="A resposta do servidor de destino excede o limite de 2MB.")

            return Response(
                content=content,
                status_code=response.status_code,
                headers=headers
            )
            
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Tempo limite esgotado ao tentar conectar ao destino.")
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Erro na comunicação com o destino: {str(e)}")

@app.get("/")
def read_root():
    return {"status": "online", "message": "Web Proxy API em execução. Acesse /static/index.html"}