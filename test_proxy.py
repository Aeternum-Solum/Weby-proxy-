import os
import pytest
from fastapi.testclient import TestClient

# Configura variável de ambiente para testes antes de importar o app
os.environ["ALLOWED_DOMAINS"] = "httpbin.org,example.com"

from main import app

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "online"

def test_blocked_domain():
    # Tenta acessar um domínio que não está na lista permitida
    response = client.post("/api/proxy", json={"url": "https://google.com"})
    assert response.status_code == 403
    assert "não está na lista de autorizados" in response.json()["detail"]

def test_ssrf_loopback_ip_block():
    # Tenta forçar acesso a IP de loopback (proteção SSRF)
    response = client.post("/api/proxy", json={"url": "http://127.0.0.1"})
    # Como 127.0.0.1 não é httpbin.org/example.com, falha na validação de domínio ou de IP
    assert response.status_code in (403, 400)