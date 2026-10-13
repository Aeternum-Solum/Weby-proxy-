import pytest
from fastapi.testclient import TestClient
from main import app, is_safe_ip

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "online"

def test_is_safe_ip():
    # IPs privados e de loopback devem ser bloqueados
    assert is_safe_ip("127.0.0.1") is False
    assert is_safe_ip("10.0.0.1") is False
    assert is_safe_ip("192.168.1.1") is False
    assert is_safe_ip("169.254.169.254") is False  # Metadados de nuvem
    
    # IP público simulado deve ser seguro
    assert is_safe_ip("8.8.8.8") is True

def test_proxy_invalid_scheme():
    # Esquema inválido (ftp) deve ser rejeitado
    response = client.post("/api/proxy", json={"url": "ftp://example.com"})
    assert response.status_code == 400
