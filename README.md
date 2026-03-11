# GCP DNS Security Audit

Script para auditar registros DNS em projetos do Google Cloud.

## Features

- Validação de DNS vs IP
- Detecção de IP fora da organização
- Identificação de recursos GKE / Load Balancer
- Detecção de possível subdomain takeover

## Uso

```bash
python dns_audit.py projects.txt
```

## Requisitos

- Python 3
- gcloud CLI autenticado

## Depois commit:

```bash
git add .
git commit -m "Add README and requirements"
git push
```
