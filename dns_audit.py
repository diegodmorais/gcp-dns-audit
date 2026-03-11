import subprocess
import dns.resolver
from tabulate import tabulate
import sys
import csv
import json
from datetime import datetime
import os
import requests

TAKEOVER_SIGNATURES = {
    "NoSuchBucket": "Possível takeover Cloud Storage",
    "The specified bucket does not exist": "Possível takeover Cloud Storage",
    "There isn't a GitHub Pages site here": "Possível takeover GitHub Pages",
    "No such app": "Possível takeover Heroku",
    "404. That’s an error": "Possível serviço GCP inexistente",
    "Project not found": "Possível takeover App Engine",
    "Service not found": "Possível takeover Cloud Run"
}


def run(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
        return output.decode().strip().splitlines()
    except:
        return []
    
def detect_takeover(domain):

    try:

        r = requests.get(f"http://{domain}", timeout=5)

        for sig, desc in TAKEOVER_SIGNATURES.items():

            if sig.lower() in r.text.lower():

                return desc

        return None

    except:

        return None
    
def collect_org_ips(projects):

    ip_inventory = {}

    for project in projects:

        print(f"Coletando IPs do projeto: {project}")

        ips = run(
            f"gcloud compute addresses list --project {project} --format='value(address)'"
        )

        nat_ips = run(
            f"gcloud compute instances list --project {project} "
            "--format='get(networkInterfaces[].accessConfigs[].natIP)'"
        )

        lb_ips = run(
            f"gcloud compute forwarding-rules list --project {project} "
            "--format='value(IPAddress)'"
        )

        for ip in ips + nat_ips + lb_ips:

            if ip:
                ip_inventory[ip] = project

    return ip_inventory


# valida argumento
if len(sys.argv) != 2:
    print("Uso: python dns_audit.py projects.txt")
    sys.exit(1)

projects_file = sys.argv[1]

# carregar projetos
with open(projects_file) as f:
    projects = [line.strip() for line in f if line.strip()]

alerts = []

ip_inventory = collect_org_ips(projects)

print(f"\nProjetos carregados: {len(projects)}\n")


for PROJECT_ID in projects:

    print(f"\n==============================")
    print(f"Analisando projeto: {PROJECT_ID}")
    print(f"==============================\n")

    valid_ips = set()
    dns_records = []

    print("Coletando IPs públicos...")

    ips = run(
        f"gcloud compute addresses list --project {PROJECT_ID} --format='value(address)'"
    )

    nat_ips = run(
        f"gcloud compute instances list --project {PROJECT_ID} "
        "--format='get(networkInterfaces[].accessConfigs[].natIP)'"
    )

    lb_ips = run(
        f"gcloud compute forwarding-rules list --project {PROJECT_ID} "
        "--format='value(IPAddress)'"
    )

    valid_ips.update([i for i in ips if i])
    valid_ips.update([i for i in nat_ips if i])
    valid_ips.update([i for i in lb_ips if i])

    print(f"✔ {len(valid_ips)} IPs encontrados")

    print("\nColetando registros DNS...")

    zones = run(
        f"gcloud dns managed-zones list --project {PROJECT_ID} --format='value(name)'"
    )

    for zone in zones:

        print(f"Zona DNS: {zone}")

        records = run(
            f"gcloud dns record-sets list --project {PROJECT_ID} --zone {zone} "
            "--format='value(name,type,rrdatas)'"
        )

        for r in records:

            parts = r.split()

            if len(parts) < 3:
                continue

            name = parts[0]
            rtype = parts[1]
            data = parts[2]

            if rtype not in ["A", "CNAME"]:
                continue

            dns_records.append((PROJECT_ID, name, rtype, data))

    print(f"✔ {len(dns_records)} registros DNS encontrados")

    print("\nValidando DNS...")

    for project, name, rtype, data in dns_records:

        try:

            answers = dns.resolver.resolve(name, "A")

            for ip in answers:

                ip = str(ip)

                if ip not in ip_inventory:

                    issue = "IP NÃO PERTENCE À ORGANIZAÇÃO"

                else:

                    owner_project = ip_inventory[ip]

                    if owner_project != project:

                        issue = f"IP pertence ao projeto {owner_project}"

                    else:

                        issue = None
                '''
                if ip not in valid_ips:

                    alerts.append({
                        "project": project,
                        "dns": name,
                        "type": rtype,
                        "ip": ip,
                        "issue": "IP NÃO PERTENCE AO PROJETO"
                    })
                    '''
                takeover = detect_takeover(name)

                if takeover:

                    alerts.append({
                    "project": project,
                    "dns": name,
                    "type": rtype,
                    "ip": ip,
                    "issue": takeover
                    })

        except:

            alerts.append({
                "project": project,
                "dns": name,
                "type": rtype,
                "ip": "N/A",
                "issue": "DNS NÃO RESOLVE"
            })
            takeover = detect_takeover(name)

            if takeover:

                alerts.append({
                    "project": project,
                    "dns": name,
                    "type": rtype,
                    "ip": "N/A",
                    "issue": takeover
                })


print("\nRELATÓRIO FINAL\n")

if alerts:

    table = [[
        a["project"],
        a["dns"],
        a["type"],
        a["ip"],
        a["issue"]
    ] for a in alerts]

    print(tabulate(
        table,
        headers=["Projeto", "DNS", "Tipo", "IP", "Problema"]
    ))

else:

    print("Nenhum problema encontrado")


# criar pasta reports se não existir
os.makedirs("reports", exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d_%H%M")

csv_file = f"reports/dns_audit_{timestamp}.csv"
json_file = f"reports/dns_audit_{timestamp}.json"


# salvar CSV
with open(csv_file, "w", newline="") as f:

    writer = csv.writer(f)
    writer.writerow(["project", "dns", "type", "ip", "issue"])

    for a in alerts:
        writer.writerow([
            a["project"],
            a["dns"],
            a["type"],
            a["ip"],
            a["issue"]
        ])


# salvar JSON
with open(json_file, "w") as f:
    json.dump(alerts, f, indent=4)


print("\nRelatórios gerados:")
print(csv_file)
print(json_file)