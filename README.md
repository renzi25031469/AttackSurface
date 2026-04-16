# Attack Surface Mapper

> 🇧🇷 [Leia em Português](#-attack-surface-mapper--português)

---

## 🇺🇸 Attack Surface Mapper — English

```
    _   _   _             _      ____              __                
   / \ | |_| |_ __ _  ___| | __ / ___| _   _ _ __ / _| __ _  ___ ___ 
  / _ \| __| __/ _` |/ __| |/ / \___ \| | | | '__| |_ / _` |/ __/ _ \
 / ___ \ |_| || (_| | (__|   <   ___) | |_| | |  |  _| (_| | (_|  __/
/_/   \_\__|__\__,_|\___|_|\_\ |____/ \__,_|_|  |_|  \__,_|\___\___|
        Attack Surface Mapper — DNS + Scan + Report
```

A Bash script that automates external attack surface discovery by combining DNS resolution, port scanning, and HTML report generation — all in a single command.

> ⚠️ **Legal notice:** Use only on systems you are authorized to test. Unauthorized scanning is illegal.

---

### Features

- **DNS resolution** via [dnsx](https://github.com/projectdiscovery/dnsx) — resolves A, AAAA, and CNAME records
- **Port scanning** via [masscan](https://github.com/robertdavidgraham/masscan) and/or [naabu](https://github.com/projectdiscovery/naabu)
- **70+ monitored ports** across Remote Access, Databases, Web, CI/CD, Messaging, Monitoring, and more
- **Risk classification** — Critical / High / Medium / Low per service
- **Interactive HTML report** with filters, search, donut chart, and bar chart
- **Resume mode** (`--resume`) to reuse previous scan results
- **IP/CIDR + domain** input support in the same file
- **Auto dependency installation** (Go tools + apt)

---

### Requirements

| Tool | Purpose |
|------|---------|
| `bash` ≥ 4.0 | Script runtime |
| `dnsx` | DNS resolution |
| `masscan` | Fast SYN port scanner (requires root) |
| `naabu` | TCP port scanner |
| `jq` | JSON parsing |
| `python3` | Masscan output normalization |

> masscan requires **root** privileges. Run with `sudo`.

---

### Installation

```bash
# Clone the repository
git clone https://github.com/your-user/attack-surface.git
cd attack-surface

# Make executable
chmod +x attack_surface.sh

# Install Go-based tools (if needed)
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Install masscan
sudo apt-get install -y masscan jq
```

---

### Usage

```bash
sudo ./attack_surface.sh -i targets.txt [-m masscan|naabu|both] [-o DIR]
```

#### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i FILE` | Input file with domains/IPs (one per line) | **required** |
| `-o DIR` | Output directory | `./asm_DATE` |
| `-m MODE` | Scan mode: `masscan`, `naabu`, or `both` | `both` |
| `-r RATE` | Masscan packets per second | `5000` |
| `-c CONC` | Naabu concurrency | `100` |
| `-t TIMEOUT` | Per-host timeout in seconds | `10` |
| `-T THREADS` | DNS resolution threads | `50` |
| `-p PROXY` | HTTP proxy (e.g. `http://127.0.0.1:8080`) | — |
| `-x FILE` | File with IPs/CIDRs to exclude | — |
| `--resume` | Reuse results from a previous scan | — |
| `-h` | Show help | — |

#### Environment variables

`MASSCAN_RATE`, `NAABU_CONCURRENCY`, `SCAN_MODE`, `TIMEOUT`, `THREADS`

---

### Examples

```bash
# Basic scan
sudo ./attack_surface.sh -i targets.txt

# Use only masscan at high rate
sudo ./attack_surface.sh -i targets.txt -m masscan -r 10000

# Use only naabu with high concurrency
sudo ./attack_surface.sh -i targets.txt -m naabu -c 200

# Custom output directory
sudo ./attack_surface.sh -i targets.txt -o /tmp/asm_report

# Resume a previous scan
sudo ./attack_surface.sh -i targets.txt --resume
```

#### Input file format (`targets.txt`)

```
example.com
sub.example.com
192.168.1.0/24
10.0.0.1
```

---

### Output

All results are saved inside the output directory (`./asm_DATE/` by default):

| File | Description |
|------|-------------|
| `report.html` | Interactive HTML report |
| `open_ports.txt` | Normalized `ip\|port` list |
| `dns_resolved.json` | Raw dnsx JSON output |
| `domain_ip_map.txt` | Domain → IP mapping |
| `masscan_raw.json` | Raw masscan output |
| `naabu_raw.txt` | Raw naabu output |
| `asm.log` | Full execution log |

---

### Monitored Services (70+ ports)

| Category | Services |
|----------|----------|
| Remote Access | FTP, SSH, Telnet, RDP, VNC, rexec, rlogin, rsh |
| Email | SMTP, POP3, IMAP and secure variants |
| Databases | MySQL, PostgreSQL, MSSQL, Oracle, Redis, MongoDB, Elasticsearch, CouchDB, Memcached |
| Web | HTTP, HTTPS and alternative/admin ports |
| Directory / Auth | LDAP, LDAPS, Kerberos |
| Network / Infra | SMB, NetBIOS, MSRPC, NFS, SNMP, DNS, TFTP, NTP |
| CI/CD / DevOps | Docker, etcd, Kubernetes API, Kubelet, Consul, Git |
| Messaging | AMQP, MQTT, Kafka, ZooKeeper |
| Monitoring | Prometheus, Grafana, InfluxDB |

---

### Author

**Renzi**

---

### License

For authorized security testing only. The author is not responsible for any misuse of this tool.

---
---

## 🇧🇷 Attack Surface Mapper — Português

```
    _   _   _             _      ____              __                
   / \ | |_| |_ __ _  ___| | __ / ___| _   _ _ __ / _| __ _  ___ ___ 
  / _ \| __| __/ _` |/ __| |/ / \___ \| | | | '__| |_ / _` |/ __/ _ \
 / ___ \ |_| || (_| | (__|   <   ___) | |_| | |  |  _| (_| | (_|  __/
/_/   \_\__|__\__,_|\___|_|\_\ |____/ \__,_|_|  |_|  \__,_|\___\___|
        Attack Surface Mapper — DNS + Scan + Report
```

Script Bash que automatiza o mapeamento de superfície de ataque externa combinando resolução DNS, varredura de portas e geração de relatório HTML — tudo em um único comando.

> ⚠️ **Aviso legal:** Use apenas em sistemas que você tem autorização para testar. Varredura não autorizada é ilegal.

---

### Funcionalidades

- **Resolução DNS** via [dnsx](https://github.com/projectdiscovery/dnsx) — resolve registros A, AAAA e CNAME
- **Varredura de portas** via [masscan](https://github.com/robertdavidgraham/masscan) e/ou [naabu](https://github.com/projectdiscovery/naabu)
- **70+ portas monitoradas** cobrindo Acesso Remoto, Bancos de Dados, Web, CI/CD, Mensageria, Monitoramento e mais
- **Classificação de risco** — Crítico / Alto / Médio / Baixo por serviço
- **Relatório HTML interativo** com filtros, busca, gráfico donut e gráfico de barras
- **Modo resume** (`--resume`) para reaproveitar resultados de scans anteriores
- **Suporte a IP/CIDR + domínios** no mesmo arquivo de entrada
- **Instalação automática de dependências** (ferramentas Go + apt)

---

### Requisitos

| Ferramenta | Finalidade |
|------------|-----------|
| `bash` ≥ 4.0 | Execução do script |
| `dnsx` | Resolução DNS |
| `masscan` | Varredura SYN rápida (requer root) |
| `naabu` | Varredura de portas TCP |
| `jq` | Processamento JSON |
| `python3` | Normalização da saída do masscan |

> masscan requer privilégios de **root**. Execute com `sudo`.

---

### Instalação

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/attack-surface.git
cd attack-surface

# Dê permissão de execução
chmod +x attack_surface.sh

# Instale as ferramentas Go (se necessário)
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Instale masscan e jq
sudo apt-get install -y masscan jq
```

---

### Uso

```bash
sudo ./attack_surface.sh -i targets.txt [-m masscan|naabu|both] [-o DIR]
```

#### Opções

| Flag | Descrição | Padrão |
|------|-----------|--------|
| `-i FILE` | Arquivo com domínios/IPs (um por linha) | **obrigatório** |
| `-o DIR` | Diretório de saída | `./asm_DATE` |
| `-m MODE` | Modo de scan: `masscan`, `naabu` ou `both` | `both` |
| `-r RATE` | Pacotes por segundo do masscan | `5000` |
| `-c CONC` | Concorrência do naabu | `100` |
| `-t TIMEOUT` | Timeout por host em segundos | `10` |
| `-T THREADS` | Threads de resolução DNS | `50` |
| `-p PROXY` | Proxy HTTP (ex: `http://127.0.0.1:8080`) | — |
| `-x FILE` | Arquivo com IPs/CIDRs a excluir | — |
| `--resume` | Reaproveita resultados de scan anterior | — |
| `-h` | Exibe a ajuda | — |

#### Variáveis de ambiente

`MASSCAN_RATE`, `NAABU_CONCURRENCY`, `SCAN_MODE`, `TIMEOUT`, `THREADS`

---

### Exemplos

```bash
# Scan básico
sudo ./attack_surface.sh -i targets.txt

# Usar apenas masscan em alta velocidade
sudo ./attack_surface.sh -i targets.txt -m masscan -r 10000

# Usar apenas naabu com alta concorrência
sudo ./attack_surface.sh -i targets.txt -m naabu -c 200

# Diretório de saída personalizado
sudo ./attack_surface.sh -i targets.txt -o /tmp/asm_report

# Retomar scan anterior
sudo ./attack_surface.sh -i targets.txt --resume
```

#### Formato do arquivo de entrada (`targets.txt`)

```
example.com
sub.example.com
192.168.1.0/24
10.0.0.1
```

---

### Saída

Todos os resultados são salvos dentro do diretório de saída (`./asm_DATE/` por padrão):

| Arquivo | Descrição |
|---------|-----------|
| `report.html` | Relatório HTML interativo |
| `open_ports.txt` | Lista normalizada `ip\|porta` |
| `dns_resolved.json` | Saída JSON bruta do dnsx |
| `domain_ip_map.txt` | Mapeamento domínio → IP |
| `masscan_raw.json` | Saída bruta do masscan |
| `naabu_raw.txt` | Saída bruta do naabu |
| `asm.log` | Log completo de execução |

---

### Serviços Monitorados (70+ portas)

| Categoria | Serviços |
|-----------|----------|
| Acesso Remoto | FTP, SSH, Telnet, RDP, VNC, rexec, rlogin, rsh |
| E-mail | SMTP, POP3, IMAP e variantes seguras |
| Bancos de Dados | MySQL, PostgreSQL, MSSQL, Oracle, Redis, MongoDB, Elasticsearch, CouchDB, Memcached |
| Web | HTTP, HTTPS e portas alternativas/admin |
| Diretório / Auth | LDAP, LDAPS, Kerberos |
| Rede / Infra | SMB, NetBIOS, MSRPC, NFS, SNMP, DNS, TFTP, NTP |
| CI/CD / DevOps | Docker, etcd, Kubernetes API, Kubelet, Consul, Git |
| Mensageria | AMQP, MQTT, Kafka, ZooKeeper |
| Monitoramento | Prometheus, Grafana, InfluxDB |

---

### Autor

**Renzi**

---

### Licença

Para uso exclusivo em testes de segurança autorizados. O autor não se responsabiliza pelo uso indevido desta ferramenta.
