```mermaid
flowchart TD
    subgraph A [Attacker Environment]
        direction TB
        A1[Kali Linux VM<br/>30.30.30.50]
        A2[Kali Linux/WSL<br/>172.24.212.130]
        A1 <--> A2
    end

    subgraph T [Target Environment]
        direction TB
        T1[Windows 10 VM<br/>30.30.30.48]
        
        subgraph T1a [Windows Services]
            T2[WinRM<br/>Port 5985]
            T3[Sysmon<br/>Event Logging]
            T4[Winlogbeat<br/>Log Forwarding]
        end
        
        T1 --> T1a
        T2 --> T3 --> T4
    end

    subgraph M [Monitoring Stack - Elastic]
        direction TB
        M0[Elasticsearch Host<br/>172.24.212.130:9200<br/>0.0.0.0 binding]
        M1[Kibana Interface<br/>30.30.30.47:5601]
        M2[Elasticsearch API<br/>30.30.30.47:9200]
        M0 --> M1
        M0 --> M2
    end

    subgraph C [Configuration Details]
        direction TB
        C1[winlogbeat.yml<br/>Hosts: 30.30.30.47:9200<br/>User: elastic<br/>Pass: qwerty12345]
        C2[kibana.yml<br/>Elasticsearch: 172.24.212.130:9200]
        C3[elasticsearch.yml<br/>http.host: 0.0.0.0]
    end

    A -- "1. Evil-WinRM Connection<br/>khaireddine/root" --> T
    T -- "2. Winlogbeat Forwarding<br/>To 30.30.30.47:9200" --> M2
    M1 -- "3. Kibana Dashboard<br/>Access via 30.30.30.47:5601" --> A
    
    T1 -- "4. Atomic Red Team<br/>Execution" --> T3

    C1 --> T4
    C2 --> M1
    C3 --> M0

    style A fill:#ffcccc
    style T fill:#ccffcc
    style M fill:#ccccff
    style C fill:#ffccff
```

# 🔍 Updated Network Architecture & Configuration

## **Revised IP Address Scheme**

### Attacker Systems:
- **Kali Linux VM**: 30.30.30.50
- **Kali Linux/WSL**: 172.24.212.130
- **Wireless LAN IP**: 30.30.30.47

### Target System:
- **Windows 10 VM**: 30.30.30.48

### Elastic Stack Services:
- **Elasticsearch API**: Accessible via 30.30.30.47:9200
- **Kibana Web Interface**: Accessible via 30.30.30.47:5601

## **Critical Configuration Files**

### 1. Winlogbeat Configuration (`winlogbeat.yml`)
```yaml
output.elasticsearch:
  hosts: ["https://30.30.30.47:9200"]
  username: "elastic"
  password: "qwerty12345"
  ssl:
    certificate_authorities: "C:/Users/Public/http_ca.crt"
    verification_mode: certificate
  pipeline: "winlogbeat-%([agent.version])-routing"
```

### 2. Kibana Configuration (`kibana.yml`)
```yaml
elasticsearch.hosts: ["https://172.24.212.130:9200"]
```

### 3. Elasticsearch Configuration (`elasticsearch.yml`)
```yaml
http.host: 0.0.0.0  # Listen on all interfaces
```

## **Connection Flow & Data Path**

### Step 1: Initial Compromise
```bash
# From Kali Linux VM (30.30.30.50) or WSL (172.24.212.130)
evil-winrm -i 30.30.30.48 -u khaireddine -p root
```

### Step 2: Log Generation & Collection
- Windows VM (30.30.30.48) generates Sysmon events
- Winlogbeat collects and processes logs

### Step 3: Log Forwarding
```mermaid
flowchart LR
    W[Winlogbeat on<br/>30.30.30.48] -->|HTTPS| E[Elasticsearch API<br/>30.30.30.47:9200]
    E -->|Internal| EI[Elasticsearch Process<br/>172.24.212.130:9200]
```

### Step 4: Dashboard Access
```bash
# Access Kibana from any machine
# URL: https://30.30.30.47:5601
# Credentials: elastic / qwerty12345
```

## **Network Connectivity Checklist**

✅ **WinRM Access**: Kali → Windows VM (30.30.30.48:5985)  
✅ **Winlogbeat → Elasticsearch**: Windows VM → Elasticsearch (30.30.30.47:9200)  
✅ **Kibana Access**: Any browser → Kibana (30.30.30.47:5601)  
✅ **Elasticsearch Internal**: 172.24.212.130:9200 → 0.0.0.0 (all interfaces)  

## **Troubleshooting Notes**

### If Winlogbeat cannot connect to Elasticsearch:
1. Verify Elasticsearch is running on 172.24.212.130:9200
2. Check firewall rules allow 9200/tcp
3. Confirm SSL certificate path is correct

### If Kibana cannot connect to Elasticsearch:
1. Verify `elasticsearch.hosts` points to correct IP
2. Check Elasticsearch is bound to 0.0.0.0
3. Validate credentials elastic/qwerty12345

### Network Connectivity Tests:
```bash
# From Windows VM test Elasticsearch connection
Test-NetConnection 30.30.30.47 -Port 9200

# From Kali test WinRM connection
nc -zv 30.30.30.48 5985
```
