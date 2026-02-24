# Investigação Completa do Incidente

## Linha do Tempo

```mermaid
timeline
    title Timeline do Incidente MDR
    14:23:15 : Tarefa UpdaterService criada
              : Usuário JDOE autenticado
    14:23:18 : PowerShell executado
              : Script decodificado
    14:23:20 : Download do payload.exe
    14:23:25 : Payload executado
              : Conexão com C2 (192.168.1.10)
    14:24:00 : Alerta SIEM disparado
    14:24:30 : Analista inicia triagem
    14:25:00 : Classificado como incidente