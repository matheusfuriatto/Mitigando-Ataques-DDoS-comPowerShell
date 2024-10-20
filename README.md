Claro! Aqui está o arquivo `README.md` para o seu projeto no GitHub:

---

# Bloqueio de IPs Maliciosos com PowerShell

Este script em PowerShell foi desenvolvido para ajudar a mitigar ataques DDoS na porta de aplicação, bloqueando automaticamente IPs maliciosos que excedem o número máximo de conexões permitidas.

## Funcionalidades

- **Lista de IPs confiáveis**: IPs que nunca devem ser bloqueados.
- **Parâmetros configuráveis**: Número máximo de conexões permitidas, duração do bloqueio, intervalo de verificação e tempo de espera antes do bloqueio.
- **Verificação e bloqueio de IPs**: Monitora conexões TCP ativas e bloqueia IPs que excedem o limite de conexões.
- **Loop de verificação**: Executa a função de verificação periodicamente.

## Uso

### 1. Configuração

Abra o PowerShell na pasta onde está o script ou navegue até ela usando `cd` e `ls`.

### 2. Verificar a Política de Execução Atual

Depois de abrir o PowerShell como administrador, você pode verificar a política de execução atual digitando:

```powershell
Get-ExecutionPolicy
```

### 3. Alterar a Política de Execução

Para permitir a execução de scripts, altere a política de execução usando o seguinte comando:

```powershell
Set-ExecutionPolicy RemoteSigned
```

### 4. Executar o Script

Execute o script com o comando:

```powershell
.\BloquearIPs.ps1
```

### 5. Restaurar a Política de Execução

Após finalizar, restaure a política de execução para o estado restrito:

```powershell
Set-ExecutionPolicy Restricted
```

## Código do Script

```powershell
# Lista de IPs confiáveis que nunca devem ser bloqueados
$whitelist = @(
    "192.168.1.1", "192.168.1.2"
)

# Define o número máximo de conexões permitidas
$maxConnections = 5  # ajuste conforme necessário

# Define o tempo de bloqueio temporário em minutos
$blockDuration = 10  # ajuste conforme necessário

# Define um tempo de espera entre verificações
$checkInterval = 60  # em segundos

# Define o tempo de espera antes de bloquear um IP (em segundos)
$waitBeforeBlock = 30  # ajuste conforme necessário

# Inicializa um dicionário para armazenar os IPs bloqueados e a contagem de bloqueios
$blockedIPs = @{}
$connectionHistory = @{}

# Função para verificar e bloquear IPs
function CheckAndBlockIPs {
    # Obtém as conexões TCP ativas
    $connections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }
    $groupedConnections = $connections | Group-Object -Property RemoteAddress

    # Verifica se algum IP excedeu o número máximo de conexões
    foreach ($group in $groupedConnections) {
        $ip = $group.Name

        # Ignorar IPs na lista de permissões
        if ($whitelist -contains $ip) {
            continue
        }

        # Inicializa o histórico de conexões para o IP, se necessário
        if (-not $connectionHistory.ContainsKey($ip)) {
            $connectionHistory[$ip] = @()
        }

        # Adiciona a conexão atual ao histórico
        $connectionHistory[$ip] += (Get-Date)

        # Remove entradas antigas do histórico
        $connectionHistory[$ip] = $connectionHistory[$ip] | Where-Object { $_ -gt (Get-Date).AddSeconds(-$waitBeforeBlock) }

        # Verifica se o IP excedeu o número máximo de conexões
        if ($connectionHistory[$ip].Count -gt $maxConnections) {
            # Se o IP já está bloqueado, incremente a contagem
            if ($blockedIPs.ContainsKey($ip)) {
                $blockedIPs[$ip].Count++
            } else {
                # Se não está bloqueado, adicione à lista
                $blockedIPs[$ip] = @{ Count = 1; Timer = (Get-Date).AddMinutes($blockDuration) }
            }

            # Se a contagem de bloqueios for 1, bloqueie o IP
            if ($blockedIPs[$ip].Count -eq 1) {
                New-NetFirewallRule -DisplayName "Bloqueio Temporário - IP $ip" -Direction Inbound -RemoteAddress $ip -Action Block
                Write-Host "Bloqueio temporário: IP $ip foi bloqueado devido a múltiplas conexões."
            }
        }
    }

    # Remover regras de bloqueio para IPs que estão fora do tempo de bloqueio
    foreach ($ip in $blockedIPs.Keys) {
        if ((Get-Date) -ge $blockedIPs[$ip].Timer) {
            Remove-NetFirewallRule -DisplayName "Bloqueio Temporário - IP $ip"
            Write-Host "Bloqueio removido: IP $ip foi desbloqueado após $blockDuration minutos."
            # Remover IP da lista de bloqueados
            $blockedIPs.Remove($ip)
        }
    }

    # Exibe a lista de IPs bloqueados
    if ($blockedIPs.Count -gt 0) {
        Write-Host "Lista de IPs bloqueados:"
        $blockedIPs.Keys | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "Nenhum IP foi bloqueado."
    }
}

# Loop para verificar e bloquear IPs periodicamente
while ($true) {
    CheckAndBlockIPs
    Start-Sleep -Seconds $checkInterval
}
```

## Contribuição

Sinta-se à vontade para contribuir com melhorias ou sugestões para este projeto. Abra uma issue ou envie um pull request.

---

Espero que isso ajude! Se precisar de mais alguma coisa, é só avisar. 😊
