# Lista de IPs confiáveis que nunca devem ser bloqueados
$whitelist = @(
    "192.168.1.1", "192.168.1.2"    )

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