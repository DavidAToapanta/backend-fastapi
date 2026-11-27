# Preparar la instancia local de ensayo. Requiere Docker Desktop y Git para Windows.
[CmdletBinding()]
param([string]$Directorio = (Join-Path $env:LOCALAPPDATA 'AegisHealth\misp-ensayo'))
$ErrorActionPreference = 'Stop'
$revision = 'd9e2dd1a07eca20c59ac665f1d01167c4443e97d'
if (-not (Test-Path -LiteralPath $Directorio)) {
    git clone https://github.com/MISP/misp-docker.git $Directorio
    if ($LASTEXITCODE) { throw 'Falló la descarga de misp-docker.' }
    git -C $Directorio checkout --detach $revision
    if ($LASTEXITCODE) { throw 'Falló la selección de la revisión de ensayo.' }
}
if ((git -C $Directorio rev-parse HEAD) -ne $revision) {
    throw 'La carpeta ya existe y corresponde a otra revisión. Elegí otra carpeta de ensayo.'
}
$openssl = Join-Path $env:ProgramFiles 'Git\usr\bin\openssl.exe'
if (-not (Test-Path -LiteralPath $openssl)) { $openssl = (Get-Command openssl).Source }
function Nuevo-Secreto([int]$Bytes) {
    $resultado = & $openssl rand -hex $Bytes
    if ($LASTEXITCODE) { throw 'Falló la generación de la credencial local.' }
    return $resultado.Trim()
}
Push-Location -LiteralPath $Directorio
try {
    if (-not (Test-Path -LiteralPath '.env')) {
        $valores = [ordered]@{
            BASE_URL = 'https://127.0.0.1:8443'
            ADMIN_ORG = 'AegisHealth'
            ADMIN_KEY = Nuevo-Secreto 20
            ADMIN_PASSWORD = Nuevo-Secreto 24
            GPG_PASSPHRASE = Nuevo-Secreto 24
            MYSQL_ROOT_PASSWORD = Nuevo-Secreto 24
            MYSQL_PASSWORD = Nuevo-Secreto 24
            REDIS_PASSWORD = Nuevo-Secreto 24
            SUPERVISOR_PASSWORD = Nuevo-Secreto 24
            ENCRYPTION_KEY = Nuevo-Secreto 16
            DISABLE_PRINTING_PLAINTEXT_CREDENTIALS = 'true'
            ENABLE_BACKGROUND_UPDATES = 'false'
            NUM_WORKERS_DEFAULT = '1'
            NUM_WORKERS_PRIO = '1'
            NUM_WORKERS_EMAIL = '1'
            NUM_WORKERS_CACHE = '1'
        }
        $lineas = @(Get-Content -LiteralPath 'template.env' | Where-Object {
            -not ($_ -match '^([A-Z_]+)=' -and $valores.Contains($Matches[1]))
        })
        foreach ($k in $valores.Keys) { $lineas += "$k=$($valores[$k])" }
        [IO.File]::WriteAllLines((Join-Path $Directorio '.env'), [string[]]$lineas)
    }
    $ssl = Join-Path $Directorio 'ssl'
    if (-not (Test-Path -LiteralPath $ssl)) { New-Item -ItemType Directory -Path $ssl | Out-Null }
    if (-not (Test-Path -LiteralPath 'ssl/cert.pem') -and -not (Test-Path -LiteralPath 'ssl/key.pem')) {
        & $openssl req -x509 -newkey rsa:3072 -noenc -days 365 -subj '/CN=AegisHealth MISP local' -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign' -addext 'extendedKeyUsage=serverAuth' -keyout 'ssl/key.pem' -out 'ssl/cert.pem' 2>$null
        if ($LASTEXITCODE) { throw 'Falló la generación del certificado TLS local.' }
    }
    if (-not (Test-Path -LiteralPath 'ssl/cert.pem') -or -not (Test-Path -LiteralPath 'ssl/key.pem')) {
        throw 'El par TLS local está incompleto.'
    }
    $opciones = @('-p','aegis-misp-ensayo','-f','docker-compose.yml','-f',(Join-Path $PSScriptRoot 'misp-local.yml'))
    $config = docker compose @opciones config --format json 2>$null | ConvertFrom-Json
    if ($LASTEXITCODE -or -not $config) { throw 'Configuración Compose inválida.' }
    $puertos = @($config.services.PSObject.Properties | ForEach-Object { if ($_.Value.ports) { $_.Value.ports } })
    # El servicio opcional misp-guard está excluido por perfil.
    $serviciosEntrada = @($config.services.PSObject.Properties |
        Where-Object { $_.Value.networks.PSObject.Properties.Name -contains 'entrada_local' })
    if ($puertos.Count -ne 1 -or $puertos[0].host_ip -ne '127.0.0.1' -or $puertos[0].published -ne '8443' -or
        -not $config.networks.default.internal -or $serviciosEntrada.Count -ne 1 -or
        $serviciosEntrada[0].Name -ne 'misp-nginx') {
        throw 'La red o los puertos no corresponden al ensayo local.'
    }
    Write-Output "Proyecto aegis-misp-ensayo preparado en $Directorio. HTTPS local en 8443."
} finally { Pop-Location }
