[CmdletBinding()]
param([string]$Directorio = (Join-Path $env:LOCALAPPDATA 'AegisHealth\guardian-piloto'))
$ErrorActionPreference = 'Stop'

function Nuevo-Token {
    $bytes = New-Object byte[] 32
    $generador = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generador.GetBytes($bytes) } finally { $generador.Dispose() }
    return [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
}

function Obtener-Huella([string]$Token) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Token)) } finally { $sha.Dispose() }
    return [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
}

$envPiloto = Join-Path $Directorio 'piloto.env'
$credenciales = Join-Path $Directorio 'credenciales.json'
if ((Test-Path -LiteralPath $envPiloto) -and (Test-Path -LiteralPath $credenciales)) {
    Write-Output "Credenciales de ensayo disponibles en $Directorio"
    return
}
if (Test-Path -LiteralPath $Directorio) {
    throw 'La carpeta ya existe con configuración incompleta. Elegí otra ruta para evitar sobrescribir credenciales.'
}
$padre = Split-Path -Parent $Directorio
[IO.Directory]::CreateDirectory($padre) | Out-Null
$temporal = Join-Path $padre ('piloto-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporal) | Out-Null
$sesionAfiliado = Nuevo-Token
$sesionAnonima1 = Nuevo-Token
$sesionAnonima2 = Nuevo-Token
$analista = Nuevo-Token
$sesiones = @{
    afiliado = @{ keySha256 = Obtener-Huella $sesionAfiliado; affiliate = 'AFI-00000000A001' }
    anonimo1 = @{ keySha256 = Obtener-Huella $sesionAnonima1; affiliate = $null }
    anonimo2 = @{ keySha256 = Obtener-Huella $sesionAnonima2; affiliate = $null }
} | ConvertTo-Json -Depth 3 -Compress
$analistas = @{ 'analista-piloto' = Obtener-Huella $analista } | ConvertTo-Json -Compress
$claves = @{
    affiliateToken = $sesionAfiliado
    anonymousToken1 = $sesionAnonima1
    anonymousToken2 = $sesionAnonima2
    analystId = 'analista-piloto'
    analystToken = $analista
} | ConvertTo-Json
[IO.File]::WriteAllLines((Join-Path $temporal 'piloto.env'), [string[]]@(
    "AEGIS_HMAC_CLAVE=$(Nuevo-Token)",
    "PILOTO_SESIONES_JSON='$sesiones'",
    "PILOTO_ANALISTAS_JSON='$analistas'"
))
[IO.File]::WriteAllText((Join-Path $temporal 'credenciales.json'), $claves)
[IO.Directory]::Move($temporal, $Directorio)
Write-Output "Credenciales de ensayo disponibles en $Directorio"
