# Compila MemReader como un unico .exe autocontenido (x64).
# Uso:  .\build.ps1
$ErrorActionPreference = "Stop"

Write-Host "Compilando MemReader (Release, win-x64, single-file)..." -ForegroundColor Cyan

dotnet publish -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true

$exe = Join-Path $PSScriptRoot "bin\Release\net8.0-windows\win-x64\publish\MemReader.exe"

if (Test-Path $exe) {
    Write-Host "`nListo:" -ForegroundColor Green
    Write-Host "  $exe"
    Write-Host "`nRecuerda ejecutarlo como Administrador." -ForegroundColor Yellow
} else {
    Write-Warning "No se encontro el ejecutable esperado en $exe"
}
