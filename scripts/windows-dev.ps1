# mediu de test pe windows: server in WSL, daemon-ul ca administrator, interfata ca user normal
#
#   scripts\windows-dev.ps1 start   porneste serverul in WSL, daemon-ul (fereastra UAC) si interfata
#   scripts\windows-dev.ps1 code    codul TOTP curent (in locul telefonului, doar pentru teste)
#   scripts\windows-dev.ps1 stop    deconecteaza, opreste interfata si serverul din WSL
#
# cere: build-ul de windows (cargo build, cd gui; cargo build) si WSL cu Rust instalat.
# pentru tunelul complet: wintun.dll langa target\debug\vpn-client.exe (https://www.wintun.net)

param([ValidateSet("start", "stop", "code")][string]$Action = "start")

$Root = Split-Path $PSScriptRoot -Parent
$Dev = Join-Path $Root "dev"
$Client = Join-Path $Root "target\debug\vpn-client.exe"
$Gui = Join-Path $Root "gui\target\debug\vpn-gui.exe"
$Wintun = Join-Path $Root "target\debug\wintun.dll"
# E:\proiecte\VPN -> /mnt/e/proiecte/VPN
$WslRoot = "/mnt/" + $Root.Substring(0, 1).ToLower() + ($Root.Substring(2) -replace '\\', '/')

function Show-Code {
    $secret = (Get-Content (Join-Path $Dev "secret") -ErrorAction Stop).Trim()
    wsl -- python3 "$WslRoot/scripts/totp.py" $secret
}

switch ($Action) {
    "code" {
        Show-Code
    }
    "stop" {
        & $Client ctl disconnect 2> $null
        Get-Process vpn-gui -ErrorAction SilentlyContinue | Stop-Process
        wsl -u root -- bash "$WslRoot/scripts/dev-wsl-server.sh" stop
        # daemon-ul ruleaza ca administrator: un proces fara drepturi nu il poate opri
        Write-Host "daemon-ul se opreste cu ctrl+c in fereastra lui (cea de administrator)"
    }
    "start" {
        foreach ($f in $Client, $Gui) {
            if (-not (Test-Path $f)) { throw "lipseste $f - ruleaza cargo build (si in gui\)" }
        }
        if (-not (Test-Path $Wintun)) {
            Write-Warning "lipseste $Wintun - interfata va arata eroarea 'lipseste wintun.dll'. il gasesti pe https://www.wintun.net (wintun/bin/amd64/wintun.dll)"
        }

        Write-Host "== binare linux in WSL"
        $wslHome = (wsl -- bash -lc 'echo $HOME').Trim()
        wsl -- bash -lc "cd '$WslRoot' && CARGO_TARGET_DIR=~/vpn-target cargo build -q -p vpn-server -p vpn-client"
        if ($LASTEXITCODE -ne 0) { throw "build-ul din WSL a esuat" }

        Write-Host "== server de dezvoltare in WSL"
        New-Item -ItemType Directory -Force $Dev | Out-Null
        wsl -u root -- env "BIN=$wslHome/vpn-target/debug" bash "$WslRoot/scripts/dev-wsl-server.sh" start "$WslRoot/dev"
        if ($LASTEXITCODE -ne 0) { throw "serverul din WSL nu a pornit" }

        Write-Host "== daemon (ca administrator - confirma fereastra UAC)"
        $config = Join-Path $Dev "client.toml"
        Start-Process -FilePath $Client -ArgumentList "daemon", "--config", "`"$config`"" -Verb RunAs
        Start-Sleep -Seconds 3

        Write-Host "== interfata (user normal)"
        Start-Process -FilePath $Gui
        Write-Host ""
        Write-Host "cod TOTP pentru interfata:"
        Show-Code
        Write-Host ""
        Write-Host "dupa conectare: ping 10.9.0.1   |   cod nou: scripts\windows-dev.ps1 code"
    }
}
