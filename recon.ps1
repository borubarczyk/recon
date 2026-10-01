<#
================================================================================
 Recon.ps1  —  external attack surface recon po incydencie 
Natywny PowerShell (5.1+), bez instalowania basha. Wynik: raport HTML + pliki CSV.

 ZAKRES / LEGALNOŚĆ:
   Uruchamiaj TYLKO na infrastrukturze, którą administrujesz lub masz zgodę testować.
   Fazy Ports/Web/WP są AKTYWNE — trzymaj się własnych domen/IP.

 UŻYCIE (PowerShell):
   .\Recon.ps1 -InputFile .\lista.txt
   .\Recon.ps1 -InputFile .\lista.txt -Phases dns,ip,tls,web,wp        # bez portów
   .\Recon.ps1 -InputFile .\lista.txt -Ports 80,443,3389,3306,8080,8443
   # jak PowerShell blokuje skrypt:  powershell -ExecutionPolicy Bypass -File .\Recon.ps1 -InputFile .\lista.txt

 WYMAGANE: Windows PowerShell 5.1 lub PowerShell 7. Wszystko na wbudowanych cmdletach.
 OPCJONALNIE: nmap.exe w PATH -> faza Ports użyje nmapa (dokładniej: wersje usług).
              Bez nmapa robi własny, równoległy test portów TCP.
================================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InputFile,
    [string[]]$Phases = @('dns','ip','ports','web','wp','tls'),
    [int[]]$Ports = @(21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,1521,3000,3306,3389,5432,5900,6379,8000,8080,8081,8443,8888,9200,10000),
    [int]$TimeoutMs = 1500
)

# TLS 1.2 dla RDAP/crt.sh (5.1 domyślnie potrafi mieć starsze)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not (Test-Path $InputFile)) { Write-Error "Nie ma pliku: $InputFile"; exit 1 }
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutDir = Join-Path (Get-Location) "recon_$stamp"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Hosts = Get-Content $InputFile |
    ForEach-Object { $_.Trim().TrimStart('*').TrimStart('.') } |
    Where-Object { $_ -and $_ -notmatch '^\s*#' } |
    ForEach-Object { $_.ToLower() } | Sort-Object -Unique

Write-Host "[i] Hostow: $($Hosts.Count)   Fazy: $($Phases -join ',')   Katalog: $OutDir" -ForegroundColor Cyan

# kontener na wyniki do raportu HTML
$R = [ordered]@{ dns=@(); ptr=@(); prov=@(); ports=@(); web=@(); wp=@(); tls=@() }

#--------------------------------------------------------------------- 1. DNS
if ($Phases -contains 'dns') {
    Write-Host "[*] DNS..." -ForegroundColor Yellow
    foreach ($h in $Hosts) {
        foreach ($t in 'A','AAAA','CNAME','MX','NS','TXT') {
            try {
                Resolve-DnsName -Name $h -Type $t -ErrorAction Stop |
                Where-Object { $_.Type -eq $t } | ForEach-Object {
                    $val = switch ($t) {
                        'A'     { $_.IPAddress }
                        'AAAA'  { $_.IPAddress }
                        'CNAME' { $_.NameHost }
                        'MX'    { "$($_.NameExchange) (pref $($_.Preference))" }
                        'NS'    { $_.NameHost }
                        'TXT'   { ($_.Strings -join ' ') }
                    }
                    if ($val) { $R.dns += [pscustomobject]@{ Host=$h; Type=$t; Value=$val } }
                }
            } catch {}
        }
    }
    $IPs = $R.dns | Where-Object { $_.Type -in 'A','AAAA' } | Select-Object -Expand Value | Sort-Object -Unique
    Write-Host "[i] Unikalnych IP: $($IPs.Count)"
    # PTR
    foreach ($ip in $IPs) {
        $ptr = try { (Resolve-DnsName -Name $ip -Type PTR -ErrorAction Stop | Select-Object -Expand NameHost) -join ', ' } catch { '<brak>' }
        $R.ptr += [pscustomobject]@{ IP=$ip; PTR=$ptr }
    }
    $R.dns  | Export-Csv "$OutDir\dns.csv"  -NoTypeInformation -Encoding UTF8
    $R.ptr  | Export-Csv "$OutDir\ptr.csv"  -NoTypeInformation -Encoding UTF8
} else {
    $IPs = @()
}

#------------------------------------------------------------------ 2. IP / PROVIDER (RDAP)
if ($Phases -contains 'ip') {
    Write-Host "[*] IP / dostawca (RDAP)..." -ForegroundColor Yellow
    if (-not $IPs -or $IPs.Count -eq 0) {
        $IPs = $R.dns | Where-Object { $_.Type -in 'A','AAAA' } | Select-Object -Expand Value | Sort-Object -Unique
    }
    foreach ($ip in $IPs) {
        $org=''; $cc=''; $handle=''
        try {
            $d = Invoke-RestMethod -Uri "https://rdap.org/ip/$ip" -TimeoutSec 15 -ErrorAction Stop
            $handle = $d.handle
            $cc     = $d.country
            $org    = ($d.entities | Where-Object { $_.roles -contains 'registrant' -or $_.roles -contains 'administrative' } |
                        Select-Object -First 1).vcardArray[1] | Where-Object { $_[0] -eq 'fn' } | ForEach-Object { $_[3] }
            if (-not $org) { $org = $d.name }
        } catch { $org = '(RDAP niedostepny)' }
        $R.prov += [pscustomobject]@{ IP=$ip; Blok=$handle; Wlasciciel=$org; Kraj=$cc }
    }
    $R.prov | Export-Csv "$OutDir\providers.csv" -NoTypeInformation -Encoding UTF8
    $R.prov | Format-Table -AutoSize | Out-String | Write-Host
}

#--------------------------------------------------------------------- 3. PORTS
if ($Phases -contains 'ports') {
    if (-not $IPs -or $IPs.Count -eq 0) {
        $IPs = $R.dns | Where-Object { $_.Type -in 'A','AAAA' } | Select-Object -Expand Value | Sort-Object -Unique
    }
    $nmap = Get-Command nmap.exe -ErrorAction SilentlyContinue
    if ($nmap) {
        Write-Host "[*] Ports (nmap.exe)..." -ForegroundColor Yellow
        $IPs | Set-Content "$OutDir\ips.txt"
        $pl = $Ports -join ','
        & nmap.exe -Pn -sV --open -p $pl -iL "$OutDir\ips.txt" -oN "$OutDir\nmap.txt" | Out-Null
        Write-Host "[i] Wynik nmap: $OutDir\nmap.txt"
        # do raportu wrzucamy surowy tekst
        $R.ports += [pscustomobject]@{ IP='(nmap)'; Otwarte = (Get-Content "$OutDir\nmap.txt" -Raw) }
    } else {
        Write-Host "[*] Ports (TCP connect, rownolegle — brak nmap.exe)..." -ForegroundColor Yellow
        $pool = [runspacefactory]::CreateRunspacePool(1, 64); $pool.Open()
        $jobs = @()
        $probe = {
            param($ip,$port,$to)
            $c = New-Object Net.Sockets.TcpClient
            try {
                $ar = $c.BeginConnect($ip,$port,$null,$null)
                if ($ar.AsyncWaitHandle.WaitOne($to)) { $c.EndConnect($ar); if ($c.Connected){ return "$ip`:$port" } }
            } catch {} finally { $c.Close() }
            return $null
        }
        foreach ($ip in $IPs) { foreach ($p in $Ports) {
            $ps = [powershell]::Create().AddScript($probe).AddArgument($ip).AddArgument($p).AddArgument($TimeoutMs)
            $ps.RunspacePool = $pool
            $jobs += [pscustomobject]@{ PS=$ps; H=$ps.BeginInvoke() }
        }}
        $open = foreach ($j in $jobs) { $r = $j.PS.EndInvoke($j.H); $j.PS.Dispose(); if ($r){ $r } }
        $pool.Close()
        $byIp = $open | Group-Object { ($_ -split ':')[0] }
        foreach ($g in $byIp) {
            $R.ports += [pscustomobject]@{ IP=$g.Name; Otwarte = (($g.Group | ForEach-Object { ($_ -split ':')[1] }) -join ', ') }
        }
        $R.ports | Export-Csv "$OutDir\ports.csv" -NoTypeInformation -Encoding UTF8
        $R.ports | Format-Table -AutoSize | Out-String | Write-Host
    }
}

#----------------------------------------------------------------------- 4. WEB
$LiveUrls = @()
if ($Phases -contains 'web') {
    Write-Host "[*] Web (naglowki, tytul, tech)..." -ForegroundColor Yellow
    # ignoruj bledy certów (chcemy dojsc mimo zlego cert)
    try { Add-Type @"
using System.Net;using System.Security.Cryptography.X509Certificates;
public class TrustAll : ICertificatePolicy { public bool CheckValidationResult(ServicePoint s,X509Certificate c,WebRequest r,int p){return true;} }
"@ ; [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAll } catch {}
    foreach ($h in $Hosts) {
        foreach ($scheme in 'https','http') {
            $url = "${scheme}://$h"
            try {
                $resp = Invoke-WebRequest -Uri $url -TimeoutSec 15 -MaximumRedirection 5 -UseBasicParsing -ErrorAction Stop
                $server = $resp.Headers['Server']
                $powered = $resp.Headers['X-Powered-By']
                $title = if ($resp.Content -match '<title[^>]*>([^<]*)') { $matches[1].Trim() } else { '' }
                $R.web += [pscustomobject]@{ URL=$url; Kod=$resp.StatusCode; Server=$server; 'X-Powered-By'=$powered; Tytul=$title }
                $LiveUrls += $url
            } catch {
                $code = $_.Exception.Response.StatusCode.value__
                if ($code) { $R.web += [pscustomobject]@{ URL=$url; Kod=$code; Server=''; 'X-Powered-By'=''; Tytul='(blad/redirect)' }; $LiveUrls += $url }
            }
        }
    }
    $LiveUrls = $LiveUrls | Sort-Object -Unique
    $R.web | Export-Csv "$OutDir\web.csv" -NoTypeInformation -Encoding UTF8
    $R.web | Format-Table -AutoSize | Out-String | Write-Host
}

#------------------------------------------------------------------------ 5. WP
if ($Phases -contains 'wp') {
    Write-Host "[*] WordPress..." -ForegroundColor Yellow
    if (-not $LiveUrls -or $LiveUrls.Count -eq 0) { $LiveUrls = $Hosts | ForEach-Object { "https://$_" } }
    function Get-Code($u){ try { (Invoke-WebRequest $u -TimeoutSec 12 -UseBasicParsing -MaximumRedirection 0 -ErrorAction Stop).StatusCode } catch { $_.Exception.Response.StatusCode.value__ } }
    foreach ($base in $LiveUrls) {
        $base = $base.TrimEnd('/')
        $findings = New-Object System.Collections.Generic.List[string]
        $isWp = $false
        try {
            $home = Invoke-WebRequest "$base/" -TimeoutSec 15 -UseBasicParsing -MaximumRedirection 5 -ErrorAction Stop
            if ($home.Content -match 'wp-content|wp-includes|/wp-json') { $isWp = $true }
            if ($home.Content -match '<meta name="generator" content="([^"]*)"') { $findings.Add("generator: $($matches[1])") }
        } catch {}
        $lc = Get-Code "$base/wp-login.php"
        if ($lc -in 200,302) { $isWp = $true; $findings.Add("wp-login.php: $lc (panel wystawiony)") }

        if ($isWp) {
            try { $rd = (Invoke-WebRequest "$base/readme.html" -TimeoutSec 12 -UseBasicParsing -ErrorAction Stop).Content
                  if ($rd -match 'Version ([0-9.]+)') { $findings.Add("readme.html -> Version $($matches[1])  (USUN ten plik)") } } catch {}
            $xc = Get-Code "$base/xmlrpc.php"; if ($xc -in 200,405) { $findings.Add("xmlrpc.php: $xc (rozwaz wylaczenie)") }
            try { $u = Invoke-RestMethod "$base/wp-json/wp/v2/users" -TimeoutSec 12 -ErrorAction Stop
                  if ($u) { $findings.Add("wp-json users (ENUMERACJA): " + (($u | ForEach-Object { "$($_.id):$($_.slug)" }) -join ', ')) } } catch {}
            foreach ($f in 'wp-config.php.bak','wp-config.bak','.env','.git/config','backup.zip','db.sql','dump.sql','wp-content/debug.log') {
                if ((Get-Code "$base/$f") -eq 200) { $findings.Add("!!! /$f dostepny (200) — WYCIEK") }
            }
        } else { $findings.Add('(nie wyglada na WordPress)') }
        $R.wp += [pscustomobject]@{ URL=$base; Ustalenia = ($findings -join " | ") }
    }
    $R.wp | Export-Csv "$OutDir\wordpress.csv" -NoTypeInformation -Encoding UTF8
    $R.wp | Format-Table -AutoSize -Wrap | Out-String | Write-Host
    Write-Host "[i] Glebszy skan: wpscan --url <host> --enumerate vp,u  (przez WSL/Docker)"
}

#----------------------------------------------------------------------- 6. TLS
if ($Phases -contains 'tls') {
    Write-Host "[*] TLS (cert, SAN)..." -ForegroundColor Yellow
    foreach ($h in $Hosts) {
        try {
            $tcp = New-Object Net.Sockets.TcpClient($h, 443)
            $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, ({ $true }))
            $ssl.AuthenticateAsClient($h)
            $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $ssl.RemoteCertificate
            $san = ($cert.Extensions | Where-Object { $_.Oid.FriendlyName -match 'Subject Alternative' } |
                    ForEach-Object { $_.Format($false) }) -join ' '
            $R.tls += [pscustomobject]@{ Host=$h; Subject=$cert.Subject; Wystawca=$cert.Issuer; Wazny_do=$cert.NotAfter; SAN=$san }
            $ssl.Close(); $tcp.Close()
        } catch { $R.tls += [pscustomobject]@{ Host=$h; Subject='(brak TLS/blad)'; Wystawca=''; Wazny_do=''; SAN='' } }
    }
    $R.tls | Export-Csv "$OutDir\tls.csv" -NoTypeInformation -Encoding UTF8
    Write-Host "[i] SAN w certach potrafi ujawnic subdomeny spoza subfindera."
}

#=============================================================== RAPORT HTML
Write-Host "[*] Buduje raport HTML..." -ForegroundColor Green
$css = @"
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#0f1420;color:#e6e6e6;margin:0;padding:24px}
h1{color:#6ea8fe} h2{color:#8bd450;border-bottom:1px solid #2a3350;padding-bottom:6px;margin-top:32px}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}
th{background:#1b2338;color:#9db4ff;text-align:left;padding:6px 10px}
td{border-top:1px solid #232c44;padding:6px 10px;vertical-align:top}
tr:nth-child(even){background:#141b2c}
.warn{color:#ff7b7b;font-weight:bold} .ok{color:#8bd450}
small{color:#8a93a8}
</style>
"@
function Section($title,$data){
    if (-not $data -or $data.Count -eq 0) { return "<h2>$title</h2><p><small>brak danych</small></p>" }
    $html = $data | ConvertTo-Html -Fragment
    # podswietl krytyczne
    $html = $html -replace '(!!!.*?WYCIEK|ENUMERACJA|panel wystawiony)', '<span class="warn">$1</span>'
    return "<h2>$title</h2>$html"
}
$body = @"
<h1>Recon report</h1>
<p><small>Wejscie: $InputFile &middot; Hostow: $($Hosts.Count) &middot; Wygenerowano: $(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; Fazy: $($Phases -join ', ')</small></p>
$(Section 'DNS' $R.dns)
$(Section 'Reverse DNS (PTR)' $R.ptr)
$(Section 'IP / dostawca (RDAP)' $R.prov)
$(Section 'Otwarte porty' $R.ports)
$(Section 'Web (naglowki / tech)' $R.web)
$(Section 'WordPress' $R.wp)
$(Section 'Certyfikaty TLS' $R.tls)
"@
$report = Join-Path $OutDir 'raport.html'
"<html><head><meta charset='utf-8'>$css</head><body>$body</body></html>" | Set-Content $report -Encoding UTF8
Write-Host "[OK] Raport: $report" -ForegroundColor Green
Start-Process $report   # otwiera w przegladarce
