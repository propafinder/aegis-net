param(
  [Parameter(Mandatory = $true)][string]$BindAddress,
  [Parameter(Mandatory = $true)][int]$Port,
  [Parameter(Mandatory = $true)][string]$LogPath,
  [Parameter(Mandatory = $true)][string]$Body
)

$ErrorActionPreference = 'Stop'

$address = [System.Net.IPAddress]::Parse($BindAddress)
$listener = [System.Net.Sockets.TcpListener]::new($address, $Port)
Set-Content -Path $LogPath -Value "listener starting $(Get-Date -Format o) on ${BindAddress}:${Port}"
$listener.Start()

try {
  while ($true) {
    $client = $listener.AcceptTcpClient()
    $remote = $client.Client.RemoteEndPoint.ToString()
    Add-Content -Path $LogPath -Value "accepted $remote at $(Get-Date -Format o)"

    $stream = $client.GetStream()
    $buffer = New-Object byte[] 4096
    $count = $stream.Read($buffer, 0, $buffer.Length)
    $request = [Text.Encoding]::ASCII.GetString($buffer, 0, [Math]::Max(0, $count))
    $request = $request.Replace("`r", '\r').Replace("`n", '\n')
    Add-Content -Path $LogPath -Value "request $request"

    $response = "HTTP/1.1 200 OK`r`nContent-Length: $($Body.Length)`r`nConnection: close`r`n`r`n$Body"
    $bytes = [Text.Encoding]::ASCII.GetBytes($response)
    $stream.Write($bytes, 0, $bytes.Length)
    $client.Close()
  }
}
finally {
  $listener.Stop()
}
