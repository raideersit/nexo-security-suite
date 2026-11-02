function Instream([byte[]]$datos) {
    $t = New-Object Net.Sockets.TcpClient('127.0.0.1', 3310)
    $s = $t.GetStream()
    $cmd = [Text.Encoding]::ASCII.GetBytes("zINSTREAM`0"); $s.Write($cmd, 0, $cmd.Length)
    $len = [BitConverter]::GetBytes([int][Net.IPAddress]::HostToNetworkOrder([int]$datos.Length))
    $s.Write($len, 0, 4); $s.Write($datos, 0, $datos.Length)
    $s.Write([byte[]](0,0,0,0), 0, 4)
    $buf = New-Object byte[] 512; $n = $s.Read($buf, 0, 512)
    $t.Close()
    [Text.Encoding]::ASCII.GetString($buf, 0, $n).TrimEnd("`0", "`n")
}
$a = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR'
$b = '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
'EICAR en memoria -> ' + (Instream ([Text.Encoding]::ASCII.GetBytes($a + $b)))
'texto limpio     -> ' + (Instream ([Text.Encoding]::ASCII.GetBytes('hola mundo limpio')))
