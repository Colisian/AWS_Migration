$yourCred = Get-Credential domain\account
$yourServer = "your.server.fqdn"

$LatestThumb = Invoke-Command -ComputerName $yourServer `
                            -Credential $yourCred `
                            -ScriptBlock {
                                Get-ChildItem -Path Cert:\LocalMachine\My |
                                Where-Object {$_.subject -match "CN=$yourServer"} |
                                Sort-Object -Property NotAfter |
                                Select-Object -Last 1 -ExpandProperty Thumbprint
                            }

Set-WSManInstance -ResourceURI winrm/config/Listener `
                  -SelectorSet @{Address="*";Transport="HTTPS"} `
                  -ComputerName $yourServer `
                  -Credential $yourCred `
                  -ValueSet @{CertificateThumbprint=$LatestThumb}

Invoke-Command -ComputerName $yourServer `
               -Credential $yourCred `
               -ScriptBlock { Restart-Service -Force -Name WinRM }


                #username and password
    $username = "trianz"
    $password = ConvertTo-SecureString "NeededForTri@nz!" -AsPlainText -Force

      

   
