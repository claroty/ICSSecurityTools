# SMBv3Compression Tester

NSE Script to check if a Windows machine has SMBv3 protocol enabled with the compression feature.
Currently it's a standalone NSE script with a patched lua file but we will PR the nmap repository with those changes.

## Supported CVEs

* No CVE has been published yet.

## Requirements

* nmap

## Usage
`cd` into run `SMBv3Compression` (your cwd must be the same as the files) and run:

    nmap -p445 --script ./smb2-capabilities_patched.nse IP_ADDR

Search for `SMBv3 Compression LZTN1 (Negotiation Context)`.



## Disable SMBv3 compression
You can disable SMBv3 compression with the PowerShell command below:

    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force

## License
Apache License 2.0. See the parent directory.


## Disclaimer
There is no warranty, expressed or implied, associated with this product.
