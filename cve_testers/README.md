# CVE Testers

Scripts used to check whether OT devices are vulnerable to published vulnerabilities.

## Supported CVEs

* CVE-2019-12258: One of 11 vulnerabilities in VxWorks (also known as URGENT/11), made public in July 2019. 
CVE-2019-12258 is a DoS vulnerability which allows to drop existing TCP connections. 
The vulnerability affects VxWorks v6.5 and above, and affected devices are often vulnerable to other URGENT/11 vulnerabilities.
For more details, see [Claroty's blog post](https://blog.claroty.com/mitigating-the-impact-of-urgent11-on-ics/ot-networks)

## Requirements

* Python 3.6 or above
* Required python libraries are listed in requirements.txt

## Usage
* run `python3 cve_testers/cve_2019_12258.py -h` for detailed help


## License
Apache License 2.0. See the parent directory.


## Disclaimer
There is no warranty, expressed or implied, associated with this product.
