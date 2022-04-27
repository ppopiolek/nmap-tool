## Check _nmap-tool.ipynb_ notebook

Script nmap-tool.py is based on code snippets presented in section 2 of nmap-tool.ipynb. In addition it implements *click* library functionality.

Following tool:
- does nmap scanning for all given hosts
- verifies all opened ports
- returns versions of services found on opened ports
- lists vunerabilities for those services
- saves the result to CSV file for further analysis
   
Components and libraries
- ```Nmap 7.92``` scanning tool
- ```Python 3.9.5``` script language
- ```python-nmap 0.7.1``` nmap library for python
- ```pandas 1.3.5``` data processing library for python
- ```nvdlib 0.5.6``` obtaining CVEs library for python
