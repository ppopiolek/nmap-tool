import nmap
import pandas as pd
import nvdlib
from io import StringIO as sio
import numpy as np
import click

@click.command()
@click.option('--input', '-i', prompt = 'List of hosts', help='Input file which contains list of hosts to scan. If containing several hosts or address spaces(ip/mask), each of them should be seperated with [space]. Default: lista_hostow.')
@click.option('--output', '-o', prompt='Output file', help='Output file to write processed CSV data.')
@click.option('--sort', '-s', default = True, help = 'If you don\'t want to sort found CVEs descending by CVSS then set this parameter to False. Default: True.')
@click.option('--explode', '-e', default = True, help = 'If you want to keep CVEs for each service in a list then set this parameter to False. Default: True.')
def scan(input, output, sort, explode):
    f = open(input)
    nm = nmap.PortScanner()
    print('Scanning... (this may take a while)')
    nm.scan(f.read())
    print('nmap parameters: ' + nm.command_line())
    print('Processing data and searching for CVEs... (this may take a while)')
    data = sio(nm.csv())
    df = pd.read_csv(data, sep=';')
    df = df.loc[:, ['host', 'hostname', 'port', 'state', 'name', 'product', 'version', 'extrainfo', 'cpe']]
    df['status'] = df['cpe'].apply(lambda x: 'Service not found' if x is np.nan else 'Version not found' if x.count(':') == 3 else 'OK' if x.count(':') == 4 else 'Unknown error')
    df['vunerabilities'] = df['cpe'].apply(lambda x: np.nan if x is np.nan else np.nan if x.count(':') == 3 else [(cve.id, cve.score) for cve in nvdlib.searchCVE(cpeName = x)])
    if sort is True:
        df['vunerabilities'] = df['vunerabilities'].apply(lambda x: np.nan if x is np.nan else sorted(x, key = lambda y: y[1][1], reverse = True))
    if explode is True:
        df_exploded = df.explode('vunerabilities', ignore_index = False)
        df_exploded.reset_index(inplace=True)
    else:
        df_exploded = df
    print('Result:')
    print(df_exploded)
    df_exploded.to_csv(output)
    print('Result saved to: ' + output)

if __name__ == '__main__':
    scan()