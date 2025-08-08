#!/usr/bin/env python3
import socket
import sys
import json

from argparse import ArgumentParser, SUPPRESS, Namespace
from datetime import datetime
from time import sleep
from csv import DictWriter

try:
    from OpenSSL import SSL
except ImportError:
    print('Please install required modules: pip install -r requirements.txt')
    sys.exit(1)


class Clr:
    """Text colors."""

    RST = '\033[39m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'


class SSLChecker:

    total_valid = 0
    total_expired = 0
    total_failed = 0
    total_warning = 0

    def get_cert(self, host, port, socks_host=None, socks_port=None, timeout=10, retries=1):
        """Connect to the host and negotiate TLS, preferring the highest version (TLS 1.3 if available).

        Parameters:
        - timeout: socket timeout in seconds for connect/handshake.
        - retries: number of additional attempts on failure (>=0).
        """
        use_socks = False
        socks_module = None
        if socks_host:
            import socks as _socks
            socks_module = _socks
            use_socks = True

        # Prefer a generic TLS client method (negotiates the highest version, including TLS 1.3),
        # with a single legacy alias fallback for older OpenSSL.
        method_candidates = []
        if hasattr(SSL, 'TLS_CLIENT_METHOD'):
            method_candidates.append(('auto', SSL.TLS_CLIENT_METHOD))
        elif hasattr(SSL, 'TLS_METHOD'):
            method_candidates.append(('auto', SSL.TLS_METHOD))
        elif hasattr(SSL, 'SSLv23_METHOD'):
            # Historical alias that negotiates the highest available protocol
            method_candidates.append(('auto', SSL.SSLv23_METHOD))

        last_error = None
        attempts = max(0, int(retries)) + 1
        for attempt in range(attempts):
            for label, tls_method in method_candidates:
                sock = None
                try:
                    if use_socks and socks_module is not None:
                        sock = socks_module.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                        sp = 1080 if socks_port is None else int(socks_port)
                        socks_module.setdefaultproxy(socks_module.PROXY_TYPE_SOCKS5, socks_host, sp, True)
                    else:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((host, int(port)))
                    # Use blocking mode for the SSL handshake to avoid premature timeouts
                    sock.settimeout(None)

                    ctx = SSL.Context(tls_method)
                    con = SSL.Connection(ctx, sock)
                    con.set_tlsext_host_name(host.encode())
                    con.set_connect_state()
                    con.do_handshake()

                    cert = con.get_peer_certificate()
                    try:
                        resolved_ip = socket.gethostbyname(host)
                    except Exception:
                        resolved_ip = ''

                    # Determine the negotiated protocol version if available
                    tls_version = label
                    if hasattr(con, 'get_protocol_version_name'):
                        try:
                            negotiated = con.get_protocol_version_name()
                            if negotiated and isinstance(negotiated, str):
                                tls_version = negotiated.replace('TLSv', 'TLS ')
                        except Exception:
                            pass
                    return cert, resolved_ip, tls_version
                except Exception as e:
                    last_error = e
                    continue
                finally:
                    try:
                        if sock:
                            sock.close()
                    except Exception:
                        pass
            # Backoff before next attempt (short to keep CI fast)
            if attempt < attempts - 1:
                sleep(1)

        # If all attempts fail, raise the last captured error
        if last_error:
            raise last_error
        raise SSL.SysCallError("Failed to establish SSL connection with any supported TLS version")

    def border_msg(self, message):
        """Print the message in the box."""
        row = len(message)
        h = ''.join(['+'] + ['-' * row] + ['+'])
        result = h + '\n' "|" + message + "|"'\n' + h
        print(result)

    def analyze_ssl(self, host, context, user_args):
        """Analyze the security of the SSL certificate using SSL Labs.

        Fast-path behavior: prefer cached results and avoid long waits/timeouts in CI.
        If cached results are not READY, annotate and return without blocking.
        """
        from urllib.request import urlopen
        from urllib.error import URLError, HTTPError

        api_url = 'https://api.ssllabs.com/api/v3/'
        analyze_url = f"{api_url}analyze?host={host}&fromCache=on&all=done&startNew=off"

        if user_args.verbose:
            print('{}Requesting analyze (cached) from {}{}\n'.format(Clr.YELLOW, api_url, Clr.RST))

        try:
            main_request = json.loads(urlopen(analyze_url, timeout=10).read().decode('utf-8'))
        except (URLError, HTTPError, TimeoutError) as e:
            # Do not fail the overall run; annotate and return
            context.setdefault(host, {})
            context[host]['analyze_error'] = f'SSL Labs request failed: {e}'
            return context

        status = main_request.get('status')
        if status != 'READY':
            # Avoid long waits; annotate status and return
            context.setdefault(host, {})
            context[host]['analyze_status'] = status or 'UNKNOWN'
            return context

        # With READY status, proceed to fetch endpoint details
        try:
            ip_addr = main_request['endpoints'][0]['ipAddress']
            endpoint_url = f"{api_url}getEndpointData?host={host}&s={ip_addr}"
            endpoint_data = json.loads(urlopen(endpoint_url, timeout=10).read().decode('utf-8'))
        except Exception as e:
            context.setdefault(host, {})
            context[host]['analyze_error'] = f'Endpoint fetch failed: {e}'
            return context

        if user_args.verbose:
            print('{}Analyze report message: {}{}\n'.format(Clr.YELLOW, endpoint_data.get('statusMessage', 'n/a'), Clr.RST))

        # if the certificate is invalid
        if endpoint_data.get('statusMessage') == 'Certificate not valid for domain name':
            return context

        # Populate known fields when present
        try:
            context[host]['grade'] = main_request['endpoints'][0].get('grade')
            details = endpoint_data.get('details', {})
            context[host]['poodle_vuln'] = details.get('poodle')
            context[host]['heartbleed_vuln'] = details.get('heartbleed')
            context[host]['heartbeat_vuln'] = details.get('heartbeat')
            context[host]['freak_vuln'] = details.get('freak')
            context[host]['logjam_vuln'] = details.get('logjam')
            context[host]['drownVulnerable'] = details.get('drownVulnerable')
        except Exception:
            # Keep resilient even if schema shifts
            pass

        return context

    def get_cert_sans(self, x509cert):
        """Get Subject Alt Names without using deprecated pyOpenSSL X.509 extension APIs.

        Returns a semicolon-separated string like "DNS:example.com; DNS:*.example.com; IP:1.2.3.4"
        to preserve backward compatibility with existing outputs.
        """
        try:
            from cryptography import x509 as cx509
            from cryptography.x509.oid import ExtensionOID
        except Exception:
            # Fallback to original behavior if cryptography import fails (unlikely since pyOpenSSL depends on it)
            try:
                san = ''
                ext_count = x509cert.get_extension_count()
                for i in range(0, ext_count):
                    ext = x509cert.get_extension(i)
                    if 'subjectAltName' in str(ext.get_short_name()):
                        san = ext.__str__()
                return san.replace(',', ';')
            except Exception:
                return ''

        try:
            crypto_cert = x509cert.to_cryptography()
            san_ext = crypto_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            dns_names = san_ext.get_values_for_type(cx509.DNSName)
            ip_addrs = san_ext.get_values_for_type(cx509.IPAddress)
            parts = []
            for d in dns_names:
                parts.append(f'DNS:{d}')
            for ip in ip_addrs:
                parts.append(f'IP:{ip}')
            return '; '.join(parts)
        except Exception:
            return ''

    def get_cert_info(self, host, cert, resolved_ip, tls_version=None):
        """Get all the information about cert and create a JSON file."""
        context = {}

        cert_subject = cert.get_subject()

        context['host'] = host
        context['resolved_ip'] = resolved_ip
        context['tls_version'] = tls_version
        context['issued_to'] = cert_subject.CN
        context['issued_o'] = cert_subject.O
        context['issuer_c'] = cert.get_issuer().countryName
        context['issuer_o'] = cert.get_issuer().organizationName
        context['issuer_ou'] = cert.get_issuer().organizationalUnitName
        context['issuer_cn'] = cert.get_issuer().commonName
        context['cert_sn'] = str(cert.get_serial_number())
        context['cert_sha1'] = cert.digest('sha1').decode()
        context['cert_alg'] = cert.get_signature_algorithm().decode()
        context['cert_ver'] = cert.get_version()
        context['cert_sans'] = self.get_cert_sans(cert)
        context['cert_exp'] = cert.has_expired()
        context['cert_valid'] = False if cert.has_expired() else True

        # Valid from
        valid_from = datetime.strptime(cert.get_notBefore().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
        context['valid_from'] = valid_from.strftime('%Y-%m-%d')

        # Valid till
        valid_till = datetime.strptime(cert.get_notAfter().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
        context['valid_till'] = valid_till.strftime('%Y-%m-%d')

        # Validity days
        context['validity_days'] = (valid_till - valid_from).days

        # Validity in days from now
        now = datetime.now()
        context['days_left'] = (valid_till - now).days

        # Valid days left
        context['valid_days_to_expire'] = (datetime.strptime(context['valid_till'],
                                           '%Y-%m-%d') - datetime.now()).days

        if cert.has_expired():
            self.total_expired += 1
        else:
            self.total_valid += 1

        # If the certificate has less than 15 days validity
        if context['valid_days_to_expire'] <= 15:
            self.total_warning += 1

        return context

    def print_status(self, host, context, analyze=False):
        """Print all the usefull info about host."""
        print('\t{}[\u2713]{} {}\n\t{}'.format(Clr.GREEN if context[host]['cert_valid'] else Clr.RED, Clr.RST, host, '-' * (len(host) + 5)))
        print('\t\tIssued domain: {}'.format(context[host]['issued_to']))
        print('\t\tIssued to: {}'.format(context[host]['issued_o']))
        print('\t\tIssued by: {} ({})'.format(context[host]['issuer_o'], context[host]['issuer_c']))
        print('\t\tServer IP: {}'.format(context[host]['resolved_ip']))
        print('\t\tValid from: {}'.format(context[host]['valid_from']))
        print('\t\tValid to: {} ({} days left)'.format(context[host]['valid_till'], context[host]['valid_days_to_expire']))
        print('\t\tValidity days: {}'.format(context[host]['validity_days']))
        print('\t\tTLS Version: {}'.format(context[host]['tls_version']))
        print('\t\tCertificate valid: {}'.format(context[host]['cert_valid']))
        print('\t\tCertificate S/N: {}'.format(context[host]['cert_sn']))
        print('\t\tCertificate SHA1 FP: {}'.format(context[host]['cert_sha1']))
        print('\t\tCertificate version: {}'.format(context[host]['cert_ver']))
        print('\t\tCertificate algorithm: {}'.format(context[host]['cert_alg']))

        if analyze:
            print('\t\tCertificate grade: {}'.format(context[host]['grade']))
            print('\t\tPoodle vulnerability: {}'.format(context[host]['poodle_vuln']))
            print('\t\tHeartbleed vulnerability: {}'.format(context[host]['heartbleed_vuln']))
            print('\t\tHeartbeat vulnerability: {}'.format(context[host]['heartbeat_vuln']))
            print('\t\tFreak vulnerability: {}'.format(context[host]['freak_vuln']))
            print('\t\tLogjam vulnerability: {}'.format(context[host]['logjam_vuln']))
            print('\t\tDrown vulnerability: {}'.format(context[host]['drownVulnerable']))

        print('\t\tExpired: {}'.format(context[host]['cert_exp']))
        print('\t\tCertificate SANs: ')

        for san in context[host]['cert_sans'].split(';'):
            print('\t\t \\_ {}'.format(san.strip()))

        print('\n')

    def show_result(self, user_args):
        """Get the context."""
        context = {}
        start_time = datetime.now()
        hosts = user_args.hosts

        if not user_args.json_true and not user_args.summary_true:
            self.border_msg(' Analyzing {} host(s) '.format(len(hosts)))

        if not user_args.json_true and user_args.analyze:
            print('{}Warning: -a/--analyze is enabled. It takes more time...{}\n'.format(Clr.YELLOW, Clr.RST))

        for host in hosts:
            if user_args.verbose:
                print('{}Working on host: {}{}\n'.format(Clr.YELLOW, host, Clr.RST))

            host, port = self.filter_hostname(host)

            # Check duplication
            if host in context.keys():
                continue

            try:
                # Check if socks should be used
                if user_args.socks:
                    if user_args.verbose:
                        print('{}Socks proxy enabled, connecting via proxy{}\n'.format(Clr.YELLOW, Clr.RST))

                    # Parse SOCKS address separately: default port 1080 if omitted
                    if ':' in str(user_args.socks):
                        socks_host, socks_port = str(user_args.socks).split(':', 1)
                    else:
                        socks_host, socks_port = str(user_args.socks), 1080
                    cert, resolved_ip, tls_version = self.get_cert(host, port, socks_host, socks_port, timeout=getattr(user_args, 'timeout', 10), retries=getattr(user_args, 'retries', 1))
                else:
                    cert, resolved_ip, tls_version = self.get_cert(host, port, timeout=getattr(user_args, 'timeout', 10), retries=getattr(user_args, 'retries', 1))

                context[host] = self.get_cert_info(host, cert, resolved_ip, tls_version)
                context[host]['tcp_port'] = int(port)

                # Analyze the certificate if enabled
                if user_args.analyze:
                    context = self.analyze_ssl(host, context, user_args)

                if not user_args.json_true and not user_args.summary_true:
                    self.print_status(host, context, user_args.analyze)
            except SSL.SysCallError:
                context[host] = 'failed'
                if not user_args.json_true:
                    print('\t{}[\u2717]{} {:<20s} Failed: Misconfigured SSL/TLS\n'.format(Clr.RED, Clr.RST, host))
                    self.total_failed += 1
            except Exception as error:
                context[host] = 'failed'
                if not user_args.json_true:
                    print('\t{}[\u2717]{} {:<20s} Failed: {}\n'.format(Clr.RED, Clr.RST, host, error))
                    self.total_failed += 1
            except KeyboardInterrupt:
                print('{}Canceling script...{}\n'.format(Clr.YELLOW, Clr.RST))
                sys.exit(1)

        if not user_args.json_true:
            self.border_msg(' Successful: {} | Failed: {} | Valid: {} | Warning: {} | Expired: {} | Duration: {} '.format(
                len(hosts) - self.total_failed, self.total_failed, self.total_valid,
                self.total_warning, self.total_expired, datetime.now() - start_time))
            if user_args.summary_true:
                # Exit the script just
                return

        # CSV export if -c/--csv is specified
        if user_args.csv_enabled:
            self.export_csv(context, user_args.csv_enabled, user_args)

        # HTML export if -x/--html is specified
        if user_args.html_true:
            self.export_html(context)

        # While using the script as a module
        if __name__ != '__main__':
            return json.dumps(context)

        # Enable JSON output if -j/--json argument specified
        if user_args.json_true:
            print(json.dumps(context))

        if user_args.json_save_true:
            for host in context.keys():
                with open(host + '.json', 'w', encoding='UTF-8') as fp:
                    fp.write(json.dumps(context[host]))

    def export_csv(self, context, filename, user_args):
        """Export all context results to CSV file."""
        # prepend dict keys to write column headers
        if user_args.verbose:
            print('{}Generating CSV export{}\n'.format(Clr.YELLOW, Clr.RST))

        # Filter only successful dict entries
        records = [v for v in context.values() if isinstance(v, dict)]
        if not records:
            if user_args.verbose:
                print('{}No successful records to export to CSV{}\n'.format(Clr.YELLOW, Clr.RST))
            return

        with open(filename, 'w') as csv_file:
            csv_writer = DictWriter(csv_file, records[0].keys())
            csv_writer.writeheader()
            for rec in records:
                csv_writer.writerow(rec)

    def export_html(self, context):
        """Export JSON to HTML."""
        import importlib
        try:
            json2html_module = importlib.import_module('json2html')
        except ImportError:
            print('HTML export requires json2html. Please install it via: pip install json2html')
            return

        html = json2html_module.json2html.convert(json=context)
        file_name = datetime.strftime(datetime.now(), '%Y_%m_%d_%H_%M_%S')
        with open('{}.html'.format(file_name), 'w', encoding='utf-8') as html_file:
            html_file.write(html)

        return

    def filter_hostname(self, host):
        """Remove unused characters and split by address and port."""
        host = host.replace('http://', '').replace('https://', '').replace('/', '')
        port = 443
        if ':' in host:
            host, port = host.split(':')

        return host, port

    def get_args(self, json_args={}):
        """Set argparse options."""
        parser = ArgumentParser(prog='ssl_checker.py', add_help=False,
                                description="""Collects useful information about the given host's SSL certificates.""")

        if len(json_args) > 0:
            # When used as a module, don't parse sys.argv; construct a Namespace
            args = Namespace()
            setattr(args, 'json_true', True)
            setattr(args, 'verbose', False)
            setattr(args, 'csv_enabled', False)
            setattr(args, 'html_true', False)
            setattr(args, 'json_save_true', False)
            setattr(args, 'socks', False)
            setattr(args, 'analyze', False)
            setattr(args, 'summary_true', False)
            setattr(args, 'hosts', json_args['hosts'])
            return args

        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-H', '--host', dest='hosts', nargs='*',
                           required=False, help='Hosts as input separated by space')
        group.add_argument('-f', '--host-file', dest='host_file',
                           required=False, help='Hosts as input from a file')
        parser.add_argument('-s', '--socks', dest='socks',
                            default=False, metavar='HOST:PORT',
                            help='Enable SOCKS proxy for connection')
        parser.add_argument('-c', '--csv', dest='csv_enabled',
                            default=False, metavar='FILENAME.CSV',
                            help='Enable CSV file export')
        parser.add_argument('-j', '--json', dest='json_true',
                            action='store_true', default=False,
                            help='Enable JSON in the output')
        parser.add_argument('-S', '--summary', dest='summary_true',
                            action='store_true', default=False,
                            help='Enable summary output only')
        parser.add_argument('-x', '--html', dest='html_true',
                            action='store_true', default=False,
                            help='Enable HTML file export')
        parser.add_argument('-J', '--json-save', dest='json_save_true',
                            action='store_true', default=False,
                            help='Enable JSON export individually per host')
        parser.add_argument('-a', '--analyze', dest='analyze',
                            default=False, action='store_true',
                            help='Enable SSL security analysis on the host')
        parser.add_argument('-v', '--verbose', dest='verbose',
                            default=False, action='store_true',
                            help='Enable verbose to see what is going on')
        parser.add_argument('-h', '--help', default=SUPPRESS,
                            action='help',
                            help='Show this help message and exit')

        args = parser.parse_args()

        # Get hosts from file if provided
        if args.host_file:
            with open(args.host_file) as f:
                args.hosts = f.read().splitlines()

        # Checks hosts list
        if isinstance(args.hosts, list):
            if len(args.hosts) == 0:
                parser.print_help()
                sys.exit(0)

        return args


if __name__ == '__main__':
    SSLCheckerObject = SSLChecker()
    SSLCheckerObject.show_result(SSLCheckerObject.get_args(json_args={}))
