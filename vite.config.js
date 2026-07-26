import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import net from 'net'
import url from 'url'

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'real-tcp-scanner-backend',
      configureServer(server) {
        server.middlewares.use('/api/scan', async (req, res) => {
          const reqUrl = url.parse(req.url, true);
          const target = reqUrl.query.target || '127.0.0.1';

          // List of common ports to perform real TCP Connect Scan
          const portsToScan = [
            { port: 21, name: 'FTP', service: 'File Transfer Protocol' },
            { port: 22, name: 'SSH', service: 'Secure Shell Remote Login' },
            { port: 23, name: 'Telnet', service: 'Unencrypted Telnet Text Protocol' },
            { port: 25, name: 'SMTP', service: 'Simple Mail Transfer Protocol' },
            { port: 53, name: 'DNS', service: 'Domain Name System' },
            { port: 80, name: 'HTTP', service: 'Web Server (HTTP)' },
            { port: 110, name: 'POP3', service: 'Post Office Protocol Mail' },
            { port: 135, name: 'MSRPC', service: 'Microsoft RPC Endpoint Mapper' },
            { port: 139, name: 'NetBIOS', service: 'NetBIOS Session Service' },
            { port: 143, name: 'IMAP', service: 'Internet Message Access Protocol' },
            { port: 443, name: 'HTTPS', service: 'Secure Web Server (HTTPS)' },
            { port: 445, name: 'SMB', service: 'Microsoft SMB File Sharing (MS17-010 Risk)' },
            { port: 1433, name: 'MSSQL', service: 'Microsoft SQL Server Database' },
            { port: 1521, name: 'Oracle', service: 'Oracle Database Listener' },
            { port: 3000, name: 'Dev-Server', service: 'Vite / Node Development Server' },
            { port: 3306, name: 'MySQL', service: 'MySQL Database Server' },
            { port: 3389, name: 'RDP', service: 'Windows Remote Desktop Protocol' },
            { port: 5432, name: 'PostgreSQL', service: 'PostgreSQL Database Server' },
            { port: 5900, name: 'VNC', service: 'VNC Remote Desktop Protocol' },
            { port: 6379, name: 'Redis', service: 'Redis In-Memory Key-Value Store' },
            { port: 8080, name: 'HTTP-Proxy', service: 'HTTP Proxy / Web Application' },
            { port: 8443, name: 'HTTPS-Alt', service: 'Alternative Secure Web Server' }
          ];

          // Perform parallel TCP socket probes using Node.js native net.Socket
          const probePort = (targetHost, portObj) => {
            return new Promise((resolve) => {
              const start = Date.now();
              const socket = new net.Socket();

              socket.setTimeout(1200);

              socket.on('connect', () => {
                const rtt = Date.now() - start;
                socket.destroy();
                resolve({
                  port: portObj.port,
                  protocol: 'tcp',
                  state: 'open',
                  service: `${portObj.name} - ${portObj.service}`,
                  rtt: `${rtt}ms`,
                  vulns: portObj.port === 445 ? 'Exposed SMB Port (Audit MS17-010 EternalBlue)' :
                        portObj.port === 3389 ? 'Exposed RDP Port (Enforce NLA & MFA)' :
                        portObj.port === 23 ? 'Insecure Telnet Protocol (Unencrypted)' :
                        'Active TCP Service Listener'
                });
              });

              socket.on('timeout', () => {
                socket.destroy();
                resolve({
                  port: portObj.port,
                  protocol: 'tcp',
                  state: 'filtered',
                  service: portObj.name,
                  rtt: 'Timeout',
                  vulns: 'Connection timed out (Firewall Filtered)'
                });
              });

              socket.on('error', (err) => {
                socket.destroy();
                resolve({
                  port: portObj.port,
                  protocol: 'tcp',
                  state: 'closed',
                  service: portObj.name,
                  rtt: 'Refused',
                  vulns: 'Port closed (Connection refused)'
                });
              });

              socket.connect(portObj.port, targetHost);
            });
          };

          try {
            const probeResults = await Promise.all(portsToScan.map(p => probePort(target, p)));
            const openPorts = probeResults.filter(r => r.state === 'open');

            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({
              host: target,
              scanTime: new Date().toISOString(),
              scannedPortsCount: portsToScan.length,
              openPorts: openPorts,
              allResults: probeResults
            }));
          } catch (err) {
            res.statusCode = 500;
            res.end(JSON.stringify({ error: err.message }));
          }
        });
      }
    }
  ],
  server: {
    port: 3000,
    open: true
  }
})
