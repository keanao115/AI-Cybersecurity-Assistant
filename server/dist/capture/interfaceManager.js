import os from 'os';
export class InterfaceManager {
    static getInterfaces() {
        const interfaces = os.networkInterfaces();
        const result = [];
        let counter = 1;
        for (const [name, netInterface] of Object.entries(interfaces)) {
            if (!netInterface)
                continue;
            let ipv4 = '';
            let ipv6 = '';
            let mac = '';
            for (const info of netInterface) {
                if (info.family === 'IPv4' && !ipv4)
                    ipv4 = info.address;
                if (info.family === 'IPv6' && !ipv6)
                    ipv6 = info.address;
                if (info.mac && info.mac !== '00:00:00:00:00:00')
                    mac = info.mac;
            }
            const isLoopback = name.toLowerCase().includes('loopback') || ipv4 === '127.0.0.1';
            result.push({
                id: `iface-${counter++}`,
                name,
                description: `${os.platform() === 'win32' ? 'Npcap / Windows' : 'libpcap / Unix'} Adapter (${name})`,
                ipAddresses: { ipv4: ipv4 || undefined, ipv6: ipv6 || undefined },
                macAddress: mac || '00:15:5D:01:2A:8C',
                isLoopback,
                isUp: true,
                promiscuousSupported: !isLoopback,
                mtu: 1500,
                speedMbps: isLoopback ? 10000 : 1000,
            });
        }
        return result;
    }
    static getInterfaceById(id) {
        return this.getInterfaces().find((i) => i.id === id || i.name === id);
    }
}
