using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Linq;

class NetworkScanner
{
    static async Task Main()
    {
        string localIP = GetLocalIPAddress();
        if (localIP == null)
        {
            Console.WriteLine("❌ Failed to determine local IP.");
            return;
        }

        Console.WriteLine($"✅ Your IP: {localIP}");
        string subnet = localIP.Substring(0, localIP.LastIndexOf('.') + 1);
        Console.WriteLine($"🔎 Starting scan in subnet {subnet}0/24...");

        List<Task> tasks = new List<Task>();

        for (int i = 1; i <= 254; i++)
        {
            string testIP = subnet + i;
            tasks.Add(ScanHost(testIP));
        }

        await Task.WhenAll(tasks);
    }

    static string GetLocalIPAddress()
    {
        foreach (var netInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (netInterface.OperationalStatus == OperationalStatus.Up &&
                netInterface.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            {
                foreach (var addr in netInterface.GetIPProperties().UnicastAddresses)
                {
                    if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        string ip = addr.Address.ToString();
                        if (ip.StartsWith("192.168.") || ip.StartsWith("10.") || ip.StartsWith("172."))
                            return ip;
                    }
                }
            }
        }
        return null;
    }

    static async Task ScanHost(string ip)
    {
        if (PingHost(ip) || TryTcpPing(ip))
        {
            Console.WriteLine($"[+] {ip} - Online");
            await ScanPortsAsync(ip);
        }
    }

    static bool PingHost(string ip)
    {
        try
        {
            using (Ping ping = new Ping())
            {
                PingReply reply = ping.Send(ip, 100);
                return reply.Status == IPStatus.Success;
            }
        }
        catch
        {
            return false;
        }
    }

    static bool TryTcpPing(string ip)
    {
        return IsPortOpen(ip, 80, 50) || IsPortOpen(ip, 443, 50);
    }

    static async Task ScanPortsAsync(string ip)
    {
        var ports = new (int Port, string Service)[]
        {
            (21, "FTP"),
            (22, "SSH"),
            (23, "Telnet"),
            (25, "SMTP"),
            (53, "DNS"),
            (80, "HTTP"),
            (110, "POP3"),
            (139, "NetBIOS"),
            (443, "HTTPS"),
            (445, "SMB"),
            (3389, "RDP")
        };

        Console.WriteLine($"🔎 Scanning ports on {ip}...");

        List<Task> scanTasks = new List<Task>();

        foreach (var (port, service) in ports)
        {
            scanTasks.Add(Task.Run(async () =>
            {
                if (IsPortOpen(ip, port, 100))
                {
                    Console.WriteLine($"[!] {ip}:{port} - {service} (Open)");
                    await CheckVulnerabilities(service);
                }
            }));
        }

        await Task.WhenAll(scanTasks);
    }

    static bool IsPortOpen(string ip, int port, int timeout)
    {
        try
        {
            using (var client = new TcpClient())
            {
                var result = client.BeginConnect(ip, port, null, null);
                bool success = result.AsyncWaitHandle.WaitOne(timeout);
                return success && client.Connected;
            }
        }
        catch
        {
            return false;
        }
    }

    static Dictionary<string, List<string>> cveCache = new Dictionary<string, List<string>>();

    static async Task CheckVulnerabilities(string service)
    {
        if (cveCache.ContainsKey(service))
        {
            PrintVulnerabilities(service, cveCache[service]);
            return;
        }

        string apiUrl = $"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}&resultsPerPage=5";

        using (HttpClient client = new HttpClient())
        {
            try
            {
                HttpResponseMessage response = await client.GetAsync(apiUrl);
                response.EnsureSuccessStatusCode();
                string responseBody = await response.Content.ReadAsStringAsync();

                JObject json = JObject.Parse(responseBody);
                var vulnerabilities = json["vulnerabilities"];
                List<string> cveList = new List<string>();

                if (vulnerabilities != null && vulnerabilities.HasValues)
                {
                    var recentCVE = vulnerabilities
                        .Where(v => DateTime.TryParse(v["cve"]["published"].ToString(), out DateTime date) && date > DateTime.Now.AddYears(-5)) 
                        .Take(5) 
                        .Select(v => $"{v["cve"]["id"]}: {v["cve"]["descriptions"]?[0]?["value"]?.ToString()}")
                        .ToList();

                    cveList.AddRange(recentCVE);
                }

                cveCache[service] = cveList;
                PrintVulnerabilities(service, cveList);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠ Error retrieving CVE data for {service}: {ex.Message}");
            }
        }
    }

    static void PrintVulnerabilities(string service, List<string> cveList)
    {
        if (cveList.Count > 0)
        {
            Console.WriteLine($"⚠ Found vulnerabilities for {service}:");
            foreach (var cve in cveList)
                Console.WriteLine($"   - {cve}");
        }
        else
        {
            Console.WriteLine($"✅ No recent vulnerabilities found for {service}.");
        }
    }
}
