using System;
using System.Runtime.InteropServices;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace LanScanner
{
    public class HostRow
    {
        public string Ip = "";
        public bool Alive;
        public long Rtt;
        public int Ttl;
        public string Mac = "";
        public string ArpState = "";
        public string Path = "";
        public string Role = "";
        public string Vendor = "";
        public string HostName = "";
    }

    public class ArpInfo
    {
        public string Mac = "";
        public string State = "";
    }

    public class ScanOptions
    {
        public int Concurrency = 512;
        public int TimeoutMs = 300;
        public int RetryRounds = 0;
        public bool UseArp = true;
        public bool ResolveDns = false;
    }

    public static class IpUtil
    {
        public static uint ToUInt(string ip)
        {
            uint v;
            if (!TryToUInt(ip, out v)) throw new FormatException("IP 格式不对: " + ip);
            return v;
        }

        public static bool TryToUInt(string ip, out uint value)
        {
            value = 0;
            IPAddress a;
            if (!IPAddress.TryParse(ip, out a)) return false;
            byte[] b = a.GetAddressBytes();
            if (b.Length != 4) return false;
            value = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
            return true;
        }

        public static string FromUInt(uint v)
        {
            return string.Format("{0}.{1}.{2}.{3}", (v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255);
        }

        public static uint MaskFromPrefix(int prefix)
        {
            if (prefix <= 0) return 0;
            if (prefix >= 32) return 0xFFFFFFFFu;
            return 0xFFFFFFFFu << (32 - prefix);
        }

        public static int PrefixFromMask(uint mask)
        {
            int n = 0;
            for (int i = 31; i >= 0; i--)
            {
                if (((mask >> i) & 1u) == 1u) n++;
                else break;
            }
            return n;
        }
    }

    // 把“范围文本 + 并发数”翻译成界面上那句即时统计；校验失败时给出人话原因。
    public static class RangePlan
    {
        public static string Describe(string text, int concurrency, out bool isError, out string error)
        {
            isError = false;
            error = "";
            string t = (text == null ? "" : text).Trim();
            if (t.Length == 0)
            {
                isError = true;
                error = "请填写扫描范围";
                return "请选择要扫描的网段";
            }
            string[] pre = t.Replace('\uFF0C', ',').Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < pre.Length; i++)
            {
                string one = pre[i].Trim();
                int slash = one.LastIndexOf('/');
                if (slash <= 0) continue;
                int prefix;
                if (!int.TryParse(one.Substring(slash + 1), out prefix)) continue;
                if (prefix < 12)
                {
                    isError = true;
                    error = "范围太大（/" + prefix + "），请缩到 /12 以内";
                    return "范围太大（/" + prefix + "），请缩到 /12 以内";
                }
            }
            int conc = concurrency < 1 ? 512 : concurrency;
            string desc, err;
            List<uint> addrs = RangeParser.Parse(t, out desc, out err);
            if (err != null)
            {
                isError = true;
                error = err;
                return "格式有误：" + err;
            }
            long sec = (long)Math.Ceiling(addrs.Count / (conc * 1.8));
            if (sec < 1) sec = 1;
            string plan = string.Format("{0} 段 · {1} 个地址 · 预计约 {2} 秒", pre.Length, addrs.Count, sec);
            if (addrs.Count > 100000) plan += "（大范围）";
            return plan;
        }
    }

    public static class RangeParser
    {
        public static List<uint> Parse(string text, out string description, out string error)
        {
            error = null;
            description = "";
            var set = new HashSet<uint>();
            var labels = new List<string>();
            if (string.IsNullOrEmpty(text) || text.Trim().Length == 0)
            {
                error = "请填写扫描范围";
                return new List<uint>();
            }
            text = text.Replace('\uFF0C', ',').Replace('\uFF1B', ';').Replace('\u3001', ',');
            string[] tokens = text.Split(new char[] { ',', ';', ' ', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string raw in tokens)
            {
                string t = raw.Trim();
                if (t.Length == 0) continue;
                int slash = t.IndexOf('/');
                int dash = t.IndexOf('-');
                if (t.IndexOf('*') >= 0)
                {
                    string wildErr;
                    if (!ExpandWildcard(t, set, out wildErr, labels))
                    {
                        error = wildErr;
                        return new List<uint>();
                    }
                }
                else if (slash > 0)
                {
                    string ipPart = t.Substring(0, slash);
                    int prefix;
                    if (!int.TryParse(t.Substring(slash + 1), out prefix) || prefix < 0 || prefix > 32)
                    {
                        error = "前缀长度不对: " + t;
                        return new List<uint>();
                    }
                    if (prefix < 12)
                    {
                        error = "范围太大（/" + prefix + "），请缩到 /12 以内";
                        return new List<uint>();
                    }
                    uint ip;
                    if (!IpUtil.TryToUInt(ipPart, out ip))
                    {
                        error = "IP 格式不对: " + t;
                        return new List<uint>();
                    }
                    uint net = ip & IpUtil.MaskFromPrefix(prefix);
                    ulong size = 1UL << (32 - prefix);
                    uint first, last;
                    if (prefix >= 31) { first = net; last = (uint)((ulong)net + size - 1UL); }
                    else { first = net + 1u; last = (uint)((ulong)net + size - 2UL); }
                    for (ulong v = first; v <= last; v++) set.Add((uint)v);
                    labels.Add(string.Format("{0}/{1}（{2} 个地址）", IpUtil.FromUInt(net), prefix, last - first + 1));
                }
                else if (dash > 0)
                {
                    uint first, last;
                    string leftPart = t.Substring(0, dash);
                    string rightPart = t.Substring(dash + 1);
                    if (rightPart.IndexOf('.') < 0 && leftPart.LastIndexOf('.') > 0)
                    {
                        // 末段简写：192.168.1.1-254
                        int dot = leftPart.LastIndexOf('.');
                        string baseIp = leftPart.Substring(0, dot);
                        int lo, hi;
                        uint baseAddr;
                        if (!int.TryParse(leftPart.Substring(dot + 1), out lo) || !int.TryParse(rightPart, out hi)
                            || lo < 0 || lo > 255 || hi < 0 || hi > 255
                            || !IpUtil.TryToUInt(baseIp + ".0", out baseAddr))
                        {
                            error = "范围写法不对: " + t;
                            return new List<uint>();
                        }
                        first = baseAddr + (uint)lo;
                        last = baseAddr + (uint)hi;
                    }
                    else if (!IpUtil.TryToUInt(leftPart, out first) || !IpUtil.TryToUInt(rightPart, out last))
                    {
                        error = "范围写法不对: " + t;
                        return new List<uint>();
                    }
                    if (last < first) { uint tmp = first; first = last; last = tmp; }
                    for (ulong v = first; v <= last; v++) set.Add((uint)v);
                    labels.Add(string.Format("{0} ~ {1}", IpUtil.FromUInt(first), IpUtil.FromUInt(last)));
                }
                else
                {
                    uint one;
                    if (!IpUtil.TryToUInt(t, out one))
                    {
                        error = "IP 格式不对: " + t;
                        return new List<uint>();
                    }
                    set.Add(one);
                    labels.Add(IpUtil.FromUInt(one));
                }
                if (set.Count > 1048576)
                {
                    error = "范围超过 1048576 个地址，请缩小";
                    return new List<uint>();
                }
            }
            var list = set.ToList();
            list.Sort();
            description = string.Join("、", labels.ToArray());
            return list;
        }

        // 通配写法：192.168.1.* / 192.168.*.* / 192.168.1-3.*
        static bool ExpandWildcard(string t, HashSet<uint> set, out string error, List<string> labels)
        {
            error = null;
            string[] segs = t.Split('.');
            if (segs.Length != 4)
            {
                error = "通配写法不对: " + t;
                return false;
            }
            int[] lo = new int[4];
            int[] hi = new int[4];
            long total = 1;
            for (int i = 0; i < 4; i++)
            {
                string s = segs[i].Trim();
                if (s.Length == 0)
                {
                    error = "通配写法不对: " + t;
                    return false;
                }
                if (s == "*")
                {
                    // 末段的 * 按 1~254 展开：网络地址和广播地址本来就不会被扫，这样"地址数"才和实际扫的个数一致
                    if (i == 3) { lo[i] = 1; hi[i] = 254; }
                    else { lo[i] = 0; hi[i] = 255; }
                }
                else
                {
                    int dash = s.IndexOf('-');
                    if (dash > 0)
                    {
                        if (!int.TryParse(s.Substring(0, dash), out lo[i]) || !int.TryParse(s.Substring(dash + 1), out hi[i]))
                        {
                            error = "通配写法不对: " + t;
                            return false;
                        }
                        if (lo[i] > hi[i]) { int tmp = lo[i]; lo[i] = hi[i]; hi[i] = tmp; }
                    }
                    else
                    {
                        if (!int.TryParse(s, out lo[i]))
                        {
                            error = "通配写法不对: " + t;
                            return false;
                        }
                        hi[i] = lo[i];
                    }
                }
                if (lo[i] < 0 || lo[i] > 255 || hi[i] < 0 || hi[i] > 255)
                {
                    error = "通配写法不对: " + t;
                    return false;
                }
                total *= (long)(hi[i] - lo[i] + 1);
            }
            if (total > 1048576)
            {
                error = "范围超过 1048576 个地址，请缩小";
                return false;
            }
            for (int a = lo[0]; a <= hi[0]; a++)
            {
                for (int b = lo[1]; b <= hi[1]; b++)
                {
                    for (int c = lo[2]; c <= hi[2]; c++)
                    {
                        for (int d = lo[3]; d <= hi[3]; d++)
                        {
                            set.Add(((uint)a << 24) | ((uint)b << 16) | ((uint)c << 8) | (uint)d);
                        }
                    }
                }
            }
            labels.Add(string.Format("{0}（{1} 个地址）", t, total));
            return true;
        }
    }

    public class Subnet
    {
        public uint Net;
        public uint Mask;
        public int Prefix;
        public string Alias = "";
        public string LocalIp = "";
        public uint Size;
    }

    public class NetInfo
    {
        public List<Subnet> Subnets = new List<Subnet>();
        public HashSet<string> LocalIps = new HashSet<string>();
        public List<string> Gateways = new List<string>();

        public void Load()
        {
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                IPInterfaceProperties props;
                try { props = ni.GetIPProperties(); } catch { continue; }
                foreach (UnicastIPAddressInformation ua in props.UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                    if (ua.IPv4Mask == null) continue;
                    string ipText = ua.Address.ToString();
                    uint ip, mask;
                    if (!IpUtil.TryToUInt(ipText, out ip) || !IpUtil.TryToUInt(ua.IPv4Mask.ToString(), out mask)) continue;
                    var s = new Subnet();
                    s.Mask = mask;
                    s.Net = ip & mask;
                    s.Prefix = IpUtil.PrefixFromMask(mask);
                    s.Alias = ni.Name;
                    s.LocalIp = ipText;
                    s.Size = (uint)(1UL << (32 - s.Prefix));
                    Subnets.Add(s);
                    LocalIps.Add(ipText);
                }
                foreach (GatewayIPAddressInformation gw in props.GatewayAddresses)
                {
                    if (gw.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                    if (!Gateways.Contains(gw.Address.ToString())) Gateways.Add(gw.Address.ToString());
                }
            }
        }

        public bool IsDirect(uint addr)
        {
            foreach (Subnet s in Subnets)
            {
                if ((addr & s.Mask) == s.Net) return true;
            }
            return false;
        }

        public string PathFor(uint addr)
        {
            foreach (Subnet s in Subnets)
            {
                if ((addr & s.Mask) == s.Net) return "直达";
            }
            return "跨网段";
        }

        public string RoleFor(uint addr)
        {
            string ip = IpUtil.FromUInt(addr);
            if (LocalIps.Contains(ip)) return "本机";
            if (Gateways.Contains(ip)) return "网关";
            return "设备";
        }

        public bool IsEdge(uint addr)
        {
            foreach (Subnet s in Subnets)
            {
                if (addr == s.Net) return true;
                if (addr == (uint)((ulong)s.Net + s.Size - 1UL)) return true;
            }
            return false;
        }

        public string Summary()
        {
            var parts = new List<string>();
            foreach (Subnet s in Subnets)
            {
                parts.Add(string.Format("{0}/{1}  本机 {2}  [{3}]", IpUtil.FromUInt(s.Net), s.Prefix, s.LocalIp, s.Alias));
            }
            return string.Join(Environment.NewLine, parts.ToArray());
        }

        public string CidrList()
        {
            var parts = new List<string>();
            foreach (Subnet s in Subnets)
            {
                string cidr = string.Format("{0}/{1}", IpUtil.FromUInt(s.Net), s.Prefix);
                if (!parts.Contains(cidr)) parts.Add(cidr);
            }
            return string.Join(",", parts.ToArray());
        }
    }

    public static class NativeArp
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_IPNETROW
        {
            public int dwIndex;
            public int dwPhysAddrLen;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] bPhysAddr;
            public int dwAddr;
            public int dwType;
        }

        // 诊断用：把原始 dwAddr 按两种字节序解释都打印出来，用于确认取值方式
        public static List<string> DumpRaw(int max)
        {
            var lines = new List<string>();
            int size = 0;
            try
            {
                GetIpNetTable(IntPtr.Zero, ref size, false);
                if (size <= 0) { lines.Add("size<=0"); return lines; }
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    int rc = GetIpNetTable(buf, ref size, false);
                    lines.Add("rc=" + rc + " size=" + size);
                    int count = Marshal.ReadInt32(buf);
                    lines.Add("rows=" + count + " rowSize=" + Marshal.SizeOf(typeof(MIB_IPNETROW)));
                    for (int i = 0; i < count && i < max; i++)
                    {
                        IntPtr p = new IntPtr(buf.ToInt64() + 4 + i * Marshal.SizeOf(typeof(MIB_IPNETROW)));
                        MIB_IPNETROW row = (MIB_IPNETROW)Marshal.PtrToStructure(p, typeof(MIB_IPNETROW));
                        string mac = "";
                        if (row.bPhysAddr != null)
                        {
                            StringBuilder mb = new StringBuilder();
                            for (int k = 0; k < row.dwPhysAddrLen && k < 8; k++)
                            {
                                if (k > 0) mb.Append(':');
                                mb.Append(row.bPhysAddr[k].ToString("x2"));
                            }
                            mac = mb.ToString();
                        }
                        uint raw = unchecked((uint)row.dwAddr);
                        uint le = raw;
                        uint be = ((raw & 0xFFu) << 24) | ((raw & 0xFF00u) << 8) | ((raw >> 8) & 0xFF00u) | ((raw >> 24) & 0xFFu);
                        lines.Add(string.Format("type={0} len={1} mac={2} raw=0x{3:X8} asIs={4} swapped={5}",
                            row.dwType, row.dwPhysAddrLen, mac, raw, IpUtil.FromUInt(le), IpUtil.FromUInt(be)));
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
            catch (Exception ex)
            {
                lines.Add("EX " + ex.Message);
            }
            return lines;
        }

        // GetIpNetTable 里的 dwAddr 是网络字节序，读成 int 后必须换字节序
        static uint SwapBytes(uint v)
        {
            return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) | ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
        }

        public static Dictionary<string, ArpInfo> Snapshot()
        {
            var result = new Dictionary<string, ArpInfo>();
            int size = 0;
            try
            {
                GetIpNetTable(IntPtr.Zero, ref size, false);
                if (size <= 0) return result;
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    int rc = GetIpNetTable(buf, ref size, false);
                    if (rc != 0 && rc != 122) return result;
                    int count = Marshal.ReadInt32(buf);
                    int rowSize = Marshal.SizeOf(typeof(MIB_IPNETROW));
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr p = new IntPtr(buf.ToInt64() + 4 + i * rowSize);
                        MIB_IPNETROW row = (MIB_IPNETROW)Marshal.PtrToStructure(p, typeof(MIB_IPNETROW));
                        if (row.dwType == 2) continue;
                        if (row.dwPhysAddrLen < 1 || row.dwPhysAddrLen > 8) continue;
                        if (row.bPhysAddr == null) continue;
                        var sb = new System.Text.StringBuilder();
                        for (int k = 0; k < row.dwPhysAddrLen; k++)
                        {
                            if (k > 0) sb.Append(':');
                            sb.Append(row.bPhysAddr[k].ToString("x2"));
                        }
                        string mac = sb.ToString();
                        if (mac == "ff:ff:ff:ff:ff:ff") continue;
                        int firstOctet = Convert.ToInt32(mac.Substring(0, 2), 16);
                        if ((firstOctet & 1) != 0) continue;
                        if (mac == "00:00:00:00:00:00") continue;
                        uint addr = SwapBytes(unchecked((uint)row.dwAddr));
                        var info = new ArpInfo();
                        info.Mac = mac;
                        info.State = row.dwType == 4 ? "Static" : "Dynamic";
                        result[IpUtil.FromUInt(addr)] = info;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
            catch { }
            return result;
        }
    }

    public class Engine
    {
        public ConcurrentDictionary<uint, HostRow> Hits = new ConcurrentDictionary<uint, HostRow>();
        public ConcurrentDictionary<string, ArpInfo> Arp = new ConcurrentDictionary<string, ArpInfo>();
        public long Done;
        public long Total;
        int arpBusy;

        readonly NetInfo net;

        public Engine(NetInfo info)
        {
            net = info;
        }

        void SnapshotArp()
        {
            if (Interlocked.CompareExchange(ref arpBusy, 1, 0) != 0) return;
            try
            {
                Dictionary<string, ArpInfo> snap = NativeArp.Snapshot();
                foreach (KeyValuePair<string, ArpInfo> kv in snap)
                {
                    Arp[kv.Key] = kv.Value;
                }
            }
            finally
            {
                Interlocked.Exchange(ref arpBusy, 0);
            }
        }

        async Task ScanOne(uint addr, ScanOptions o, Action<HostRow> onFound)
        {
            string ip = IpUtil.FromUInt(addr);
            try
            {
                PingReply reply;
                using (Ping ping = new Ping())
                {
                    reply = await ping.SendPingAsync(ip, o.TimeoutMs).ConfigureAwait(false);
                }
                if (reply != null && reply.Status == IPStatus.Success)
                {
                    var row = new HostRow();
                    row.Ip = ip;
                    row.Alive = true;
                    row.Rtt = reply.RoundtripTime;
                    row.Ttl = reply.Options != null ? reply.Options.Ttl : 0;
                    row.Path = net.PathFor(addr);
                    row.Role = net.RoleFor(addr);
                    Hits[addr] = row;
                    if (onFound != null) onFound(row);
                }
            }
            catch { }
        }

        public async Task<List<HostRow>> RunFull(List<uint> addresses, ScanOptions o, Action<string> log, Action<HostRow> onFound, CancellationToken token)
        {
            Total = addresses.Count;
            Done = 0;
            Hits.Clear();
            Arp.Clear();
            if (o.UseArp) SnapshotArp();
            if (log != null) log(string.Format("开始扫描 {0} 个地址（并发 {1}，超时 {2}ms）", addresses.Count, o.Concurrency, o.TimeoutMs));

            int workers = Math.Max(1, Math.Min(o.Concurrency, addresses.Count));
            int cursor = -1;
            var tasks = new List<Task>();
            for (int w = 0; w < workers; w++)
            {
                tasks.Add(Task.Run(async () =>
                {
                    while (true)
                    {
                        if (token.IsCancellationRequested) break;
                        int i = Interlocked.Increment(ref cursor);
                        if (i >= addresses.Count) break;
                        await ScanOne(addresses[i], o, onFound);
                        long d = Interlocked.Increment(ref Done);
                        if (o.UseArp && (d & 1023L) == 0L) SnapshotArp();
                    }
                }));
            }
            await Task.WhenAll(tasks.ToArray()).ConfigureAwait(false);

            // ---- 补扫
            if (!token.IsCancellationRequested && o.RetryRounds > 0)
            {
                for (int round = 1; round <= o.RetryRounds; round++)
                {
                    var missed = new List<uint>();
                    foreach (uint a in addresses) if (!Hits.ContainsKey(a)) missed.Add(a);
                    if (missed.Count == 0) break;
                    if (log != null) log(string.Format("第 {0} 轮补扫：{1} 个无响应地址", round, missed.Count));
                    int cw = Math.Max(1, Math.Min(o.Concurrency, missed.Count));
                    int cur = -1;
                    var ts = new List<Task>();
                    for (int w = 0; w < cw; w++)
                    {
                        ts.Add(Task.Run(async () =>
                        {
                            while (true)
                            {
                                if (token.IsCancellationRequested) break;
                                int i = Interlocked.Increment(ref cur);
                                if (i >= missed.Count) break;
                                await ScanOne(missed[i], o, onFound);
                            }
                        }));
                    }
                    await Task.WhenAll(ts.ToArray()).ConfigureAwait(false);
                    if (token.IsCancellationRequested) break;
                }
            }

            // ---- ARP 合并（只认二层直达）
            if (o.UseArp && !token.IsCancellationRequested)
            {
                SnapshotArp();
                var scanned = new HashSet<uint>(addresses);
                var candidates = new List<string>();
                foreach (KeyValuePair<string, ArpInfo> kv in Arp)
                {
                    uint a;
                    if (!IpUtil.TryToUInt(kv.Key, out a)) continue;
                    if (!scanned.Contains(a)) continue;
                    if (Hits.ContainsKey(a)) continue;
                    if (net.IsEdge(a)) continue;
                    if (!net.IsDirect(a)) continue;
                    candidates.Add(kv.Key);
                }
                if (candidates.Count > 0)
                {
                    if (log != null) log(string.Format("ARP 里还有 {0} 个不响应 ICMP 的地址，正在复核…", candidates.Count));
                    foreach (string ip in candidates)
                    {
                        try
                        {
                            Ping p = new Ping();
                            p.SendPingAsync(ip, 120);
                        }
                        catch { }
                    }
                    await Task.Delay(350).ConfigureAwait(false);
                    SnapshotArp();
                    foreach (string ip in candidates)
                    {
                        ArpInfo info;
                        if (!Arp.TryGetValue(ip, out info)) continue;
                        uint a;
                        IpUtil.TryToUInt(ip, out a);
                        var row = new HostRow();
                        row.Ip = ip;
                        row.Alive = false;
                        Hits[a] = row;
                    }
                }
            }

            // ---- 组装结果
            var rows = new List<HostRow>();
            foreach (KeyValuePair<uint, HostRow> kv in Hits)
            {
                HostRow r = kv.Value;
                r.Path = net.PathFor(kv.Key);
                r.Role = net.RoleFor(kv.Key);
                ArpInfo info;
                if (o.UseArp && Arp.TryGetValue(r.Ip, out info))
                {
                    r.Mac = info.Mac;
                    r.ArpState = info.State;
                }
                r.Vendor = Oui.Lookup(r.Mac);
                rows.Add(r);
            }
            rows.Sort(delegate(HostRow x, HostRow y)
            {
                return IpUtil.ToUInt(x.Ip).CompareTo(IpUtil.ToUInt(y.Ip));
            });

            // ---- 反查主机名
            if (o.ResolveDns && rows.Count > 0 && !token.IsCancellationRequested && log != null)
            {
                log(string.Format("反向解析 {0} 个主机名…", rows.Count));
                var sem = new SemaphoreSlim(32);
                var dnsTasks = new List<Task>();
                foreach (HostRow r in rows)
                {
                    HostRow captured = r;
                    dnsTasks.Add(Task.Run(async () =>
                    {
                        await sem.WaitAsync().ConfigureAwait(false);
                        try
                        {
                            Task<IPHostEntry> t = Dns.GetHostEntryAsync(captured.Ip);
                            Task done = await Task.WhenAny(t, Task.Delay(1500)).ConfigureAwait(false);
                            if (done == t)
                            {
                                IPHostEntry entry = await t.ConfigureAwait(false);
                                if (entry != null && entry.HostName != null) captured.HostName = entry.HostName;
                            }
                        }
                        catch { }
                        finally
                        {
                            sem.Release();
                        }
                    }));
                }
                await Task.WhenAll(dnsTasks.ToArray()).ConfigureAwait(false);
            }
            return rows;
        }
    }

    /// <summary>直连未知 IP 探测：临时给网卡加一个同段地址 → 对整段做 ARP 扫描 → 结束后恢复。</summary>
    public static class DirectProbe
    {
        public class Hit
        {
            public string Ip = "";
            public string Mac = "";
            public string Vendor = "";
            public string Segment = "";
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref int phyAddrLen);

        public static bool IsAdministrator()
        {
            try
            {
                System.Security.Principal.WindowsIdentity id = System.Security.Principal.WindowsIdentity.GetCurrent();
                System.Security.Principal.WindowsPrincipal p = new System.Security.Principal.WindowsPrincipal(id);
                return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        public static string[] DefaultCandidates()
        {
            return new string[] {
                "192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.4.0/24",
                "192.168.10.0/24", "192.168.16.0/24", "192.168.31.0/24", "192.168.50.0/24",
                "192.168.100.0/24", "192.168.120.0/24", "192.168.137.0/24", "192.168.254.0/24"
            };
        }

        /// <summary>挑一块已连接的非无线网卡；没有就返回 null。</summary>
        public static string DefaultAdapter()
        {
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211) continue;
                    return ni.Name;
                }
            }
            catch { }
            return null;
        }

        static string Netsh(string args)
        {
            try
            {
                System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo("netsh", args);
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;
                using (System.Diagnostics.Process p = System.Diagnostics.Process.Start(psi))
                {
                    string text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(8000))
                    {
                        try { p.Kill(); } catch { }
                    }
                    return text;
                }
            }
            catch (Exception ex) { return ex.Message; }
        }

        static NetworkInterface FindAdapter(string adapter)
        {
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (string.Equals(ni.Name, adapter, StringComparison.OrdinalIgnoreCase)) return ni;
                }
            }
            catch { }
            return null;
        }

        static bool HasAddress(string adapter, string ip)
        {
            try
            {
                NetworkInterface ni = FindAdapter(adapter);
                if (ni == null) return false;
                foreach (UnicastIPAddressInformation u in ni.GetIPProperties().UnicastAddresses)
                {
                    if (u.Address.ToString() == ip) return true;
                }
            }
            catch { }
            return false;
        }

        static HashSet<string> LocalAddresses()
        {
            HashSet<string> set = new HashSet<string>();
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    foreach (UnicastIPAddressInformation u in ni.GetIPProperties().UnicastAddresses)
                    {
                        set.Add(u.Address.ToString());
                    }
                }
            }
            catch { }
            return set;
        }

        /// <summary>对一个 /24 做 ARP 扫描：复用 Engine 的 ICMP+ARP 合并（回 ping 或回 ARP 都算）。</summary>
        static void Sweep24(string cidr, HashSet<string> local, List<Hit> hits, HashSet<string> seen, CancellationToken token, out int routedOnly)
        {
            routedOnly = 0;
            string baseIp = cidr.Substring(0, cidr.IndexOf('/'));
            byte[] b = IPAddress.Parse(baseIp).GetAddressBytes();
            List<uint> addrs = new List<uint>();
            for (int i = 1; i <= 254; i++)
            {
                b[3] = (byte)i;
                string ip = new IPAddress(b).ToString();
                if (local.Contains(ip)) continue;
                addrs.Add(IpUtil.ToUInt(ip));
            }
            NetInfo info = new NetInfo();
            info.Load();
            Engine eng = new Engine(info);
            ScanOptions o = new ScanOptions();
            o.Concurrency = 512;
            o.TimeoutMs = 200;
            o.UseArp = true;
            o.ResolveDns = false;
            List<HostRow> rows = eng.RunFull(addrs, o, null, null, token).GetAwaiter().GetResult();
            for (int i = 0; i < rows.Count; i++)
            {
                HostRow r = rows[i];
                if (r.Mac == null) r.Mac = "";
                // 只认二层证据：拿到 MAC 才是“这条线上”的设备；只有 ping 通的多半是经路由绕过去的
                if (r.Mac.Length == 0) { if (r.Alive) routedOnly++; continue; }
                lock (hits)
                {
                    if (!seen.Add(r.Ip)) continue;
                    Hit h = new Hit();
                    h.Ip = r.Ip;
                    h.Mac = r.Mac;
                    h.Vendor = Oui.Lookup(r.Mac);
                    h.Segment = cidr;
                    hits.Add(h);
                }
            }
        }


        /// <summary>本机是否已有地址落在该 /24 里。</summary>
        static bool SameSegment(HashSet<string> local, string cidr)
        {
            int slash = cidr.IndexOf('/');
            if (slash <= 0) return false;
            string baseIp = cidr.Substring(0, slash);
            int dot = baseIp.LastIndexOf('.');
            if (dot <= 0) return false;
            string prefix = baseIp.Substring(0, dot + 1);
            foreach (string ip in local)
            {
                if (ip.StartsWith(prefix, StringComparison.Ordinal) && ip.IndexOf(':') < 0) return true;
            }
            return false;
        }

        /// <summary>读 netsh 的 DHCP 开关（中英文输出都能认）。</summary>
        static bool GetDhcpEnabled(string adapter)
        {
            string text = Netsh("interface ipv4 show config name=\"" + adapter + "\"");
            if (text == null) return false;
            string[] lines = text.Replace("\r", "").Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                string s = lines[i];
                if (s.IndexOf("DHCP", StringComparison.OrdinalIgnoreCase) < 0) continue;
                if (s.IndexOf("enabled", StringComparison.OrdinalIgnoreCase) < 0 && s.IndexOf("启用", StringComparison.Ordinal) < 0) continue;
                if (s.IndexOf("否", StringComparison.Ordinal) >= 0) return false;
                if (s.IndexOf("是", StringComparison.Ordinal) >= 0) return true;
                if (s.IndexOf("No", StringComparison.OrdinalIgnoreCase) >= 0) return false;
                return true;
            }
            return false;
        }

        static string FirstLine(string s)
        {
            if (s == null || s.Length == 0) return "无输出";
            string[] lines = s.Replace("\r", "").Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].Trim().Length > 0) return lines[i].Trim();
            }
            return "无输出";
        }

        /// <summary>依次给每个候选 /24 加临时地址并 ARP 扫描；finally 里一定删掉临时地址。</summary>
        /// <summary>支持 192.168.*.0/24、192.168.0-255.0/24 这类通配，展开成逐个 /24。</summary>
        public static List<string> Expand(List<string> cidrs)
        {
            List<string> outList = new List<string>();
            for (int i = 0; i < cidrs.Count; i++)
            {
                string c = cidrs[i] == null ? "" : cidrs[i].Trim();
                if (c.Length == 0) continue;
                int slash = c.IndexOf('/');
                string head = slash > 0 ? c.Substring(0, slash) : c;
                string[] parts = head.Split('.');
                // 第三段通配：192.168.*.0/24 → 256 个 /24
                if (parts.Length == 4 && (parts[2] == "*" || parts[2] == "0-255") && parts[1] != "*" && parts[1] != "0-255")
                {
                    for (int n = 0; n < 256; n++)
                    {
                        outList.Add(parts[0] + "." + parts[1] + "." + n + ".0/24");
                    }
                    continue;
                }
                // 第二段通配：10.*.0/24 → 256 个 /24
                if (parts.Length == 4 && (parts[1] == "*" || parts[1] == "0-255"))
                {
                    for (int n = 0; n < 256; n++)
                    {
                        outList.Add(parts[0] + "." + n + "." + parts[2] + ".0/24");
                    }
                    continue;
                }
                if (slash < 0) { outList.Add(head + ".0/24"); continue; }
                outList.Add(c);
            }
            return outList;
        }

        /// <summary>把任意前缀的段拆成 /24 列表：Run 每段只扫一个 C 段，/16 必须拆成 256 段。</summary>
        static List<string> SplitTo24(List<string> cidrs, Action<string> log)
        {
            List<string> outList = new List<string>();
            HashSet<uint> seenNets = new HashSet<uint>();
            for (int i = 0; i < cidrs.Count; i++)
            {
                string c = cidrs[i] == null ? "" : cidrs[i].Trim();
                if (c.Length == 0) continue;
                int slash = c.IndexOf('/');
                if (slash <= 0) { outList.Add(c); continue; }
                int prefix;
                string ipText = c.Substring(0, slash);
                if (!int.TryParse(c.Substring(slash + 1), out prefix) || prefix < 0 || prefix > 32)
                {
                    if (log != null) log("跳过 " + c + "：前缀不对");
                    continue;
                }
                IPAddress ip;
                if (!IPAddress.TryParse(ipText, out ip) || ip.AddressFamily != AddressFamily.InterNetwork)
                {
                    if (log != null) log("跳过 " + c + "：地址格式不对");
                    continue;
                }
                if (prefix > 24)
                {
                    if (log != null) log("跳过 " + c + "：只支持 /24 或更大范围");
                    continue;
                }
                uint baseVal = IpUtil.ToUInt(ipText);
                uint mask = prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix));
                uint net = baseVal & mask;
                int count = 1 << (24 - prefix);
                if (outList.Count + count > 8192)
                {
                    if (log != null) log("跳过 " + c + "：段数太多（上限 8192 个 /24）");
                    continue;
                }
                for (int k = 0; k < count; k++)
                {
                    uint n = net + (uint)(k << 8);
                    if (!seenNets.Add(n)) continue;
                    outList.Add(((n >> 24) & 255) + "." + ((n >> 16) & 255) + "." + ((n >> 8) & 255) + ".0/24");
                }
            }
            return outList;
        }

        /// <summary>探测前的网卡配置快照，仅用于还原。</summary>
        class IfSnapshot
        {
            public List<string> Addresses = new List<string>();   // "ip/prefix"
            public List<string> Gateways = new List<string>();
            public bool HasAddress { get { return Addresses.Count > 0; } }
        }

        static IfSnapshot SnapshotIf(string adapter)
        {
            IfSnapshot s = new IfSnapshot();
            try
            {
                NetworkInterface[] all = NetworkInterface.GetAllNetworkInterfaces();
                for (int i = 0; i < all.Length; i++)
                {
                    if (!string.Equals(all[i].Name, adapter, StringComparison.OrdinalIgnoreCase)) continue;
                    IPInterfaceProperties props = all[i].GetIPProperties();
                    foreach (UnicastIPAddressInformation u in props.UnicastAddresses)
                    {
                        if (u.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                        s.Addresses.Add(u.Address + "/" + u.PrefixLength);
                    }
                    foreach (GatewayIPAddressInformation g in props.GatewayAddresses)
                    {
                        if (g.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                        s.Gateways.Add(g.Address.ToString());
                    }
                    break;
                }
            }
            catch { }
            return s;
        }

        static string MaskFromPrefix(int prefix)
        {
            uint m = prefix <= 0 ? 0u : (prefix >= 32 ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - prefix)));
            return ((m >> 24) & 255) + "." + ((m >> 16) & 255) + "." + ((m >> 8) & 255) + "." + (m & 255);
        }

        /// <summary>等一个可用的（非 169.254）IPv4 地址，超时返回 null。</summary>
        static string WaitUsableAddress(string adapter, int timeoutMs)
        {
            int waited = 0;
            while (waited < timeoutMs)
            {
                try
                {
                    NetworkInterface[] all = NetworkInterface.GetAllNetworkInterfaces();
                    for (int i = 0; i < all.Length; i++)
                    {
                        if (!string.Equals(all[i].Name, adapter, StringComparison.OrdinalIgnoreCase)) continue;
                        foreach (UnicastIPAddressInformation u in all[i].GetIPProperties().UnicastAddresses)
                        {
                            if (u.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                            string ip = u.Address.ToString();
                            if (!ip.StartsWith("169.254.", StringComparison.Ordinal)) return ip;
                        }
                    }
                }
                catch { }
                Thread.Sleep(500);
                waited += 500;
            }
            return null;
        }

        /// <summary>按快照把地址/网关加回去（探测前是什么样，就还原成什么样）。</summary>
        static void RestoreIf(string adapter, IfSnapshot snapshot, Action<string> log)
        {
            bool first = true;
            for (int i = 0; i < snapshot.Addresses.Count; i++)
            {
                string a = snapshot.Addresses[i];
                int slash = a.IndexOf('/');
                if (slash <= 0) continue;
                string ip = a.Substring(0, slash);
                int prefix;
                if (!int.TryParse(a.Substring(slash + 1), out prefix)) continue;
                string mask = MaskFromPrefix(prefix);
                if (first)
                {
                    string gw = snapshot.Gateways.Count > 0 ? snapshot.Gateways[0] : null;
                    string args = "interface ipv4 set address name=\"" + adapter + "\" static " + ip + " " + mask;
                    if (gw != null) args += " " + gw;
                    Netsh(args);
                    first = false;
                }
                else
                {
                    Netsh("interface ipv4 add address name=\"" + adapter + "\" address=" + ip + " mask=" + mask);
                }
            }
            if (log != null) log("已按探测前的配置还原网卡（" + string.Join(", ", snapshot.Addresses.ToArray()) + "）");
        }

        /// <summary>把扫描范围文本展开成去重、排序的 /24 列表（直连探测用）。</summary>
        public static List<string> SegmentsFromRange(string rangeText)
        {
            List<string> segs = new List<string>();
            if (rangeText == null || rangeText.Trim().Length == 0) return segs;
            string desc;
            string err;
            List<uint> addrs = RangeParser.Parse(rangeText, out desc, out err);
            if (addrs == null || addrs.Count == 0)
            {
                // 通配写法（192.168.*.0/24）RangeParser 不认，交给 Expand + SplitTo24
                List<string> parts = new List<string>();
                string[] raw = rangeText.Replace('，', ',').Split(',');
                for (int i = 0; i < raw.Length; i++) if (raw[i].Trim().Length > 0) parts.Add(raw[i].Trim());
                return SplitTo24(Expand(parts), null);
            }
            HashSet<uint> nets = new HashSet<uint>();
            for (int i = 0; i < addrs.Count; i++) nets.Add(addrs[i] & 0xFFFFFF00u);
            List<uint> list = new List<uint>(nets);
            list.Sort();
            for (int i = 0; i < list.Count; i++)
            {
                uint n = list[i];
                segs.Add(((n >> 24) & 255) + "." + ((n >> 16) & 255) + "." + ((n >> 8) & 255) + ".0/24");
            }
            return segs;
        }

        public static List<Hit> Run(string adapter, List<string> cidrs, int concurrency, Action<string> log, CancellationToken token)
        {
            cidrs = Expand(cidrs);
            cidrs = SplitTo24(cidrs, log);   // /16 → 256 个 /24，否则每段只扫一个 C 段
            List<Hit> hits = new List<Hit>();
            HashSet<string> seen = new HashSet<string>();
            HashSet<string> local = LocalAddresses();
            List<string> added = new List<string>();
            bool wasDhcp = GetDhcpEnabled(adapter);
            IfSnapshot snapshot = SnapshotIf(adapter);
            bool touched = false;   // 是否真的改过网卡：added 会在每段结束时清空，不能拿它当依据
            try
            {
                for (int i = 0; i < cidrs.Count; i++)
                {
                    if (token.IsCancellationRequested) break;
                    string cidr = cidrs[i] == null ? "" : cidrs[i].Trim();
                    if (cidr.Length == 0) continue;
                    int slash = cidr.IndexOf('/');
                    if (slash <= 0) { if (log != null) log("跳过 " + cidr + "：只支持 x.x.x.0/24 形式"); continue; }
                    string baseIp = cidr.Substring(0, slash);
                    int dot = baseIp.LastIndexOf('.');
                    if (dot <= 0) { if (log != null) log("跳过 " + cidr + "：地址格式不对"); continue; }
                    string tempIp = baseIp.Substring(0, dot + 1) + "250";
                    bool owned = false;
                    bool alreadyInSegment = SameSegment(local, cidr);
                    if (alreadyInSegment)
                    {
                        if (log != null) log("扫描 " + cidr + "（本机已在该段，无需临时地址）");
                    }
                    else if (!local.Contains(tempIp) && !HasAddress(adapter, tempIp))
                    {
                        string addText = Netsh("interface ipv4 add address name=\"" + adapter + "\" address=" + tempIp + " mask=255.255.255.0");
                        bool ok = false;
                        for (int w = 0; w < 25; w++)
                        {
                            if (HasAddress(adapter, tempIp)) { ok = true; break; }
                            Thread.Sleep(100);
                        }
                        if (!ok)
                        {
                            if (log != null) log("跳过 " + cidr + "：临时地址 " + tempIp + " 加不上（" + FirstLine(addText) + "）");
                            continue;
                        }
                        added.Add(tempIp);
                        local.Add(tempIp);
                        owned = true;
                        touched = true;
                        if (log != null) log("临时添加 " + tempIp + "/24 → 扫描 " + cidr);
                    }
                    else
                    {
                        if (log != null) log("扫描 " + cidr + "（" + tempIp + " 已存在，未改动）");
                    }
                    int before = hits.Count;
                    int routedOnly;
                    Sweep24(cidr, local, hits, seen, token, out routedOnly);
                    if (log != null)
                    {
                        string extra = routedOnly > 0 ? "（另有 " + routedOnly + " 台只能经路由到达，不算本段）" : "";
                        log(cidr + " 命中 " + (hits.Count - before) + " 台" + extra);
                    }
                    if (owned)
                    {
                        Netsh("interface ipv4 delete address name=\"" + adapter + "\" address=" + tempIp);
                        for (int w = 0; w < 25; w++)
                        {
                            if (!HasAddress(adapter, tempIp)) break;
                            Thread.Sleep(100);
                        }
                        added.Remove(tempIp);
                        local.Remove(tempIp);
                        if (log != null) log("已移除临时地址 " + tempIp);
                    }
                }
            }
            finally
            {
                for (int i = 0; i < added.Count; i++)
                {
                    Netsh("interface ipv4 delete address name=\"" + adapter + "\" address=" + added[i]);
                    if (log != null) log("已移除临时地址 " + added[i]);
                }
                // 加过静态地址后网卡会被切成“静态”，原来走 DHCP 的必须切回去，否则以后拿不到地址
                if (touched && wasDhcp)
                {
                    Netsh("interface ipv4 set address name=\"" + adapter + "\" source=dhcp");
                    string got = WaitUsableAddress(adapter, 20000);
                    if (got != null)
                    {
                        if (log != null) log("网卡已恢复自动获取，当前地址 " + got);
                    }
                    else
                    {
                        if (log != null) log("网卡已切回自动获取，但 20 秒内没拿到地址（DHCP 服务器没响应）");
                        if (snapshot.HasAddress)
                        {
                            RestoreIf(adapter, snapshot, log);
                        }
                    }
                }
                else if (touched && !wasDhcp)
                {
                    // 原本是静态配置：把探测前的地址/网关按快照加回去
                    if (snapshot.HasAddress) RestoreIf(adapter, snapshot, log);
                }
            }
            hits.Sort(delegate(Hit x, Hit y)
            {
                return IpUtil.ToUInt(x.Ip).CompareTo(IpUtil.ToUInt(y.Ip));
            });
            return hits;
        }
    }

    // 探测段预设：GUI 与命令行共用（扫描范围 / 192.168.x 全段 / 常见私有段）
    public static class ProbePresets
    {
        public const string Range = "range";
        public const string All16 = "192168";
        public const string CommonSeg = "common";

        public static List<string> ForPreset(string preset, string rangeText)
        {
            string p = preset == null ? "" : preset.Trim().ToLowerInvariant();
            if (p == All16 || p == "192.168" || p == "all") return All192168();
            if (p == CommonSeg || p == "private") return CommonList();
            return FromRange(rangeText);
        }

        public static List<string> FromRange(string rangeText)
        {
            return DirectProbe.SegmentsFromRange(rangeText);
        }

        public static List<string> All192168()
        {
            return DirectProbe.SegmentsFromRange("192.168.0.0/16");
        }

        public static List<string> CommonList()
        {
            string[] blocks = new string[] { "192.168.0.0/16", "10.0.0.0/16", "10.10.0.0/16", "172.16.0.0/16", "169.254.0.0/16" };
            List<string> list = new List<string>();
            HashSet<string> seen = new HashSet<string>();
            for (int i = 0; i < blocks.Length; i++)
            {
                List<string> one = DirectProbe.SegmentsFromRange(blocks[i]);
                for (int j = 0; j < one.Count; j++)
                {
                    if (seen.Add(one[j])) list.Add(one[j]);
                }
            }
            return list;
        }

        public static string Label(string preset)
        {
            string p = preset == null ? "" : preset.Trim().ToLowerInvariant();
            if (p == All16 || p == "192.168" || p == "all") return "192.168.x 全段";
            if (p == CommonSeg || p == "private") return "常见私有段";
            return "扫描范围";
        }

        public static string Eta(int segments)
        {
            double secs = segments * 0.75;
            if (secs < 90) return ((int)Math.Round(secs)) + " 秒";
            return ((int)Math.Round(secs / 60.0)) + " 分钟";
        }
    }

    // 链路体检：网卡计数器 + 可选 pktmon 抓包，判断线上到底有没有帧、对端是谁
    public static class LinkCheck
    {
        public class Peer
        {
            public string Mac = "";
            public string Vendor = "";
            public string Ip = "";
        }

        public class Evidence
        {
            public string Adapter = "";
            public string Status = "";
            public string Type = "";
            public long SpeedMbps;
            public long RxBytes0;
            public long RxBytes1;
            public long RxPackets0;
            public long RxPackets1;
            public long TxBytes0;
            public long TxBytes1;
            public int Seconds;
            public List<Peer> Peers = new List<Peer>();
            public bool SniffUsed;
            public string Verdict = "";

            public long RxDelta { get { return RxBytes1 - RxBytes0; } }
            public long RxPacketsDelta { get { return RxPackets1 - RxPackets0; } }
            public long TxDelta { get { return TxBytes1 - TxBytes0; } }
        }

        public static NetworkInterface FindAdapter(string name)
        {
            if (name == null) return null;
            string want = name.Trim();
            if (want.Length == 0) return null;
            NetworkInterface[] all = NetworkInterface.GetAllNetworkInterfaces();
            for (int i = 0; i < all.Length; i++)
            {
                if (string.Equals(all[i].Name, want, StringComparison.OrdinalIgnoreCase)) return all[i];
            }
            for (int i = 0; i < all.Length; i++)
            {
                if (all[i].Description != null && all[i].Description.IndexOf(want, StringComparison.OrdinalIgnoreCase) >= 0) return all[i];
            }
            return null;
        }

        public static bool PktMonExists()
        {
            try
            {
                string p = Path.Combine(Environment.SystemDirectory, "PktMon.exe");
                if (File.Exists(p)) return true;
            }
            catch { }
            return File.Exists(@"C:\Windows\System32\PktMon.exe");
        }

        public static Evidence Run(string adapter, int seconds, Action<string> log, CancellationToken token)
        {
            if (seconds < 3) seconds = 3;
            Evidence ev = new Evidence();
            ev.Adapter = adapter == null ? "" : adapter;
            ev.Seconds = seconds;
            NetworkInterface ni = FindAdapter(adapter);
            if (ni == null)
            {
                ev.Status = "未找到";
                ev.Verdict = "找不到网卡「" + ev.Adapter + "」，请检查名称（控制面板 → 网络连接）。";
                if (log != null) log(ev.Verdict);
                return ev;
            }
            ev.Status = ni.OperationalStatus.ToString();
            ev.Type = ni.NetworkInterfaceType.ToString();
            try { ev.SpeedMbps = ni.Speed / 1000000L; }
            catch { }

            IPv4InterfaceStatistics s0 = ni.GetIPv4Statistics();
            ev.RxBytes0 = s0.BytesReceived;
            ev.RxPackets0 = s0.UnicastPacketsReceived + s0.NonUnicastPacketsReceived;
            ev.TxBytes0 = s0.BytesSent;

            bool admin = DirectProbe.IsAdministrator();
            Task<List<Peer>> sniff = null;
            if (admin && PktMonExists())
            {
                if (log != null) log("管理员身份：同时用 pktmon 抓包 " + seconds + " 秒（只看接收方向）");
                sniff = Task.Factory.StartNew(delegate { return Sniff(ni, seconds, log, token); }, token);
            }
            else if (log != null)
            {
                log(admin ? "没找到 pktmon，只能采样计数器" : "非管理员：只采样计数器，抓不到对端 MAC");
            }

            Sleep(seconds * 1000, token);

            IPv4InterfaceStatistics s1 = ni.GetIPv4Statistics();
            ev.RxBytes1 = s1.BytesReceived;
            ev.RxPackets1 = s1.UnicastPacketsReceived + s1.NonUnicastPacketsReceived;
            ev.TxBytes1 = s1.BytesSent;

            if (sniff != null)
            {
                try
                {
                    ev.Peers = sniff.Result;
                    ev.SniffUsed = true;
                }
                catch (Exception ex)
                {
                    ev.SniffUsed = false;
                    if (log != null) log("抓包失败：" + ex.Message);
                }
            }
            ev.Verdict = BuildVerdict(ev);
            return ev;
        }

        public static string BuildVerdict(Evidence ev)
        {
            if (ev.RxDelta <= 0 && ev.Peers.Count == 0)
            {
                return "线上 " + ev.Seconds + " 秒内没有收到任何帧：设备没上电、网线只插了一头、或交换机端口没开。\r\n"
                     + "如果确认设备已上电，它可能不在 192.168.x（有的设备默认 10.x / 172.16.x / 169.254.x），\r\n"
                     + "用「直连探测 → 常见私有段」再扫一次。";
            }
            if (ev.Peers.Count > 0)
            {
                return "线上有 " + ev.Peers.Count + " 个 MAC 在发包（见下方列表），但都不回应当前扫描段的 ARP —— 它们大概率不在这个网段。\r\n"
                     + "按列表里出现的 IP 把「扫描范围」改成对应网段再扫。";
            }
            if (!ev.SniffUsed)
            {
                return "线上有流量（" + ev.RxDelta + " 字节 / " + ev.RxPacketsDelta + " 个包），但没抓到对端 MAC：\r\n"
                     + "抓包需要管理员权限，请以管理员身份重新运行一次体检。";
            }
            if (ev.Type != null && ev.Type.IndexOf("Wireless", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "线上有流量（" + ev.RxDelta + " 字节），但这是无线网卡：WiFi 帧里的 MAC 是接入点/组播地址，不能当作设备 MAC。\r\n"
                     + "链路体检请对有线网卡做（先在「网络连接」里确认网线插的是哪块网卡）。";
            }
            return "线上有流量（" + ev.RxDelta + " 字节 / " + ev.RxPacketsDelta + " 个包），但接收到的帧里没有别的设备 MAC：\r\n"
                 + "可能只是本机自己在发包（比如 DHCP/组播），也可能抓包被安全软件拦了。";
        }

        static List<Peer> Sniff(NetworkInterface ni, int seconds, Action<string> log, CancellationToken token)
        {
            List<Peer> peers = new List<Peer>();
            string etl = Path.Combine(Path.GetTempPath(), "lanscanner-sniff.etl");
            string txt = Path.Combine(Path.GetTempPath(), "lanscanner-sniff.txt");
            try
            {
                TryDelete(etl);
                TryDelete(txt);
                RunTool("pktmon", "filter remove");
                RunTool("pktmon", "start --capture --pkt-size 128 --file-name \"" + etl + "\"");
                Sleep(seconds * 1000, token);
                RunTool("pktmon", "stop");
                if (!File.Exists(etl))
                {
                    if (log != null) log("pktmon 没有生成抓包文件（可能被安全软件拦截）");
                    return peers;
                }
                RunTool("pktmon", "format \"" + etl + "\" -o \"" + txt + "\"");
                if (!File.Exists(txt))
                {
                    if (log != null) log("pktmon 转换抓包文件失败");
                    return peers;
                }
                peers = ParseSniff(txt, ni, log);
            }
            catch (Exception ex)
            {
                if (log != null) log("抓包异常：" + ex.Message);
            }
            finally
            {
                RunTool("pktmon", "filter remove");
                TryDelete(etl);
                TryDelete(txt);
            }
            return peers;
        }

        internal static List<Peer> ParseSniff(string txt, NetworkInterface ni, Action<string> log)
        {
            List<Peer> peers = new List<Peer>();
            HashSet<string> seen = new HashSet<string>();
            HashSet<string> local = LocalMacSet();

            string[] lines = File.ReadAllLines(txt);
            bool rx = false;
            bool eth = false;
            int events = 0;
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i];
                if (IsSniffHeader(line))
                {
                    events++;
                    rx = Regex.IsMatch(line, @"(方向|Direction)\s*Rx");
                    eth = Regex.IsMatch(line, @"(类型|Type)\s*(Ethernet|以太网)", RegexOptions.IgnoreCase);
                    continue;
                }
                if (!rx || !eth) continue;
                if (line.IndexOf("SA:", StringComparison.Ordinal) < 0) continue;
                StringBuilder body = new StringBuilder(line);
                for (int j = i + 1; j < lines.Length && j <= i + 2; j++)
                {
                    if (IsSniffHeader(lines[j])) break;
                    body.Append("\n").Append(lines[j]);
                }
                string sa = MatchMac(body.ToString(), "SA:");
                if (sa.Length == 0) continue;
                if (!IsUnicastMac(sa)) continue;
                if (local.Contains(sa)) continue;
                if (seen.Contains(sa)) continue;
                seen.Add(sa);
                Peer peer = new Peer();
                peer.Mac = sa;
                peer.Vendor = Oui.Lookup(sa);
                peer.Ip = MatchIp(body.ToString());
                peers.Add(peer);
                if (peers.Count >= 60) break;
            }
            if (log != null) log("抓包事件 " + events + " 条，对端 MAC " + peers.Count + " 个");
            return peers;
        }

        static bool IsSniffHeader(string line)
        {
            return line != null && line.IndexOf("PktGroupId", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        static int MatchNumber(string text, string pattern)
        {
            Match m = Regex.Match(text, pattern);
            if (!m.Success) return -1;
            int v;
            if (int.TryParse(m.Groups[2].Value, out v)) return v;
            return -1;
        }

        static bool IsUnicastMac(string mac)
        {
            if (mac == null || mac.Length < 2) return false;
            int v;
            if (!int.TryParse(mac.Substring(0, 2), System.Globalization.NumberStyles.HexNumber, null, out v)) return false;
            return (v & 0x01) == 0;
        }

        static string MatchMac(string text, string label)
        {
            Match m = Regex.Match(text, label + @"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})");
            if (!m.Success) return "";
            return m.Groups[1].Value.Replace('-', ':').ToUpperInvariant();
        }

        static string MatchIp(string text)
        {
            Match m = Regex.Match(text, @"(\d{1,3}(?:\.\d{1,3}){3})(?:\.\d{1,5})?\s*>");
            if (!m.Success) return "";
            return m.Groups[1].Value;
        }

        static HashSet<string> LocalMacSet()
        {
            HashSet<string> set = new HashSet<string>();
            try
            {
                NetworkInterface[] all = NetworkInterface.GetAllNetworkInterfaces();
                for (int i = 0; i < all.Length; i++)
                {
                    try
                    {
                        PhysicalAddress pa = all[i].GetPhysicalAddress();
                        if (pa == null) continue;
                        byte[] b = pa.GetAddressBytes();
                        if (b == null || b.Length < 6) continue;
                        StringBuilder sb = new StringBuilder();
                        for (int k = 0; k < 6; k++)
                        {
                            if (k > 0) sb.Append(":");
                            sb.Append(b[k].ToString("X2"));
                        }
                        set.Add(sb.ToString());
                    }
                    catch { }
                }
            }
            catch { }
            return set;
        }

        static void RunTool(string exe, string args)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = exe;
                psi.Arguments = args;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                using (Process p = Process.Start(psi))
                {
                    if (p == null) return;
                    p.StandardOutput.ReadToEnd();
                    p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(20000))
                    {
                        try { p.Kill(); }
                        catch { }
                    }
                }
            }
            catch { }
        }

        static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); }
            catch { }
        }

        static void Sleep(int ms, CancellationToken token)
        {
            int left = ms;
            while (left > 0)
            {
                if (token.IsCancellationRequested) return;
                int step = left > 100 ? 100 : left;
                Thread.Sleep(step);
                left -= step;
            }
        }
    }
}
