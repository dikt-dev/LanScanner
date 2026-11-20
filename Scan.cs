using System;
using System.Runtime.InteropServices;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
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
}
