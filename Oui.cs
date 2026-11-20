using System;
using System.Collections.Generic;

namespace LanScanner
{
    // 离线 OUI 前缀表：只做“这根线上大概是什么设备”的参考判断，不发网络请求。
    // 键为 MAC 前 3 字节的大写十六进制（无分隔符），如 "C46E1F"。
    public static class Oui
    {
        static readonly string[] Raw = new string[]
        {
            "00000C=Cisco", "000142=Cisco", "001C10=Cisco-Linksys",
            "001B21=Intel", "001E67=Intel", "3C970E=Intel", "8C1645=Intel", "A4BB6D=Intel",
            "00155D=Microsoft Hyper-V", "0003FF=Microsoft", "000D3A=Microsoft",
            "005056=VMware 虚拟机", "000C29=VMware 虚拟机", "000569=VMware 虚拟机",
            "001C42=Parallels 虚拟机", "080027=VirtualBox 虚拟机", "525400=QEMU/KVM 虚拟机", "0242AC=Docker 容器",
            "B827EB=树莓派 Raspberry Pi", "DCA632=树莓派 Raspberry Pi", "E45F01=树莓派 Raspberry Pi", "2CCF67=树莓派 Raspberry Pi",
            "240AC4=乐鑫 ESP", "2C3AE8=乐鑫 ESP", "3C71BF=乐鑫 ESP", "5CCF7F=乐鑫 ESP", "84F3EB=乐鑫 ESP",
            "A4CF12=乐鑫 ESP", "AC67B2=乐鑫 ESP", "B4E62D=乐鑫 ESP", "C44F33=乐鑫 ESP", "DC4F22=乐鑫 ESP",
            "ECFA5C=乐鑫 ESP", "246F28=乐鑫 ESP",
            "001A11=Google", "3C5AB4=Google", "F4F5D8=Google",
            "001D0F=TP-Link", "14CC20=TP-Link", "50C7BF=TP-Link", "60E327=TP-Link", "A42BB0=TP-Link",
            "B0BE76=TP-Link", "C025E9=TP-Link", "EC086B=TP-Link", "F4F26D=TP-Link", "98DAC4=TP-Link",
            "1C3BF3=TP-Link", "3C846A=TP-Link", "30B5C2=TP-Link",
            "000FE2=华三 H3C", "00E0FC=华为 Huawei", "00259E=华为 Huawei", "286ED4=华为 Huawei",
            "60DE44=华为 Huawei", "781DBA=华为 Huawei",
            "4419B6=海康威视 Hikvision", "C056E3=海康威视 Hikvision", "4CBD8F=海康威视 Hikvision", "BCAD28=海康威视 Hikvision",
            "3CEF8C=大华 Dahua", "4C11BF=大华 Dahua", "9C1463=大华 Dahua", "E0508B=大华 Dahua",
            "001CB3=Apple", "002500=Apple", "3C0754=Apple", "68AB1E=Apple", "8C8590=Apple",
            "F01898=Apple", "A483E7=Apple", "DCA904=Apple", "9CF387=Apple",
            "00E04C=Realtek", "000C43=MediaTek", "001018=Broadcom", "00037F=Qualcomm Atheros",
            "00156D=Ubiquiti", "24A43C=Ubiquiti", "788A20=Ubiquiti",
            "000C42=MikroTik", "4C5E0C=MikroTik", "6C3B6B=MikroTik", "744D28=MikroTik", "CC2DE0=MikroTik", "E48D8C=MikroTik",
            "001132=群晖 Synology", "9009D0=群晖 Synology",
            "00146C=Netgear", "204E7F=Netgear", "A040A0=Netgear",
            "001BFC=ASUS", "2C56DC=ASUS", "1C872C=ASUS",
            "001422=Dell", "001F29=HP", "3CD92B=HP",
            "0012FB=Samsung", "3423BA=Samsung", "5C0A5B=Samsung", "781FDB=Samsung", "0013A9=Sony",
            "640980=小米 Xiaomi", "7811DC=小米 Xiaomi", "508F4C=小米 Xiaomi", "2034FB=小米 Xiaomi", "68DFDD=小米 Xiaomi", "F0B429=小米 Xiaomi",
            "54EF44=Aqara 绿米", "04CF8C=Aqara 绿米",
            "34E0CF=中兴 ZTE", "4C09B4=中兴 ZTE",
            "00749C=锐捷 Ruijie", "300B6F=锐捷 Ruijie"
        };

        static Dictionary<string, string> map;

        static void Init()
        {
            Dictionary<string, string> m = new Dictionary<string, string>(Raw.Length, StringComparer.Ordinal);
            for (int i = 0; i < Raw.Length; i++)
            {
                int eq = Raw[i].IndexOf('=');
                if (eq <= 0) continue;
                string k = Raw[i].Substring(0, eq).ToUpperInvariant();
                string v = Raw[i].Substring(eq + 1);
                if (!m.ContainsKey(k)) m[k] = v;
            }
            map = m;
        }

        // 规范化 MAC：只保留十六进制字符并转大写；短于 12 位返回空串
        public static string Normalize(string mac)
        {
            if (string.IsNullOrEmpty(mac)) return "";
            char[] buf = new char[mac.Length];
            int n = 0;
            for (int i = 0; i < mac.Length; i++)
            {
                char c = mac[i];
                if (c >= '0' && c <= '9') { buf[n++] = c; }
                else if (c >= 'a' && c <= 'f') { buf[n++] = (char)(c - 32); }
                else if (c >= 'A' && c <= 'F') { buf[n++] = c; }
            }
            if (n < 12) return "";
            return new string(buf, 0, 12);
        }

        public static string Lookup(string mac)
        {
            string hex = Normalize(mac);
            if (hex.Length < 12) return "";
            if (map == null) Init();
            string key = hex.Substring(0, 6);
            string vendor;
            if (map.TryGetValue(key, out vendor)) return vendor;

            int first = Convert.ToInt32(hex.Substring(0, 2), 16);
            if ((first & 0x02) != 0) return "私有/虚拟 MAC";
            return "未知厂商";
        }
    }
}
