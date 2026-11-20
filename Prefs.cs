using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace LanScanner
{
    // 极简 ini 存储：%APPDATA%\LanScanner\settings.ini，一行一个 key=value。
    // 文件损坏或不可写时静默回落默认值，绝不影响启动。
    public class Prefs
    {
        public string Range = "192.168.0.0/16";
        public int Concurrency = 512;
        public int TimeoutMs = 300;
        public int RetryRounds = 0;
        public bool UseArp = true;
        public bool ResolveDns = false;
        public List<string> RecentRanges = new List<string>();
        public string LastExportDir = "";
        public int Width = 1000;
        public int Height = 640;

        public static string DirPath
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "LanScanner"); }
        }

        public static string FilePath
        {
            get { return Path.Combine(DirPath, "settings.ini"); }
        }

        public static Prefs Load()
        {
            Prefs p = new Prefs();
            try
            {
                if (!File.Exists(FilePath)) return p;
                string[] lines = File.ReadAllLines(FilePath, Encoding.UTF8);
                for (int i = 0; i < lines.Length; i++)
                {
                    string s = lines[i] == null ? "" : lines[i].Trim();
                    if (s.Length == 0) continue;
                    if (s[0] == '#' || s[0] == ';') continue;
                    int eq = s.IndexOf('=');
                    if (eq <= 0) continue;
                    string k = s.Substring(0, eq).Trim().ToLowerInvariant();
                    string v = s.Substring(eq + 1).Trim();
                    if (k == "range")
                    {
                        if (v.Length > 0) p.Range = v;
                    }
                    else if (k == "concurrency")
                    {
                        int n;
                        if (int.TryParse(v, out n) && n >= 1 && n <= 4096) p.Concurrency = n;
                    }
                    else if (k == "timeoutms")
                    {
                        int n;
                        if (int.TryParse(v, out n) && n >= 50 && n <= 5000) p.TimeoutMs = n;
                    }
                    else if (k == "retryrounds")
                    {
                        int n;
                        if (int.TryParse(v, out n) && n >= 0 && n <= 5) p.RetryRounds = n;
                    }
                    else if (k == "usearp")
                    {
                        p.UseArp = (v == "1" || v.ToLowerInvariant() == "true");
                    }
                    else if (k == "resolvedns")
                    {
                        p.ResolveDns = (v == "1" || v.ToLowerInvariant() == "true");
                    }
                    else if (k == "recentranges")
                    {
                        string[] parts = v.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries);
                        for (int j = 0; j < parts.Length && p.RecentRanges.Count < 5; j++)
                        {
                            string r = parts[j].Trim();
                            if (r.Length > 0) p.RecentRanges.Add(r);
                        }
                    }
                    else if (k == "lastexportdir")
                    {
                        p.LastExportDir = v;
                    }
                    else if (k == "width")
                    {
                        int n;
                        if (int.TryParse(v, out n) && n >= 700) p.Width = n;
                    }
                    else if (k == "height")
                    {
                        int n;
                        if (int.TryParse(v, out n) && n >= 460) p.Height = n;
                    }
                }
            }
            catch
            {
            }
            return p;
        }

        public void PushRecent(string range)
        {
            if (string.IsNullOrEmpty(range)) return;
            string r = range.Trim();
            if (r.Length == 0) return;
            RecentRanges.RemoveAll(delegate(string s) { return string.Equals(s, r, StringComparison.OrdinalIgnoreCase); });
            RecentRanges.Insert(0, r);
            while (RecentRanges.Count > 5) RecentRanges.RemoveAt(RecentRanges.Count - 1);
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(DirPath);
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("# 局域网设备扫描器设置，删除本文件即恢复默认");
                sb.AppendLine("Range=" + Range);
                sb.AppendLine("Concurrency=" + Concurrency);
                sb.AppendLine("TimeoutMs=" + TimeoutMs);
                sb.AppendLine("RetryRounds=" + RetryRounds);
                sb.AppendLine("UseArp=" + (UseArp ? "1" : "0"));
                sb.AppendLine("ResolveDns=" + (ResolveDns ? "1" : "0"));
                sb.AppendLine("RecentRanges=" + string.Join("|", RecentRanges.ToArray()));
                sb.AppendLine("LastExportDir=" + LastExportDir);
                sb.AppendLine("Width=" + Width);
                sb.AppendLine("Height=" + Height);
                File.WriteAllText(FilePath, sb.ToString(), new UTF8Encoding(false));
            }
            catch
            {
            }
        }
    }
}
