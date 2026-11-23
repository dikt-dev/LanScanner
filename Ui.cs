using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace LanScanner
{
    public class MainForm : Form
    {
        ComboBox cmbRange;
        TextBox txtFilter;
        Label lblCount;
        TableLayoutPanel root;
        SplitContainer splitRef;
        float _dpiScale = 1f;
        NumericUpDown numConc;
        NumericUpDown numTimeout;
        NumericUpDown numRetry;
        CheckBox chkArp;
        CheckBox chkDns;
        Button btnStart;
        Button btnStop;
        Button btnExport;
        Button btnProbe;
        Button btnLinkCheck;
        Button btnLocal;
        Button btnPick;
        Button btnAll16;
        Button btnClearRange;
        Label lblPlan;
        ToolTip tips;
        Button btnClearFilter;
        ProgressBar bar;
        Label lblStatus;
        TableLayoutPanel statusRow;
        DataGridView grid;
        TextBox logBox;
        System.Windows.Forms.Timer uiTimer;
        CancellationTokenSource cts;
        Engine engine;
        NetInfo net;
        Prefs prefs;
        List<HostRow> lastRows = new List<HostRow>();
        DateTime started;
        bool running;
        string autoRange;
        bool autoScan;
        internal string ShotPath;
        internal string ShotRange;
        internal string ShotStatus;
        internal int ShotClientW;
        internal int ShotClientH;

        [StructLayout(LayoutKind.Sequential)]
        struct FLASHWINFO
        {
            public int cbSize;
            public IntPtr hwnd;
            public int dwFlags;
            public int uCount;
            public int dwTimeout;
        }

        [DllImport("user32.dll")]
        static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        static extern bool FlashWindowEx(ref FLASHWINFO pwfi);

        public MainForm(string[] args)
        {
            string[] startArgs = args == null ? new string[0] : args;
            for (int i = 0; i < startArgs.Length; i++)
            {
                string s = startArgs[i];
                if (s == "--scan" || s == "/scan") { autoScan = true; continue; }
                if (s.Length > 0 && (s[0] == '-' || s[0] == '/')) continue;
                if (autoRange == null) autoRange = s;
                autoScan = true;
            }
            prefs = Prefs.Load();
            BuildUi();
            ApplyPrefs();
            net = new NetInfo();
            net.Load();
            Log("局域网设备扫描器  已启动");
            Log("本机网段：");
            string summary = net.Summary();
            if (summary.Length > 0) Log(summary);
            if (net.Gateways.Count > 0) Log("网关：" + string.Join("、", net.Gateways.ToArray()));
            Log("提示：同一个交换机下的设备若网段不同，看“路径”列分清 直达 / 跨网段。");
            Log("快捷键：Ctrl+Enter 开始，Esc 停止，Ctrl+F 过滤，Ctrl+S 导出，双击行复制 IP。");
            Log("用法：LanScanner.exe [网段] [--scan]，例如 LanScanner.exe 192.168.0.0/16 --scan");
            if (autoRange != null) cmbRange.Text = autoRange;
            Shown += new EventHandler(MainForm_Shown);
        }

        void BuildUi()
        {
            Text = "局域网设备扫描器 - 192.168.0.0 ~ 192.168.255.255";
            ClientSize = new Size(980, 440);
            MinimumSize = new Size(900, 420);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9F);
            KeyPreview = true;

            root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.ColumnCount = 1;
            root.RowCount = 3;
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 132F));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30F));
            Controls.Add(root);

            Panel top = new Panel();
            top.Dock = DockStyle.Fill;
            top.Padding = new Padding(8);
            root.Controls.Add(top, 0, 0);

            Label lblRange = new Label();
            lblRange.Text = "扫描范围:";
            lblRange.SetBounds(10, 14, 80, 20);
            top.Controls.Add(lblRange);

            cmbRange = new ComboBox();
            cmbRange.SetBounds(96, 11, 300, 24);
            cmbRange.DropDownStyle = ComboBoxStyle.DropDown;
            cmbRange.Text = "192.168.0.0/16";
            cmbRange.TextChanged += new EventHandler(cmbRange_TextChanged);
            top.Controls.Add(cmbRange);

            btnPick = new Button();
            btnPick.Text = "选择...";
            btnPick.SetBounds(400, 9, 64, 27);
            btnPick.Click += new EventHandler(btnPick_Click);
            top.Controls.Add(btnPick);

            btnLocal = new Button();
            btnLocal.Text = "本机 /24";
            btnLocal.SetBounds(470, 9, 88, 27);
            btnLocal.Click += new EventHandler(btnLocal_Click);
            top.Controls.Add(btnLocal);

            btnAll16 = new Button();
            btnAll16.Text = "整个 /16";
            btnAll16.SetBounds(564, 9, 72, 27);
            btnAll16.Click += new EventHandler(btnAll16_Click);
            top.Controls.Add(btnAll16);

            btnClearRange = new Button();
            btnClearRange.Text = "清空";
            btnClearRange.SetBounds(642, 9, 56, 27);
            btnClearRange.Click += new EventHandler(btnClearRange_Click);
            top.Controls.Add(btnClearRange);

            btnStart = new Button();
            btnStart.Text = "开始扫描";
            btnStart.SetBounds(706, 9, 90, 27);
            btnStart.Click += new EventHandler(btnStart_Click);
            top.Controls.Add(btnStart);

            btnStop = new Button();
            btnStop.Text = "停止";
            btnStop.SetBounds(802, 9, 64, 27);
            btnStop.Enabled = false;
            btnStop.Click += new EventHandler(btnStop_Click);
            top.Controls.Add(btnStop);

            btnExport = new Button();
            btnExport.Text = "导出 CSV";
            btnExport.SetBounds(872, 9, 84, 27);
            btnExport.Click += new EventHandler(btnExport_Click);
            top.Controls.Add(btnExport);

            btnProbe = new Button();
            btnProbe.Text = "直连探测";
            btnProbe.SetBounds(874, 84, 98, 26);
            btnProbe.Click += new EventHandler(btnProbe_Click);
            top.Controls.Add(btnProbe);

            btnLinkCheck = new Button();
            btnLinkCheck.Text = "链路体检";
            btnLinkCheck.SetBounds(776, 84, 92, 26);
            btnLinkCheck.Click += new EventHandler(btnLinkCheck_Click);
            top.Controls.Add(btnLinkCheck);

            Label lblConc = new Label();
            lblConc.Text = "并发";
            lblConc.SetBounds(10, 52, 44, 20);
            top.Controls.Add(lblConc);

            numConc = new NumericUpDown();
            numConc.SetBounds(58, 49, 64, 24);
            numConc.Minimum = 1;
            numConc.Maximum = 4096;
            numConc.Value = 512;
            numConc.Increment = 64;
            numConc.ValueChanged += new EventHandler(numConc_ValueChanged);
            top.Controls.Add(numConc);

            Label lblTimeout = new Label();
            lblTimeout.Text = "超时(ms)";
            lblTimeout.SetBounds(130, 52, 64, 20);
            top.Controls.Add(lblTimeout);

            numTimeout = new NumericUpDown();
            numTimeout.SetBounds(198, 49, 64, 24);
            numTimeout.Minimum = 50;
            numTimeout.Maximum = 5000;
            numTimeout.Value = 300;
            numTimeout.Increment = 50;
            top.Controls.Add(numTimeout);

            chkArp = new CheckBox();
            chkArp.Text = "识别禁 Ping 设备(ARP)";
            chkArp.SetBounds(274, 50, 176, 22);
            chkArp.Checked = true;
            top.Controls.Add(chkArp);

            chkDns = new CheckBox();
            chkDns.Text = "反查主机名";
            chkDns.SetBounds(456, 50, 104, 22);
            top.Controls.Add(chkDns);

            Label lblRetry = new Label();
            lblRetry.Text = "补扫轮数";
            lblRetry.SetBounds(566, 52, 68, 20);
            top.Controls.Add(lblRetry);

            numRetry = new NumericUpDown();
            numRetry.SetBounds(638, 49, 50, 24);
            numRetry.Minimum = 0;
            numRetry.Maximum = 5;
            numRetry.Value = 0;
            top.Controls.Add(numRetry);

            lblPlan = new Label();
            lblPlan.Text = "请选择要扫描的网段";
            lblPlan.SetBounds(700, 53, 272, 20);
            lblPlan.ForeColor = Color.DimGray;
            top.Controls.Add(lblPlan);

            tips = new ToolTip();
            tips.ShowAlways = true;
            tips.AutoPopDelay = 12000;
            tips.InitialDelay = 300;
            tips.ReshowDelay = 100;
            tips.SetToolTip(cmbRange, "可直接输入：192.168.0.0/16、192.168.1.*、192.168.1.1-254，多段用逗号分隔。点“选择...”可以勾选本机所在的网段。");
            tips.SetToolTip(btnPick, "勾选本机检测到的网段，不用记 CIDR 写法");
            if (btnProbe != null) tips.SetToolTip(btnProbe, "设备 IP 不知道、网线直连：按「扫描范围」临时给网卡加同段地址做 ARP 扫描，结束后自动还原（需管理员）");
            if (btnLinkCheck != null) tips.SetToolTip(btnLinkCheck, "采样 30 秒看网卡到底有没有收到帧；管理员身份下用系统自带 pktmon 抓包，能看到线上发包的对端 MAC");
            tips.SetToolTip(btnLocal, "只填入本机所在的一个 /24 段（最常用）");
            tips.SetToolTip(btnAll16, "填入 192.168.0.0/16，扫满 6 万多个地址");
            tips.SetToolTip(numConc, "同时在飞的 ping 数量。局域网 512 很稳；设备弱（老交换机/无线桥接）降到 128");
            tips.SetToolTip(numTimeout, "单个 ping 等多久。跨网段设备多时可调到 500~800 减少漏报");
            tips.SetToolTip(numRetry, "第一轮没响应的地址再补几轮。丢包严重的网络设 1~2");
            tips.SetToolTip(chkArp, "很多设备禁 ping，只能从 ARP 表里发现。关掉会更快但会漏设备");
            tips.SetToolTip(chkDns, "对在线设备做反向 DNS 查主机名，扫大网段时会明显变慢");

            Label lblFilter = new Label();
            lblFilter.Text = "过滤:";
            lblFilter.SetBounds(10, 90, 56, 20);
            top.Controls.Add(lblFilter);

            txtFilter = new TextBox();
            txtFilter.SetBounds(70, 87, 320, 24);
            txtFilter.TextChanged += new EventHandler(txtFilter_TextChanged);
            top.Controls.Add(txtFilter);

            btnClearFilter = new Button();
            btnClearFilter.Text = "清除过滤";
            btnClearFilter.SetBounds(398, 86, 80, 26);
            btnClearFilter.Click += new EventHandler(btnClearFilter_Click);
            top.Controls.Add(btnClearFilter);

            lblCount = new Label();
            lblCount.SetBounds(492, 90, 276, 20);
            lblCount.ForeColor = Color.DimGray;
            lblCount.Text = "显示 0 台";
            top.Controls.Add(lblCount);

            statusRow = new TableLayoutPanel();
            statusRow.Dock = DockStyle.Fill;
            statusRow.Padding = new Padding(8, 4, 8, 4);
            statusRow.BackColor = Color.FromArgb(242, 242, 242);
            statusRow.ColumnCount = 2;
            statusRow.RowCount = 1;
            statusRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 340F));
            statusRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            statusRow.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            root.Controls.Add(statusRow, 0, 2);

            bar = new ProgressBar();
            bar.Dock = DockStyle.Fill;
            bar.Margin = new Padding(0, 4, 8, 4);
            statusRow.Controls.Add(bar, 0, 0);

            lblStatus = new Label();
            lblStatus.Dock = DockStyle.Fill;
            lblStatus.TextAlign = ContentAlignment.MiddleLeft;
            lblStatus.AutoEllipsis = true;
            lblStatus.Margin = new Padding(0);
            lblStatus.Text = "就绪";
            statusRow.Controls.Add(lblStatus, 1, 0);

            SplitContainer split = new SplitContainer();
            split.Dock = DockStyle.Fill;
            split.Orientation = Orientation.Horizontal;
            split.SplitterDistance = 300;
            splitRef = split;
            root.Controls.Add(split, 0, 1);

            grid = new DataGridView();
            grid.Dock = DockStyle.Fill;
            grid.ReadOnly = true;
            grid.AllowUserToAddRows = false;
            grid.AllowUserToDeleteRows = false;
            grid.RowHeadersVisible = false;
            grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            grid.MultiSelect = true;
            grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None;
            grid.BackgroundColor = Color.White;
            grid.AllowUserToResizeRows = false;
            grid.Columns.Add("ip", "IP");
            grid.Columns.Add("icmp", "ICMP");
            grid.Columns.Add("rtt", "RTT(ms)");
            grid.Columns.Add("ttl", "TTL");
            grid.Columns.Add("mac", "MAC");
            grid.Columns.Add("vendor", "厂商(参考)");
            grid.Columns.Add("arp", "ARP 状态");
            grid.Columns.Add("path", "路径");
            grid.Columns.Add("role", "角色");
            grid.Columns.Add("host", "主机名");
            int[] widths = new int[] { 116, 52, 66, 50, 138, 132, 92, 66, 60, 190 };
            for (int i = 0; i < widths.Length; i++) grid.Columns[i].Width = widths[i];
            grid.Columns[9].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            grid.ColumnHeadersDefaultCellStyle.Padding = new Padding(4, 3, 4, 3);
            grid.ColumnHeadersDefaultCellStyle.WrapMode = DataGridViewTriState.False;
            grid.RowTemplate.Height = (int)Math.Round(grid.Font.GetHeight() + 10);
            grid.SizeChanged += new EventHandler(grid_SizeChanged);
            for (int i = 0; i < grid.Columns.Count; i++) grid.Columns[i].SortMode = DataGridViewColumnSortMode.Automatic;
            grid.SortCompare += new DataGridViewSortCompareEventHandler(grid_SortCompare);
            grid.CellDoubleClick += new DataGridViewCellEventHandler(grid_CellDoubleClick);
            grid.CellMouseDown += new DataGridViewCellMouseEventHandler(grid_CellMouseDown);
            grid.ContextMenuStrip = BuildContextMenu();
            grid.CellFormatting += new DataGridViewCellFormattingEventHandler(grid_CellFormatting);
            split.Panel1.Controls.Add(grid);

            logBox = new TextBox();
            logBox.Dock = DockStyle.Fill;
            logBox.Multiline = true;
            logBox.ReadOnly = true;
            logBox.ScrollBars = ScrollBars.Vertical;
            logBox.WordWrap = false;
            logBox.Font = new Font("Consolas", 9F);
            logBox.BackColor = Color.FromArgb(250, 250, 250);
            split.Panel2.Controls.Add(logBox);

            uiTimer = new System.Windows.Forms.Timer();
            uiTimer.Interval = 250;
            uiTimer.Tick += new EventHandler(uiTimer_Tick);

            KeyDown += new KeyEventHandler(MainForm_KeyDown);
            FormClosing += new FormClosingEventHandler(MainForm_FormClosing);
            ScaleToDpi();
            string layoutInfo = string.Format("client={0}x{1} root={2}x{3} top={4}x{5} status={6}x{7}@{8},{9} split={10}x{11}@{12},{13} rows=[{14},{15},{16}]",
                ClientSize.Width, ClientSize.Height, root.Width, root.Height, top.Width, top.Height,
                statusRow.Width, statusRow.Height, statusRow.Left, statusRow.Top,
                split.Width, split.Height, split.Left, split.Top,
                root.RowStyles[0].Height, root.RowStyles[1].Height, root.RowStyles[2].Height);
            if (Environment.GetEnvironmentVariable("LANSCANNER_DEBUG") == "1")
            {
                try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "lanscanner-layout.txt"), layoutInfo); } catch { }
            }
        }

        // 进程是 DPI 感知的，控件坐标是物理像素；按当前 DPI 把整棵布局等比放大
        void ScaleToDpi()
        {
            float k = 1f;
            try
            {
                using (Graphics g = CreateGraphics()) k = g.DpiX / 96f;
            }
            catch { }
            k = (float)Math.Round(k * 4) / 4f;
            if (k < 1.05f) return;
            if (k > 3f) k = 3f;
            // 按屏幕工作区收口，避免放大后窗口超出屏幕
            Size baseSize = ClientSize;
            Rectangle wa = Screen.PrimaryScreen.WorkingArea;
            float fitW = (wa.Width - 24f) / 980f;
            float fitH = (wa.Height - 70f) / 440f;
            float fit = Math.Min(fitW, fitH);
            if (fit < k) k = (float)Math.Max(1f, Math.Floor(fit * 4f) / 4f);
            _dpiScale = k;
            MinimumSize = new Size((int)(MinimumSize.Width * k), (int)(MinimumSize.Height * k));
            ClientSize = new Size((int)Math.Round(baseSize.Width * k), (int)Math.Round(baseSize.Height * k));
            root.RowStyles[0].Height = 132F * k;
            root.RowStyles[2].Height = 32F * k;
            ScaleControls(root, k);
            if (statusRow != null) statusRow.ColumnStyles[0].Width = 340F * k;
            if (grid != null)
            {
                for (int i = 0; i < grid.Columns.Count; i++)
                {
                    if (grid.Columns[i].AutoSizeMode == DataGridViewAutoSizeColumnMode.Fill) continue;
                    grid.Columns[i].Width = (int)(grid.Columns[i].Width * k);
                }
            }
            if (splitRef != null && splitRef.Height > 200)
            {
                int want = (int)(splitRef.Height * 0.62);
                if (want < 120) want = 120;
                if (want > splitRef.Height - 120) want = Math.Max(120, splitRef.Height - 120);
                try { splitRef.SplitterDistance = want; } catch { }
            }
        }

        void ScaleControls(Control parent, float k)
        {
            foreach (Control c in parent.Controls)
            {
                if (c.Dock == DockStyle.None)
                {
                    Rectangle b = c.Bounds;
                    c.Bounds = new Rectangle((int)Math.Round(b.X * k), (int)Math.Round(b.Y * k), (int)Math.Round(b.Width * k), (int)Math.Round(b.Height * k));
                }
                ScaleControls(c, k);
            }
        }

        void grid_SizeChanged(object sender, EventArgs e)
        {
            if (grid == null || grid.Columns.Count == 0) return;
            int idx = grid.Columns.Count - 1;
            if (grid.Columns[idx].AutoSizeMode != DataGridViewAutoSizeColumnMode.Fill) return;
            try { grid.AutoResizeColumn(idx, DataGridViewAutoSizeColumnMode.Fill); } catch { }
        }

        ContextMenuStrip BuildContextMenu()
        {
            ContextMenuStrip menu = new ContextMenuStrip();
            menu.Items.Add("复制 IP", null, new EventHandler(menu_CopyIp));
            menu.Items.Add("复制 MAC", null, new EventHandler(menu_CopyMac));
            menu.Items.Add("复制主机名", null, new EventHandler(menu_CopyHost));
            menu.Items.Add("复制整行（Tab 分隔）", null, new EventHandler(menu_CopyRow));
            menu.Items.Add("复制选中行（CSV）", null, new EventHandler(menu_CopySelected));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("在浏览器打开 http://IP", null, new EventHandler(menu_OpenBrowser));
            menu.Items.Add("新窗口 ping -t IP", null, new EventHandler(menu_OpenPing));
            return menu;
        }

        void ApplyPrefs()
        {
            for (int i = 0; i < prefs.RecentRanges.Count; i++) cmbRange.Items.Add(prefs.RecentRanges[i]);
            cmbRange.Text = prefs.Range;
            ClampTo(numConc, prefs.Concurrency);
            ClampTo(numTimeout, prefs.TimeoutMs);
            ClampTo(numRetry, prefs.RetryRounds);
            chkArp.Checked = prefs.UseArp;
            chkDns.Checked = prefs.ResolveDns;
            if (prefs.Width >= 900 && prefs.Height >= 440 && _dpiScale < 1.2f) ClientSize = new Size(prefs.Width, prefs.Height);
            UpdateRangePlan();
        }

        static void ClampTo(NumericUpDown box, int value)
        {
            decimal v = value;
            if (v < box.Minimum) v = box.Minimum;
            if (v > box.Maximum) v = box.Maximum;
            box.Value = v;
        }

        void MainForm_Shown(object sender, EventArgs e)
        {
            if (ShotPath != null)
            {
                if (ShotRange != null) cmbRange.Text = ShotRange;
                if (ShotClientW > 0 && ShotClientH > 0) ClientSize = new Size(ShotClientW, ShotClientH);
                if (ShotStatus != null)
                {
                    lblStatus.Text = ShotStatus;
                    if (bar.Maximum > 0) bar.Value = bar.Maximum;
                }
                System.Windows.Forms.Timer t = new System.Windows.Forms.Timer();
                t.Interval = 700;
                t.Tick += new EventHandler(ShotTick);
                t.Start();
                return;
            }
            if (autoScan) BeginInvoke(new MethodInvoker(StartScan));
        }

        void ShotTick(object sender, EventArgs e)
        {
            System.Windows.Forms.Timer t = (System.Windows.Forms.Timer)sender;
            t.Stop();
            t.Dispose();
            {
                try
                {
                    int colSum = 0;
                    for (int i = 0; i < grid.Columns.Count; i++) colSum += grid.Columns[i].Width;
                    string s = string.Format("client={0}x{1} grid={2}x{3} colSum={4} gridClient={5} hdrH={6} fontH={7:0.0} rowH={8} statusCol={9} bar={10}x{11} lblStatus={12}x{13}@{14},{15}",
                        ClientSize.Width, ClientSize.Height, grid.Width, grid.Height, colSum, grid.ClientSize.Width,
                        grid.ColumnHeadersHeight, grid.Font.GetHeight(), grid.RowTemplate.Height,
                        statusRow.ColumnStyles[0].Width, bar.Width, bar.Height,
                        lblStatus.Width, lblStatus.Height, lblStatus.Left, lblStatus.Top);
                    File.WriteAllText(ShotPath + ".metrics.txt", s);
                }
                catch { }
            }
            UiShot.Capture(this, ShotPath);
            Close();
        }

        void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (cts != null) { try { cts.Cancel(); } catch { } }
            try
            {
                prefs.Range = cmbRange.Text;
                prefs.Concurrency = (int)numConc.Value;
                prefs.TimeoutMs = (int)numTimeout.Value;
                prefs.RetryRounds = (int)numRetry.Value;
                prefs.UseArp = chkArp.Checked;
                prefs.ResolveDns = chkDns.Checked;
                prefs.Width = ClientSize.Width;
                prefs.Height = ClientSize.Height;
                prefs.Save();
            }
            catch { }
        }

        void MainForm_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Control && e.KeyCode == Keys.Enter) { StartScan(); e.Handled = true; e.SuppressKeyPress = true; return; }
            if (e.Control && e.KeyCode == Keys.S) { ExportCsv(); e.Handled = true; e.SuppressKeyPress = true; return; }
            if (e.Control && e.KeyCode == Keys.F) { txtFilter.Focus(); txtFilter.SelectAll(); e.Handled = true; e.SuppressKeyPress = true; return; }
            if (e.Control && e.KeyCode == Keys.A && grid.Focused) { grid.SelectAll(); e.Handled = true; e.SuppressKeyPress = true; return; }
            if (e.KeyCode == Keys.Escape && running) { RequestStop(); e.Handled = true; e.SuppressKeyPress = true; return; }
        }

        void cmbRange_TextChanged(object sender, EventArgs e)
        {
            UpdateRangePlan();
        }

        void numConc_ValueChanged(object sender, EventArgs e)
        {
            UpdateRangePlan();
        }

        void UpdateRangePlan()
        {
            if (lblPlan == null || cmbRange == null) return;
            int conc = numConc == null ? 512 : (int)numConc.Value;
            bool bad;
            string err;
            string plan = RangePlan.Describe(cmbRange.Text, conc, out bad, out err);
            cmbRange.BackColor = bad ? Color.FromArgb(255, 235, 235) : Color.White;
            lblPlan.Text = plan;
            if (bad) lblPlan.ForeColor = Color.Firebrick;
            else if (plan.IndexOf("大范围") >= 0) lblPlan.ForeColor = Color.DarkOrange;
            else lblPlan.ForeColor = Color.DimGray;
            btnStart.Enabled = !running;
        }

        void btnLocal_Click(object sender, EventArgs e)
        {
            net.Load();
            List<string> parts = new List<string>();
            for (int i = 0; i < net.Subnets.Count; i++)
            {
                Subnet s = net.Subnets[i];
                if (s.Prefix < 24) continue;
                if ((s.Net >> 16) == 0xA9FE) continue;
                parts.Add(IpUtil.FromUInt(s.Net) + "/" + s.Prefix);
            }
            string cidrs = parts.Count == 0 ? "192.168.0.0/24" : string.Join(",", parts.ToArray());
            cmbRange.Text = cidrs;
            Log("已填入本机网段：" + cidrs);
        }

        void btnAll16_Click(object sender, EventArgs e)
        {
            cmbRange.Text = "192.168.0.0/16";
        }

        void btnClearRange_Click(object sender, EventArgs e)
        {
            cmbRange.Text = "";
        }

        void btnPick_Click(object sender, EventArgs e)
        {
            net.Load();
            List<string> gws = new List<string>();
            for (int i = 0; i < net.Gateways.Count; i++) gws.Add(net.Gateways[i]);
            using (RangePickerForm f = new RangePickerForm(net.Subnets, gws, cmbRange.Text))
            {
                if (f.ShowDialog(this) != DialogResult.OK) return;
                if (f.ResultText.Length == 0) return;
                cmbRange.Text = f.ResultText;
                Log("已选择网段：" + f.ResultText);
            }
        }

        void btnClearFilter_Click(object sender, EventArgs e)
        {
            txtFilter.Text = "";
        }

        void txtFilter_TextChanged(object sender, EventArgs e)
        {
            ApplyFilter();
        }

        int probeSegments;

        void btnProbe_Click(object sender, EventArgs e)
        {
            if (running) return;
            if (!DirectProbe.IsAdministrator())
            {
                MessageBox.Show(this, "直连探测需要临时给网卡加一个同段地址，必须以管理员身份运行。\n\n请关掉程序，右键 LanScanner.exe →「以管理员身份运行」。", "需要管理员权限", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string adapter = DirectProbe.DefaultAdapter();
            if (adapter == null)
            {
                MessageBox.Show(this, "没有找到已连接的有线网卡（无线网卡不能用于直连探测）。", "无法探测", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            // 先选探测段来源：扫描范围 / 192.168.x 全段 / 常见私有段
            string preset = ProbePresets.Range;
            using (ProbeScopeForm dlg = new ProbeScopeForm(cmbRange.Text))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                preset = dlg.Preset;
            }
            List<string> cidrs;
            string sourceText;
            if (preset == ProbePresets.Range)
            {
                cidrs = DirectProbe.SegmentsFromRange(cmbRange.Text);
                if (cidrs.Count == 0)
                {
                    string rt = cmbRange.Text == null ? "" : cmbRange.Text.Trim();
                    if (rt.Length > 0)
                    {
                        MessageBox.Show(this, "「扫描范围」里的「" + rt + "」解析不出可探测的网段（可能格式有误或范围太大）。\n\n请先改正范围，或者在「选择探测范围」里改选 192.168.x 全段。", "无法探测", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                    cidrs = new List<string>(DirectProbe.DefaultCandidates());
                    sourceText = "扫描范围为空，使用默认 12 段：";
                }
                else
                {
                    sourceText = "探测段来自「扫描范围」：";
                }
            }
            else
            {
                cidrs = ProbePresets.ForPreset(preset, null);
                sourceText = "探测段来自「" + ProbePresets.Label(preset) + "」：";
            }
            if (cidrs.Count == 0)
            {
                MessageBox.Show(this, "没有解析出可探测的网段。请填 192.168.0.0/16、192.168.*.0/24 或 192.168.1.0/24 这样的范围。", "无法探测", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string eta = ProbePresets.Eta(cidrs.Count);
            string head = string.Join("、", cidrs.GetRange(0, Math.Min(6, cidrs.Count)).ToArray());
            if (cidrs.Count > 6) head += " …";
            string ask = "将在网卡「" + adapter + "」上依次临时添加 " + cidrs.Count + " 个网段的地址（如 192.168.1.250），对每段做 ARP 扫描，结束后自动删除临时地址并还原网卡配置。\n\n"
                + sourceText
                + head + "\n\n预计约 " + eta + "，期间该网卡会短暂断网。继续吗？";
            if (MessageBox.Show(this, ask, "探测直连设备", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            probeSegments = cidrs.Count;
            lastRows = new List<HostRow>();
            grid.Rows.Clear();
            logBox.Clear();
            lblCount.Text = "显示 0 台";
            running = true;
            SetBusy(true);
            bar.Style = ProgressBarStyle.Marquee;
            bar.Value = 0;
            lblStatus.Text = "直连探测中…（临时改网卡地址，请勿中断）";
            started = DateTime.Now;
            cts = new CancellationTokenSource();
            CancellationTokenSource local = cts;
            Log("直连探测：" + adapter + "，候选 " + cidrs.Count + " 个段");
            Action<string> push = delegate(string s)
            {
                if (IsDisposed) return;
                try
                {
                    if (IsHandleCreated) BeginInvoke(new MethodInvoker(delegate { Log(s); }));
                }
                catch { }
            };
            Task<List<DirectProbe.Hit>> work = Task.Run(delegate
            {
                return DirectProbe.Run(adapter, cidrs, 128, push, local.Token);
            });
            work.ContinueWith(delegate(Task<List<DirectProbe.Hit>> done)
            {
                if (IsDisposed) return;
                try { BeginInvoke(new MethodInvoker(delegate { ProbeFinished(done); })); }
                catch { }
            });
        }

        void ProbeFinished(Task<List<DirectProbe.Hit>> work)
        {
            bar.Style = ProgressBarStyle.Blocks;
            bar.Value = 0;
            running = false;
            SetBusy(false);
            if (work.IsFaulted)
            {
                string msg = work.Exception == null ? "未知错误" : work.Exception.GetBaseException().Message;
                Log("直连探测失败：" + msg);
                lblStatus.Text = "直连探测失败（临时地址已清理）";
                return;
            }
            List<DirectProbe.Hit> hits = work.Result;
            lastRows = new List<HostRow>();
            for (int i = 0; i < hits.Count; i++)
            {
                HostRow r = new HostRow();
                r.Ip = hits[i].Ip;
                r.Mac = hits[i].Mac;
                r.Vendor = hits[i].Vendor;
                r.Alive = false;
                r.ArpState = "ARP";
                r.Path = "直连探测";
                r.Role = "";
                lastRows.Add(r);
            }
            FillGrid(lastRows);
            lblStatus.Text = string.Format("直连探测完成：{0} 台 · {1} 个段 · 网卡已还原", hits.Count, probeSegments);
            if (hits.Count == 0)
            {
                Log("0 台：这些段里没有设备回应 ARP —— 设备可能不在这些段，或不在同一广播域（中间有交换机隔离/路由器）。");
                Log("可以点「整个 /16」把扫描范围设成 192.168.0.0/16 再探测一次（覆盖 256 个段，约 3 分钟）。");
            }
        }

        void btnLinkCheck_Click(object sender, EventArgs e)
        {
            if (running) return;
            string adapter = DirectProbe.DefaultAdapter();
            if (adapter == null)
            {
                MessageBox.Show(this, "没有找到已连接的有线网卡。\n\n链路体检目前只支持有线网卡（无线网卡抓到的对端 MAC 没有意义）。", "无法体检", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            bool admin = DirectProbe.IsAdministrator();
            int seconds = 30;
            string ask = "将对网卡「" + adapter + "」采样 " + seconds + " 秒，期间不改动任何网络配置。\n\n"
                + (admin ? "同时用系统自带 pktmon 抓包，能看到线上发包的对端 MAC。" : "当前不是管理员，只能看到收发了多少字节，看不到对端 MAC。建议关掉程序后右键「以管理员身份运行」。")
                + "\n\n继续吗？";
            if (MessageBox.Show(this, ask, "链路体检", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            running = true;
            SetBusy(true);
            bar.Style = ProgressBarStyle.Marquee;
            bar.Value = 0;
            lblStatus.Text = "链路体检中…（" + seconds + " 秒，不改配置）";
            started = DateTime.Now;
            cts = new CancellationTokenSource();
            CancellationTokenSource local = cts;
            Log("链路体检：" + adapter + "，采样 " + seconds + " 秒" + (admin ? " + pktmon 抓包" : "（无管理员，不抓包）"));
            Action<string> push = delegate(string s)
            {
                if (IsDisposed) return;
                try
                {
                    if (IsHandleCreated) BeginInvoke(new MethodInvoker(delegate { Log(s); }));
                }
                catch { }
            };
            Task<LinkCheck.Evidence> work = Task.Run(delegate
            {
                return LinkCheck.Run(adapter, seconds, push, local.Token);
            });
            work.ContinueWith(delegate(Task<LinkCheck.Evidence> done)
            {
                if (IsDisposed) return;
                try { BeginInvoke(new MethodInvoker(delegate { LinkCheckFinished(done); })); }
                catch { }
            });
        }

        void LinkCheckFinished(Task<LinkCheck.Evidence> work)
        {
            bar.Style = ProgressBarStyle.Blocks;
            bar.Value = 0;
            running = false;
            SetBusy(false);
            if (work.IsFaulted)
            {
                string msg = work.Exception == null ? "未知错误" : work.Exception.GetBaseException().Message;
                Log("链路体检失败：" + msg);
                lblStatus.Text = "链路体检失败";
                return;
            }
            LinkCheck.Evidence ev = work.Result;
            Log("网卡 " + ev.Adapter + "：" + ev.Status + "，" + ev.SpeedMbps + " Mbps");
            Log("接收 " + ev.RxDelta + " 字节 / " + ev.RxPacketsDelta + " 包，发送 " + ev.TxDelta + " 字节");
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("网卡：" + ev.Adapter + "（" + ev.Status + "，" + ev.SpeedMbps + " Mbps）");
            sb.AppendLine("采样：" + ev.Seconds + " 秒");
            sb.AppendLine("接收：" + ev.RxDelta + " 字节 / " + ev.RxPacketsDelta + " 个包");
            sb.AppendLine("发送：" + ev.TxDelta + " 字节");
            sb.AppendLine("抓包：" + (ev.SniffUsed ? "已用 pktmon 抓包" : "未抓包（非管理员或 pktmon 不可用）"));
            sb.AppendLine();
            if (ev.Peers.Count == 0)
            {
                sb.AppendLine("线上对端 MAC：无");
            }
            else
            {
                sb.AppendLine("线上对端 MAC（" + ev.Peers.Count + " 个）：");
                int max = Math.Min(10, ev.Peers.Count);
                for (int i = 0; i < max; i++)
                {
                    LinkCheck.Peer p = ev.Peers[i];
                    sb.AppendLine("  " + p.Mac + "  " + p.Vendor + (p.Ip.Length > 0 ? "  " + p.Ip : ""));
                    Log("对端 " + p.Mac + " " + p.Vendor + (p.Ip.Length > 0 ? " " + p.Ip : ""));
                }
                if (ev.Peers.Count > max) sb.AppendLine("  …还有 " + (ev.Peers.Count - max) + " 个");
            }
            sb.AppendLine();
            sb.AppendLine("结论：");
            sb.AppendLine(ev.Verdict);
            lblStatus.Text = ev.Peers.Count > 0
                ? string.Format("链路体检：线上 {0} 个 MAC", ev.Peers.Count)
                : (ev.RxDelta > 0 ? "链路体检：有流量但没抓到 MAC" : "链路体检：线上无帧");
            MessageBox.Show(this, sb.ToString(), "链路体检结果", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        void btnStart_Click(object sender, EventArgs e)
        {
            StartScan();
        }

        void btnExport_Click(object sender, EventArgs e)
        {
            ExportCsv();
        }

        void btnStop_Click(object sender, EventArgs e)
        {
            RequestStop();
        }

        void RequestStop()
        {
            if (cts != null)
            {
                cts.Cancel();
                Log("已请求停止…");
            }
        }

        void grid_CellMouseDown(object sender, DataGridViewCellMouseEventArgs e)
        {
            if (e.Button != MouseButtons.Right || e.RowIndex < 0) return;
            if (!grid.Rows[e.RowIndex].Selected)
            {
                grid.ClearSelection();
                grid.Rows[e.RowIndex].Selected = true;
            }
        }

        void grid_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0) return;
            object v = grid.Rows[e.RowIndex].Cells[0].Value;
            if (v == null) return;
            SetClipboard(v.ToString(), "已复制 " + v.ToString());
        }

        void grid_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            if (e.RowIndex < 0 || e.Value == null) return;
            if (txtFilter.Enabled == false) return;
            string kw = txtFilter.Text.Trim();
            if (kw.Length == 0) return;
            if (e.ColumnIndex != 0 && e.ColumnIndex != 1 && e.ColumnIndex != 4 && e.ColumnIndex != 5 && e.ColumnIndex != 9) return;
            string cell = e.Value.ToString();
            if (cell.Length == 0) return;
            int at = cell.IndexOf(kw, StringComparison.OrdinalIgnoreCase);
            if (at < 0) return;
            e.CellStyle.Font = new Font(grid.Font, FontStyle.Bold);
        }

        HostRow CurrentHost()
        {
            if (grid.CurrentRow == null) return null;
            return grid.CurrentRow.Tag as HostRow;
        }

        void menu_CopyIp(object sender, EventArgs e) { CopyField("ip"); }
        void menu_CopyMac(object sender, EventArgs e) { CopyField("mac"); }
        void menu_CopyHost(object sender, EventArgs e) { CopyField("host"); }

        void CopyField(string which)
        {
            HostRow h = CurrentHost();
            if (h == null) return;
            string v = which == "ip" ? h.Ip : (which == "mac" ? h.Mac : h.HostName);
            if (string.IsNullOrEmpty(v)) { Log("这一行没有" + (which == "mac" ? " MAC" : (which == "host" ? "主机名" : "值")) + "（跨网段设备取不到 MAC，未反查则没有主机名）"); return; }
            SetClipboard(v, "已复制 " + v);
        }

        void menu_CopyRow(object sender, EventArgs e)
        {
            HostRow h = CurrentHost();
            if (h == null) return;
            SetClipboard(RowText(h, "\t"), "已复制整行：" + h.Ip);
        }

        void menu_CopySelected(object sender, EventArgs e)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("IP\tICMP\tRTT(ms)\tTTL\tMAC\t厂商\tARP\t路径\t角色\t主机名");
            int n = 0;
            foreach (DataGridViewRow row in grid.SelectedRows)
            {
                HostRow h = row.Tag as HostRow;
                if (h == null) continue;
                sb.AppendLine(RowText(h, "\t"));
                n++;
            }
            if (n == 0) { Log("没有选中的行"); return; }
            SetClipboard(sb.ToString(), string.Format("已复制 {0} 行", n));
        }

        static string RowText(HostRow h, string sep)
        {
            return string.Join(sep, new string[] {
                h.Ip, h.Alive ? "up" : "-",
                h.Alive ? h.Rtt.ToString() : "",
                h.Alive ? h.Ttl.ToString() : "",
                h.Mac, h.Vendor, h.ArpState, h.Path, h.Role, h.HostName });
        }

        void menu_OpenBrowser(object sender, EventArgs e)
        {
            HostRow h = CurrentHost();
            if (h == null) return;
            string url = "http://" + h.Ip;
            try
            {
                Process.Start(url);
                Log("已用浏览器打开 " + url);
            }
            catch (Exception ex)
            {
                Log("打不开浏览器：" + ex.Message);
            }
        }

        void menu_OpenPing(object sender, EventArgs e)
        {
            HostRow h = CurrentHost();
            if (h == null) return;
            try
            {
                Process.Start("cmd.exe", "/k ping -t " + h.Ip);
                Log("已开新窗口持续 ping " + h.Ip);
            }
            catch (Exception ex)
            {
                Log("打开终端失败：" + ex.Message);
            }
        }

        void SetClipboard(string text, string note)
        {
            try
            {
                Clipboard.SetText(text);
                Log(note);
            }
            catch (Exception ex)
            {
                Log("复制失败（剪贴板被占用？）：" + ex.Message);
            }
        }

        bool PassFilter(HostRow h)
        {
            string kw = txtFilter.Text;
            if (kw == null) kw = "";
            kw = kw.Trim();
            if (kw.Length == 0) return true;
            string hay = (h.Ip + " " + h.Mac + " " + h.Vendor + " " + h.HostName + " " + h.Role + " " + h.Path + " " + h.ArpState).ToLowerInvariant();
            string[] parts = kw.ToLowerInvariant().Split(new char[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < parts.Length; i++)
            {
                if (hay.IndexOf(parts[i], StringComparison.Ordinal) < 0) return false;
            }
            return true;
        }

        void ApplyFilter()
        {
            if (grid == null) return;
            grid.SuspendLayout();
            int shown = 0;
            for (int i = 0; i < grid.Rows.Count; i++)
            {
                DataGridViewRow row = grid.Rows[i];
                HostRow h = row.Tag as HostRow;
                bool ok = h == null ? true : PassFilter(h);
                if (row.Visible != ok) row.Visible = ok;
                if (ok) shown++;
            }
            grid.ResumeLayout();
            lblCount.Text = string.Format("显示 {0} / 共 {1} 台", shown, grid.Rows.Count);
        }

        void grid_SortCompare(object sender, DataGridViewSortCompareEventArgs e)
        {
            if (e.Column.Index == 0)
            {
                uint a, b;
                bool ok1 = IpUtil.TryToUInt(e.CellValue1 == null ? "" : e.CellValue1.ToString(), out a);
                bool ok2 = IpUtil.TryToUInt(e.CellValue2 == null ? "" : e.CellValue2.ToString(), out b);
                if (ok1 && ok2) e.SortResult = a.CompareTo(b);
                else e.SortResult = string.Compare(e.CellValue1 == null ? "" : e.CellValue1.ToString(), e.CellValue2 == null ? "" : e.CellValue2.ToString(), StringComparison.Ordinal);
                e.Handled = true;
                return;
            }
            if (e.Column.Index == 2 || e.Column.Index == 3)
            {
                long a = ParseLong(e.CellValue1);
                long b = ParseLong(e.CellValue2);
                e.SortResult = a.CompareTo(b);
                e.Handled = true;
            }
        }

        static long ParseLong(object v)
        {
            long n;
            if (v != null && long.TryParse(v.ToString(), out n)) return n;
            return -1;
        }

        void SetGridSortable(bool on)
        {
            for (int i = 0; i < grid.Columns.Count; i++)
            {
                try
                {
                    grid.Columns[i].SortMode = on ? DataGridViewColumnSortMode.Automatic : DataGridViewColumnSortMode.NotSortable;
                }
                catch { }
            }
        }

        void uiTimer_Tick(object sender, EventArgs e)
        {
            if (engine == null) return;
            long done = Interlocked.Read(ref engine.Done);
            long total = Interlocked.Read(ref engine.Total);
            if (total <= 0) return;
            if (done > bar.Maximum) done = bar.Maximum;
            bar.Value = (int)done;
            double secs = (DateTime.Now - started).TotalSeconds;
            lblStatus.Text = string.Format("已扫 {0}/{1} · 命中 {2} 台 · {3:0.0} 秒 · {4:0} 地址/秒", done, total, grid.Rows.Count, secs, done / Math.Max(0.001, secs));
        }

        void Log(string s)
        {
            if (logBox == null) return;
            logBox.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + s + Environment.NewLine);
        }

        void SetBusy(bool busy)
        {
            running = busy;
            btnStart.Enabled = !busy;
            btnStop.Enabled = busy;
            btnExport.Enabled = !busy;
            btnLocal.Enabled = !busy;
            btnPick.Enabled = !busy;
            btnAll16.Enabled = !busy;
            btnClearRange.Enabled = !busy;
            if (btnProbe != null) btnProbe.Enabled = !busy;
            cmbRange.Enabled = !busy;
            numConc.Enabled = !busy;
            numTimeout.Enabled = !busy;
            numRetry.Enabled = !busy;
            chkArp.Enabled = !busy;
            chkDns.Enabled = !busy;
            Cursor = busy ? Cursors.AppStarting : Cursors.Default;
            SetGridSortable(!busy);
        }

        void AppendRow(HostRow r)
        {
            int idx = grid.Rows.Add(r.Ip,
                r.Alive ? "up" : "-",
                r.Alive ? r.Rtt.ToString() : "",
                r.Alive ? r.Ttl.ToString() : "",
                r.Mac,
                r.Vendor,
                r.ArpState,
                r.Path,
                r.Role,
                r.HostName);
            DataGridViewRow row = grid.Rows[idx];
            row.Tag = r;
            if (r.Role == "本机") row.DefaultCellStyle.BackColor = Color.FromArgb(234, 243, 255);
            else if (r.Role == "网关") row.DefaultCellStyle.BackColor = Color.FromArgb(255, 247, 219);
            if (!r.Alive) row.DefaultCellStyle.ForeColor = Color.FromArgb(102, 102, 102);
            row.Visible = PassFilter(r);
        }

        void AddLiveRow(HostRow r)
        {
            AppendRow(r);
            ApplyFilter();
            if (grid.Rows.Count > 0)
            {
                try { grid.FirstDisplayedScrollingRowIndex = grid.Rows.Count - 1; }
                catch { }
            }
        }

        void FillGrid(List<HostRow> rows)
        {
            grid.SuspendLayout();
            grid.Rows.Clear();
            for (int i = 0; i < rows.Count; i++) AppendRow(rows[i]);
            grid.ResumeLayout();
            ApplyFilter();
        }

        void StartScan()
        {
            if (running) return;
            string desc, err;
            List<uint> addrs = RangeParser.Parse(cmbRange.Text, out desc, out err);
            if (err != null)
            {
                MessageBox.Show(this, err + "\n\n示例：192.168.0.0/16、192.168.1.*、192.168.1.10-192.168.1.60、192.168.1.1-254", "范围写错了", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (addrs.Count > 262144)
            {
                DialogResult dr = MessageBox.Show(this, string.Format("要扫 {0} 个地址，可能要几分钟，继续吗？", addrs.Count), "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (dr != DialogResult.Yes) return;
            }

            ScanOptions o = new ScanOptions();
            o.Concurrency = (int)numConc.Value;
            o.TimeoutMs = (int)numTimeout.Value;
            o.RetryRounds = (int)numRetry.Value;
            o.UseArp = chkArp.Checked;
            o.ResolveDns = chkDns.Checked;

            lastRows = new List<HostRow>();
            grid.Rows.Clear();
            logBox.Clear();
            lblCount.Text = "显示 0 台";
            net.Load();
            engine = new Engine(net);
            cts = new CancellationTokenSource();
            started = DateTime.Now;
            bar.Maximum = Math.Max(1, addrs.Count);
            bar.Value = 0;
            SetBusy(true);
            uiTimer.Start();
            prefs.PushRecent(cmbRange.Text);
            SyncComboItems();

            Log("范围：" + desc);
            Log("并发 " + o.Concurrency + "，超时 " + o.TimeoutMs + "ms" + (o.UseArp ? "，ARP 已启用" : "") + (o.ResolveDns ? "，反查主机名" : ""));

            Action<HostRow> onFound = delegate(HostRow r)
            {
                if (IsDisposed) return;
                try { BeginInvoke(new Action<HostRow>(AddLiveRow), new object[] { r }); }
                catch { }
            };
            Action<string> logAction = delegate(string s)
            {
                if (IsDisposed) return;
                try { BeginInvoke(new Action<string>(Log), new object[] { s }); }
                catch { }
            };

            CancellationToken token = cts.Token;
            Task.Run(async delegate
            {
                List<HostRow> rows = null;
                Exception failure = null;
                try
                {
                    rows = await engine.RunFull(addrs, o, logAction, onFound, token).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    failure = ex;
                }
                if (IsDisposed) return;
                try
                {
                    BeginInvoke(new Action(delegate
                    {
                        uiTimer.Stop();
                        SetBusy(false);
                        if (failure != null)
                        {
                            Log("出错：" + failure.Message);
                            MessageBox.Show(this, failure.ToString(), "扫描出错", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }
                        FillGrid(rows);
                        lastRows = rows;
                        double secs = (DateTime.Now - started).TotalSeconds;
                        long icmp = 0;
                        for (int i = 0; i < rows.Count; i++) if (rows[i].Alive) icmp++;
                        bar.Value = bar.Maximum;
                        lblStatus.Text = string.Format("合计 {0} 台（ICMP {1} + 仅 ARP {2}）· {3} 地址 · {4:0.0} 秒 · {5:0} 地址/秒",
                            rows.Count, icmp, rows.Count - icmp, addrs.Count, secs, addrs.Count / Math.Max(0.001, secs));
                        Log(lblStatus.Text);
                        if (rows.Count == 0)
                        {
                            Log("一台都没扫到。排查顺序：1) 网线/网卡是否 Up；2) 目标是否与本机同二层（看“路径”列）；3) 设备是否禁 ICMP（保持 ARP 勾选）；4) 跨网段被 VLAN 隔离时需登录交换机看 MAC 表。");
                        }
                        SignalDone();
                    }));
                }
                catch { }
            });
        }

        void SyncComboItems()
        {
            string cur = cmbRange.Text;
            cmbRange.Items.Clear();
            for (int i = 0; i < prefs.RecentRanges.Count; i++) cmbRange.Items.Add(prefs.RecentRanges[i]);
            cmbRange.Text = cur;
        }

        void SignalDone()
        {
            try { System.Media.SystemSounds.Asterisk.Play(); }
            catch { }
            try
            {
                if (GetForegroundWindow() != Handle)
                {
                    FLASHWINFO fi = new FLASHWINFO();
                    fi.cbSize = Marshal.SizeOf(typeof(FLASHWINFO));
                    fi.hwnd = Handle;
                    fi.dwFlags = 0x00000003 | 0x0000000C;
                    fi.uCount = 3;
                    fi.dwTimeout = 0;
                    FlashWindowEx(ref fi);
                }
            }
            catch { }
        }

        void ExportCsv()
        {
            List<HostRow> rows = lastRows;
            if (rows == null || rows.Count == 0)
            {
                MessageBox.Show(this, "还没有扫描结果可导出。先点“开始扫描”。", "无数据", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            SaveFileDialog dlg = new SaveFileDialog();
            dlg.Filter = "CSV 文件|*.csv";
            dlg.FileName = "lan-hosts-" + DateTime.Now.ToString("yyyyMMdd-HHmm") + ".csv";
            if (prefs.LastExportDir != null && prefs.LastExportDir.Length > 0 && Directory.Exists(prefs.LastExportDir))
            {
                dlg.InitialDirectory = prefs.LastExportDir;
            }
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            try
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("\"IP\",\"ICMP\",\"RTT_ms\",\"TTL\",\"MAC\",\"厂商\",\"ARP\",\"路径\",\"角色\",\"主机名\"");
                for (int i = 0; i < rows.Count; i++)
                {
                    HostRow r = rows[i];
                    sb.AppendLine(string.Join(",", new string[] {
                        Q(r.Ip), Q(r.Alive ? "up" : "-"),
                        Q(r.Alive ? r.Rtt.ToString() : ""),
                        Q(r.Alive ? r.Ttl.ToString() : ""),
                        Q(r.Mac), Q(r.Vendor), Q(r.ArpState), Q(r.Path), Q(r.Role), Q(r.HostName) }));
                }
                File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(true));
                try { prefs.LastExportDir = Path.GetDirectoryName(dlg.FileName); }
                catch { }
                Log("已导出：" + dlg.FileName);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "导出失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        static string Q(string s)
        {
            if (s == null) s = "";
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        }
    }

    static class UiShot
    {
        public static void Capture(Form f, string path)
        {
            try
            {
                f.Refresh();
                Application.DoEvents();
                using (Bitmap bmp = new Bitmap(f.Width, f.Height))
                {
                    f.DrawToBitmap(bmp, new Rectangle(0, 0, f.Width, f.Height));
                    bmp.Save(path, System.Drawing.Imaging.ImageFormat.Png);
                }
            }
            catch (Exception ex)
            {
                try { File.WriteAllText(path + ".err.txt", ex.ToString()); } catch { }
            }
        }
    }

    static class Program
    {
        [DllImport("user32.dll")]
        static extern bool SetProcessDPIAware();

        [STAThread]
        static void Main(string[] args)
        {
            if (args.Length > 0 && (args[0] == "--rangetest" || args[0] == "/rangetest"))
            {
                StringBuilder sb = new StringBuilder();
                string[] cases = new string[] {
                    "", "192.168.0.0/16", "192.168.0.0/24,192.168.1.0/24",
                    "192.168.0.0/24\uFF0C192.168.1.0/24", "192.168.1.300",
                    "192.168.1.1-254", "10.0.0.0/8", "192.168.1.*" };
                for (int i = 0; i < cases.Length; i++)
                {
                    bool bad;
                    string err;
                    string plan = RangePlan.Describe(cases[i], 512, out bad, out err);
                    sb.AppendLine("[" + cases[i] + "] bad=" + bad + " plan=" + plan + " err=" + err);
                }
                File.WriteAllText(Path.Combine(Path.GetTempPath(), "LanScanner-rangetest.txt"), sb.ToString(), new UTF8Encoding(true));
                Environment.Exit(0);
            }
            if (args.Length > 0 && (args[0] == "--probe-direct" || args[0] == "/probe-direct"))
            {
                try
                {
                    RunProbeDirect(args);
                }
                catch (Exception ex)
                {
                    try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "LanScanner-probe-direct.txt"), "ERROR=" + ex.ToString(), new UTF8Encoding(true)); }
                    catch { }
                    Environment.Exit(2);
                }
                return;
            }
            if (args.Length > 0 && (args[0] == "--linkcheck" || args[0] == "/linkcheck"))
            {
                try
                {
                    RunLinkCheck(args);
                }
                catch (Exception ex)
                {
                    try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "LanScanner-linkcheck.txt"), "ERROR=" + ex.ToString(), new UTF8Encoding(true)); }
                    catch { }
                    Environment.Exit(2);
                }
                return;
            }
            if (args.Length > 0 && (args[0] == "--selftest" || args[0] == "/selftest"))
            {
                try
                {
                    RunSelfTest(args);
                }
                catch (Exception ex)
                {
                    try
                    {
                        Console.Error.WriteLine("SELFTEST FAILED: " + ex);
                        Console.Error.Flush();
                        File.WriteAllText(Path.Combine(Path.GetTempPath(), "LanScanner-selftest-error.txt"), ex.ToString(), new UTF8Encoding(false));
                    }
                    catch { }
                    Environment.Exit(2);
                }
                return;
            }
            try { SetProcessDPIAware(); }
            catch { }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            if (args.Length > 0 && (args[0] == "--shot" || args[0] == "--shotpick"))
            {
                string shotPath = args.Length > 1 ? args[1] : Path.Combine(Path.GetTempPath(), "lanscanner-shot.png");
                if (args[0] == "--shotpick")
                {
                    try
                    {
                    NetInfo info = new NetInfo();
                    info.Load();
                    List<string> gws = new List<string>();
                    for (int i = 0; i < info.Gateways.Count; i++) gws.Add(info.Gateways[i]);
                    using (RangePickerForm f = new RangePickerForm(info.Subnets, gws, "192.168.0.0/24"))
                    {
                        f.Show();
                        Application.DoEvents();
                        UiShot.Capture(f, shotPath);
                        f.Close();
                    }
                    }
                    catch (Exception ex)
                    {
                        try { File.WriteAllText(shotPath + ".err.txt", ex.ToString()); } catch { }
                    }
                }
                else
                {
                    MainForm mf = new MainForm(new string[0]);
                    mf.ShotPath = shotPath;
                    mf.ShotRange = args.Length > 2 ? args[2] : "192.168.0.0/24,192.168.1.0/24,10.36.8.0/22";
                    mf.ShotStatus = args.Length > 3 ? args[3] : "扫描完成：共 14 台设备（ICMP 13 + 仅 ARP 1）· 65534 地址 · 68.7 秒 · 954 地址/秒";
                    if (args.Length > 4)
                    {
                        string[] wh = args[4].Split('x');
                        int sw, sh;
                        if (wh.Length == 2 && int.TryParse(wh[0], out sw) && int.TryParse(wh[1], out sh) && sw > 400 && sh > 300)
                        {
                            mf.ShotClientW = sw;
                            mf.ShotClientH = sh;
                        }
                    }
                    Application.Run(mf);
                }
                Environment.Exit(0);
            }
            try
            {
                Application.Run(new MainForm(args));
            }
            catch (Exception ex)
            {
                try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "LanScanner-crash.txt"), ex.ToString()); }
                catch { }
                MessageBox.Show(ex.ToString(), "局域网设备扫描器 崩溃", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        static string ProgressPath
        {
            get { return Path.Combine(Path.GetTempPath(), "LanScanner-selftest-progress.txt"); }
        }

        static void Mark(string s)
        {
            try
            {
                File.AppendAllText(ProgressPath, DateTime.Now.ToString("HH:mm:ss.fff") + " " + s + Environment.NewLine, new UTF8Encoding(false));
            }
            catch { }
        }

        static void RunProbeDirect(string[] args)
        {
            StringBuilder sb = new StringBuilder();
            bool hasAdapter = args.Length > 1 && !args[1].StartsWith("--");
            string adapter = hasAdapter ? args[1] : DirectProbe.DefaultAdapter();
            string preset = null;
            string cidrArg = null;
            for (int i = hasAdapter ? 2 : 1; i < args.Length; i++)
            {
                if (args[i] == "--preset" && i + 1 < args.Length)
                {
                    preset = args[i + 1];
                    i++;
                }
                else if (!args[i].StartsWith("--") && cidrArg == null)
                {
                    cidrArg = args[i];
                }
            }
            if (preset != null && cidrArg != null)
            {
                sb.AppendLine("ERROR=--preset 不能和显式网段同时给");
                File.WriteAllText(Path.Combine(Path.GetTempPath(), "LanScanner-probe-direct.txt"), sb.ToString(), new UTF8Encoding(true));
                Environment.Exit(2);
            }
            List<string> cidrs = new List<string>();
            if (preset != null)
            {
                cidrs.AddRange(ProbePresets.ForPreset(preset, null));
                sb.AppendLine("PRESET=" + ProbePresets.Label(preset));
            }
            else if (cidrArg != null && cidrArg.Length > 0)
            {
                string[] parts = cidrArg.Split(',');
                for (int i = 0; i < parts.Length; i++)
                {
                    if (parts[i].Trim().Length > 0) cidrs.Add(parts[i].Trim());
                }
            }
            else
            {
                cidrs.AddRange(DirectProbe.DefaultCandidates());
            }
            sb.AppendLine("ADAPTER=" + (adapter == null ? "(none)" : adapter));
            sb.AppendLine("ADMIN=" + DirectProbe.IsAdministrator());
            sb.AppendLine("SEGMENT_COUNT=" + cidrs.Count);
            sb.AppendLine("SEGMENTS=" + string.Join(",", cidrs.GetRange(0, Math.Min(8, cidrs.Count)).ToArray()) + (cidrs.Count > 8 ? ",..." : ""));
            if (adapter == null)
            {
                sb.AppendLine("ERROR=no wired adapter up");
            }
            else
            {
                DateTime t0 = DateTime.Now;
                List<DirectProbe.Hit> hits = DirectProbe.Run(adapter, cidrs, 128,
                    delegate(string s) { sb.AppendLine("LOG " + s); }, CancellationToken.None);
                sb.AppendLine("ELAPSED=" + (int)(DateTime.Now - t0).TotalSeconds);
                sb.AppendLine("COUNT=" + hits.Count);
                for (int i = 0; i < hits.Count; i++)
                {
                    sb.AppendLine(string.Join("\t", new string[] { hits[i].Ip, hits[i].Mac, hits[i].Vendor, hits[i].Segment }));
                }
                NetInfo info = new NetInfo();
                info.Load();
                sb.AppendLine("AFTER=" + info.CidrList());
            }
            File.WriteAllText(Path.Combine(Path.GetTempPath(), "LanScanner-probe-direct.txt"), sb.ToString(), new UTF8Encoding(true));
            Environment.Exit(0);
        }

        static void RunLinkCheck(string[] args)
        {
            string adapter = args.Length > 1 && args[1].Length > 0 ? args[1] : DirectProbe.DefaultAdapter();
            int seconds = 10;
            if (args.Length > 2)
            {
                int v;
                if (int.TryParse(args[2], out v) && v >= 3) seconds = v;
            }
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("ADAPTER=" + (adapter == null ? "(none)" : adapter));
            sb.AppendLine("ADMIN=" + DirectProbe.IsAdministrator());
            LinkCheck.Evidence ev = LinkCheck.Run(adapter, seconds,
                delegate(string s) { sb.AppendLine("LOG " + s); }, CancellationToken.None);
            sb.AppendLine("STATUS=" + ev.Status);
            sb.AppendLine("SPEED=" + ev.SpeedMbps);
            sb.AppendLine("SECONDS=" + ev.Seconds);
            sb.AppendLine("RX0=" + ev.RxBytes0);
            sb.AppendLine("RX1=" + ev.RxBytes1);
            sb.AppendLine("RXDELTA=" + ev.RxDelta);
            sb.AppendLine("RXPACKETS=" + ev.RxPacketsDelta);
            sb.AppendLine("TXDELTA=" + ev.TxDelta);
            sb.AppendLine("SNIFF=" + ev.SniffUsed);
            sb.AppendLine("COUNT=" + ev.Peers.Count);
            for (int i = 0; i < ev.Peers.Count; i++)
            {
                sb.AppendLine("PEERS=" + ev.Peers[i].Mac + "\t" + ev.Peers[i].Vendor + "\t" + ev.Peers[i].Ip);
            }
            sb.AppendLine("VERDICT=" + ev.Verdict.Replace("\r\n", " ").Replace("\n", " "));
            File.WriteAllText(Path.Combine(Path.GetTempPath(), "LanScanner-linkcheck.txt"), sb.ToString(), new UTF8Encoding(true));
            Environment.Exit(0);
        }

        static void RunSelfTest(string[] args)
        {
            try { File.Delete(ProgressPath); }
            catch { }
            Mark("start args=" + string.Join(" ", args));
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("OUI-52:54:00:12:34:56=" + Oui.Lookup("52:54:00:12:34:56"));
            sb.AppendLine("OUI-B8:27:EB:12:34:56=" + Oui.Lookup("B8:27:EB:12:34:56"));
            sb.AppendLine("OUI-5E:7A:2B:C1:13:0D=" + Oui.Lookup("5E:7A:2B:C1:13:0D"));
            sb.AppendLine("OUI-AA:BB:CC:DD:EE:FF=" + Oui.Lookup("AA:BB:CC:DD:EE:FF"));
            sb.AppendLine("OUI-empty=" + Oui.Lookup(""));

            string text = args.Length > 1 ? args[1] : "127.0.0.1";
            if (text == "--arpdump")
            {
                List<string> dump = NativeArp.DumpRaw(14);
                for (int i = 0; i < dump.Count; i++) sb.AppendLine(dump[i]);
                Mark("arpdump done");
                File.WriteAllText(Path.Combine(Path.GetTempPath(), "LanScanner-selftest.txt"), sb.ToString(), new UTF8Encoding(true));
                Environment.Exit(0);
            }
            Mark("parsing " + text);
            string desc, err;
            List<uint> addrs = RangeParser.Parse(text, out desc, out err);
            Mark("parsed count=" + addrs.Count + " err=" + (err == null ? "none" : err));
            if (err != null)
            {
                sb.AppendLine("ERROR=" + err);
            }
            else
            {
                sb.AppendLine("DESC=" + desc);
                sb.AppendLine("COUNT=" + addrs.Count);
                NetInfo info = new NetInfo();
                Mark("netLoad begin");
                info.Load();
                Mark("netLoad done subnets=" + info.CidrList());
                sb.AppendLine("SUBNETS=" + info.CidrList());
                ScanOptions o = new ScanOptions();
                o.Concurrency = args.Length > 2 ? int.Parse(args[2]) : 512;
                o.TimeoutMs = args.Length > 3 ? int.Parse(args[3]) : 300;
                o.UseArp = true;
                Engine eng = new Engine(info);
                Mark("runFull begin count=" + addrs.Count);
                List<HostRow> rows = eng.RunFull(addrs, o,
                    delegate(string s) { Mark("eng: " + s); sb.AppendLine("LOG " + s); }, null, CancellationToken.None).GetAwaiter().GetResult();
                Mark("runFull done rows=" + rows.Count);
                sb.AppendLine("ROWS=" + rows.Count);
                for (int i = 0; i < rows.Count; i++)
                {
                    HostRow r = rows[i];
                    sb.AppendLine(string.Join("\t", new string[] { r.Ip, r.Alive ? "up" : "-", r.Rtt.ToString(), r.Ttl.ToString(), r.Mac, r.Vendor, r.ArpState, r.Path, r.Role, r.HostName }));
                }
            }
            Mark("writing result");
            File.WriteAllText(Path.Combine(Path.GetTempPath(), "LanScanner-selftest.txt"), sb.ToString(), new UTF8Encoding(true));
            Mark("done");
            Environment.Exit(0);
        }
    }

    // 直连探测的段来源选择框
    public class ProbeScopeForm : Form
    {
        public string Preset = "range";

        public ProbeScopeForm(string rangeText)
        {
            Text = "选择探测范围";
            Font = new Font("Microsoft YaHei UI", 9F);
            ClientSize = new Size(540, 236);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;

            int nRange = 0;
            try { nRange = DirectProbe.SegmentsFromRange(rangeText).Count; }
            catch { }

            Label tip = new Label();
            tip.Text = "「直连探测」要临时给网卡加同段地址再发 ARP，先选要扫哪些段：";
            tip.SetBounds(14, 12, 512, 20);
            Controls.Add(tip);

            RadioButton rbRange = NewRadio("扫描范围（" + (nRange > 0 ? nRange + " 段" : "未填写，改用默认 12 段") + "）", 14, 40, 512);
            RadioButton rb16 = NewRadio("192.168.x 全段（256 段，约 3 分钟）", 14, 72, 512);
            RadioButton rbCommon = NewRadio("常见私有段（1280 段，含 10.x / 172.16.x / 169.254.x，约 16 分钟）", 14, 104, 512);
            if (nRange > 0) rbRange.Checked = true;
            else rb16.Checked = true;

            Label warn = new Label();
            warn.Text = "探测期间该网卡会短暂断网，结束后自动还原配置。";
            warn.ForeColor = Color.DimGray;
            warn.SetBounds(14, 140, 512, 20);
            Controls.Add(warn);

            Button ok = new Button();
            ok.Text = "开始探测";
            ok.SetBounds(320, 176, 96, 28);
            ok.DialogResult = DialogResult.OK;
            Controls.Add(ok);

            Button cancel = new Button();
            cancel.Text = "取消";
            cancel.SetBounds(426, 176, 96, 28);
            cancel.DialogResult = DialogResult.Cancel;
            Controls.Add(cancel);

            AcceptButton = ok;
            CancelButton = cancel;

            rbRange.CheckedChanged += new EventHandler(OnRadio);
            rb16.CheckedChanged += new EventHandler(OnRadio);
            rbCommon.CheckedChanged += new EventHandler(OnRadio);
        }

        RadioButton NewRadio(string text, int x, int y, int w)
        {
            RadioButton rb = new RadioButton();
            rb.Text = text;
            rb.AutoSize = false;
            rb.SetBounds(x, y, w, 26);
            Controls.Add(rb);
            return rb;
        }

        void OnRadio(object sender, EventArgs e)
        {
            RadioButton rb = sender as RadioButton;
            if (rb == null || !rb.Checked) return;
            if (rb.Text.StartsWith("扫描范围")) Preset = ProbePresets.Range;
            else if (rb.Text.StartsWith("192.168")) Preset = ProbePresets.All16;
            else Preset = ProbePresets.CommonSeg;
        }
    }
}
