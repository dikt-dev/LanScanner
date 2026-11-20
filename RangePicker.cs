using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace LanScanner
{
    // 网段选择对话框：把本机检测到的网段列成可勾选清单，另支持手动添加一段。
    public class RangePickerForm : Form
    {
        class Item
        {
            public string Cidr;
            public long Count;
            public bool LinkLocal;
        }

        CheckedListBox lst;
        TextBox txtManual;
        Label lblPreview;
        Label lblEmpty;
        Button btnOk;
        List<Item> items = new List<Item>();

        public string ResultText = "";

        public RangePickerForm(IList<Subnet> subnets, List<string> gateways, string currentText)
        {
            Text = "选择要扫描的网段";
            Font = new Font("Microsoft YaHei UI", 9F);
            ClientSize = new Size(660, 470);
            MinimumSize = new Size(560, 380);
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = false;
            MinimizeBox = false;

            Label lblTip = new Label();
            lblTip.Text = "勾选要扫描的网段（可多选）。列表里是本机网卡当前所在的网段：";
            lblTip.SetBounds(14, 12, 620, 20);
            Controls.Add(lblTip);

            lst = new CheckedListBox();
            lst.SetBounds(14, 36, 632, 268);
            lst.CheckOnClick = true;
            lst.HorizontalScrollbar = true;
            lst.IntegralHeight = false;
            lst.ItemCheck += new ItemCheckEventHandler(lst_ItemCheck);
            Controls.Add(lst);

            lblEmpty = new Label();
            lblEmpty.Text = "未检测到本机网段，请在下面手动添加要扫描的网段。";
            lblEmpty.ForeColor = Color.DimGray;
            lblEmpty.SetBounds(20, 40, 600, 20);
            lblEmpty.Visible = false;
            Controls.Add(lblEmpty);

            Button btnAll = new Button();
            btnAll.Text = "全选";
            btnAll.SetBounds(14, 312, 64, 26);
            btnAll.Click += new EventHandler(btnAll_Click);
            Controls.Add(btnAll);

            Button btnNone = new Button();
            btnNone.Text = "全不选";
            btnNone.SetBounds(84, 312, 70, 26);
            btnNone.Click += new EventHandler(btnNone_Click);
            Controls.Add(btnNone);

            GroupBox gb = new GroupBox();
            gb.Text = "手动添加一段";
            gb.SetBounds(14, 346, 632, 60);
            Controls.Add(gb);

            txtManual = new TextBox();
            txtManual.SetBounds(12, 24, 520, 24);
            txtManual.Text = "192.168.0.0/24";
            gb.Controls.Add(txtManual);

            Button btnAdd = new Button();
            btnAdd.Text = "添加";
            btnAdd.SetBounds(542, 23, 74, 26);
            btnAdd.Click += new EventHandler(btnAdd_Click);
            gb.Controls.Add(btnAdd);

            lblPreview = new Label();
            lblPreview.SetBounds(14, 414, 430, 20);
            lblPreview.ForeColor = Color.DimGray;
            Controls.Add(lblPreview);

            btnOk = new Button();
            btnOk.Text = "确定";
            btnOk.SetBounds(452, 412, 90, 28);
            btnOk.Click += new EventHandler(btnOk_Click);
            Controls.Add(btnOk);
            AcceptButton = btnOk;

            Button btnCancel = new Button();
            btnCancel.Text = "取消";
            btnCancel.SetBounds(550, 412, 90, 28);
            btnCancel.DialogResult = DialogResult.Cancel;
            Controls.Add(btnCancel);
            CancelButton = btnCancel;

            FillSubnets(subnets, gateways);
            SelectFromText(currentText);
            UpdatePreview();
        }

        void FillSubnets(IList<Subnet> subnets, List<string> gateways)
        {
            if (subnets == null || subnets.Count == 0)
            {
                lblEmpty.Visible = true;
                return;
            }
            for (int i = 0; i < subnets.Count; i++)
            {
                Subnet s = subnets[i];
                long count = (long)s.Size - 2;
                if (count < 1) count = 1;
                bool linkLocal = ((s.Net >> 16) == 0xA9FE);
                Item it = new Item();
                it.Cidr = IpUtil.FromUInt(s.Net) + "/" + s.Prefix;
                it.Count = count;
                it.LinkLocal = linkLocal;

                string gw = "";
                for (int g = 0; g < gateways.Count; g++)
                {
                    uint gv;
                    if (!IpUtil.TryToUInt(gateways[g], out gv)) continue;
                    if ((gv & s.Mask) == s.Net) { gw = gateways[g]; break; }
                }

                string text = it.Cidr + "    本机 " + s.LocalIp;
                if (gw.Length > 0) text += "    网关 " + gw;
                if (s.Alias != null && s.Alias.Length > 0) text += "    [" + s.Alias + "]";
                text += "    " + count + " 个地址";
                if (linkLocal) text += "    （自动地址，通常不用扫）";

                items.Add(it);
                int idx = lst.Items.Add(text);
                lst.SetItemChecked(idx, !linkLocal);
            }
        }

        void SelectFromText(string currentText)
        {
            if (currentText == null) return;
            string[] parts = currentText.Replace("\uFF0C", ",").Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) return;
            bool matched = false;
            for (int p = 0; p < parts.Length; p++)
            {
                for (int i = 0; i < items.Count; i++)
                {
                    if (string.Equals(items[i].Cidr, parts[p].Trim(), StringComparison.OrdinalIgnoreCase)) matched = true;
                }
            }
            if (!matched) return;
            for (int i = 0; i < items.Count; i++)
            {
                bool on = false;
                for (int p = 0; p < parts.Length; p++)
                {
                    if (string.Equals(items[i].Cidr, parts[p].Trim(), StringComparison.OrdinalIgnoreCase)) { on = true; break; }
                }
                lst.SetItemChecked(i, on);
            }
        }

        void lst_ItemCheck(object sender, ItemCheckEventArgs e)
        {
            // 构造期间（句柄还没建）填充勾选状态也会走到这里，此时不能 BeginInvoke
            if (!IsHandleCreated) return;
            BeginInvoke(new MethodInvoker(UpdatePreview));
        }

        void btnAll_Click(object sender, EventArgs e)
        {
            for (int i = 0; i < lst.Items.Count; i++) lst.SetItemChecked(i, true);
            UpdatePreview();
        }

        void btnNone_Click(object sender, EventArgs e)
        {
            for (int i = 0; i < lst.Items.Count; i++) lst.SetItemChecked(i, false);
            UpdatePreview();
        }

        void btnAdd_Click(object sender, EventArgs e)
        {
            string text = txtManual.Text.Trim();
            if (text.Length == 0) return;
            string desc, err;
            List<uint> addrs = RangeParser.Parse(text, out desc, out err);
            if (err != null)
            {
                MessageBox.Show(this, "格式有误：" + err, "无法添加", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (addrs.Count > 65536)
            {
                MessageBox.Show(this, "这一段有 " + addrs.Count + " 个地址，太大了。请先缩到 /16（65534 个地址）以内。",
                    "范围太大", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            Item it = new Item();
            it.Cidr = text;
            it.Count = addrs.Count;
            items.Add(it);
            int idx = lst.Items.Add(it.Cidr + "    （手动添加）    " + addrs.Count + " 个地址");
            lst.SetItemChecked(idx, true);
            UpdatePreview();
        }

        List<int> CheckedIndexes()
        {
            List<int> ids = new List<int>();
            for (int i = 0; i < lst.Items.Count; i++) if (lst.GetItemChecked(i)) ids.Add(i);
            return ids;
        }

        void UpdatePreview()
        {
            List<int> ids = CheckedIndexes();
            if (ids.Count == 0)
            {
                lblPreview.Text = "还没有选择网段";
                btnOk.Enabled = false;
                return;
            }
            long total = 0;
            for (int i = 0; i < ids.Count; i++)
            {
                int idx = ids[i];
                if (idx < items.Count) total += items[idx].Count;
            }
            double sec = Math.Ceiling(total / (512.0 * 1.8));
            if (sec < 1) sec = 1;
            lblPreview.Text = string.Format("{0} 段 · {1} 个地址 · 按 512 并发预计约 {2} 秒", ids.Count, total, (long)sec);
            btnOk.Enabled = true;
        }

        void btnOk_Click(object sender, EventArgs e)
        {
            List<int> ids = CheckedIndexes();
            List<string> parts = new List<string>();
            for (int i = 0; i < ids.Count; i++)
            {
                int idx = ids[i];
                if (idx < items.Count) parts.Add(items[idx].Cidr);
            }
            if (parts.Count == 0) return;
            ResultText = string.Join(",", parts.ToArray());
            DialogResult = DialogResult.OK;
            Close();
        }
    }
}
