using ProxiFyre.Configuration;
using ProxiFyreUI.Infrastructure;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace ProxiFyreUI.Forms
{
    internal sealed class DomainRuleEditorForm : Form
    {
        private readonly TextBox exact = new TextBox { Name = "domainsTextBox", Multiline = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Vertical };
        private readonly TextBox suffix = new TextBox { Name = "domainSuffixesTextBox", Multiline = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Vertical };
        private readonly Label validation = new Label { Dock = DockStyle.Fill, AutoEllipsis = true };
        public List<string> Domains { get; private set; }
        public List<string> DomainSuffixes { get; private set; }

        public DomainRuleEditorForm(IList<string> domains, IList<string> suffixes)
        {
            Text = "Domain conditions";
            Font = WinFormsFontBootstrap.CreateUiFont("Segoe UI", 9F);
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            ClientSize = new Size(620, 450);
            MinimumSize = new Size(480, 400);
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            exact.Text = string.Join(Environment.NewLine, domains ?? new List<string>());
            suffix.Text = string.Join(Environment.NewLine, suffixes ?? new List<string>());
            var grid = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), ColumnCount = 1, RowCount = 7 };
            grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            grid.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            grid.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 54));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
            grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
            grid.Controls.Add(new Label { Text = "Exact domains (one per line)", AutoSize = true }, 0, 0);
            grid.Controls.Add(exact, 0, 1);
            grid.Controls.Add(new Label { Text = "Domain suffixes (root and subdomains, one per line)", AutoSize = true }, 0, 2);
            grid.Controls.Add(suffix, 0, 3);
            grid.Controls.Add(new Label { Dock = DockStyle.Fill, Text = "Both lists empty: all destinations. Otherwise either list can match. Domains are learned from observed DNS; put domain rules before fallback rules." }, 0, 4);
            grid.Controls.Add(validation, 0, 5);
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft };
            var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
            var ok = new Button { Text = "OK", AutoSize = true };
            buttons.Controls.Add(cancel); buttons.Controls.Add(ok); grid.Controls.Add(buttons, 0, 6);
            Controls.Add(grid); AcceptButton = ok; CancelButton = cancel;
            ok.Click += (sender, args) =>
            {
                var rule = new ProxyRule { Socks5ProxyEndpoint = "127.0.0.1:1080", AppNames = new List<string> { "" },
                    Domains = Read(exact.Text), DomainSuffixes = Read(suffix.Text) };
                var errors = new ConfigurationValidator().ValidateRule(rule).Issues
                    .Where(issue => issue.Severity == ValidationSeverity.Error).ToArray();
                validation.Text = string.Join("; ", errors.Select(issue => issue.Message));
                if (errors.Length > 0) return;
                Domains = DomainRules.Normalize(rule.Domains, false);
                DomainSuffixes = DomainRules.Normalize(rule.DomainSuffixes, true);
                DialogResult = DialogResult.OK;
            };
        }

        private static List<string> Read(string text)
        {
            return string.IsNullOrWhiteSpace(text) ? new List<string>() : text.Replace("\r", "").Split('\n').Select(line => line.Trim()).ToList();
        }
    }
}
