using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using NetFwTypeLib;
using System.Net;
using System.Security.Permissions;
using System.Diagnostics;

namespace ClipMon
{
    class FwOutRule
    {
        public FwOutRule() { Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT; Enabled = true; }

        public FwOutRule(INetFwRule fwRule)
            : this()
        {
            Action = fwRule.Action;
            ApplicationName = fwRule.ApplicationName;
            Description = fwRule.Description;
            Enabled = fwRule.Enabled;
            Name = fwRule.Name;
            RemoteAddresses = fwRule.RemoteAddresses;
            Enabled = true;
        }

        public FwOutRule(FwOutRule rule)
            : this()
        {
            Action = rule.Action;
            ApplicationName = rule.ApplicationName;
            Description = rule.Description;
            Enabled = rule.Enabled;
            Name = rule.Name;
            RemoteAddresses = rule.RemoteAddresses;
            Enabled = true;
        }

        public FwOutRule(IPAddress addr)
            : this()
        {
            Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
            Description = string.Format("{0} Used to block an IP [{1}] since {2}",
                Program.AppName, addr.ToString(), DateTime.UtcNow);
            Name = string.Format("{0} Used to block an IP [{1}]",
                Program.AppName, addr.ToString());
            RemoteAddresses = addr.ToString();
            Enabled = true;
        }

        public NET_FW_ACTION_ Action { get; set; }
        public NET_FW_RULE_DIRECTION_ Direction { get; internal set; }
        public string ApplicationName { get; set; }
        public string Description { get; set; }
        public bool Enabled { get; set; }
        public string Name { get; set; }
        public string RemoteAddresses { get; set; }

        public IPAddress IP
        {
            get
            {
                IPAddress res = null;
                IPAddress.TryParse(RemoteAddresses.Split('/')[0], out res);
                return res;
            }
        }

        public string SubNet
        {
            get
            {
                if (IP != null)
                {
                    var ipp = IP.ToString().Split('.');
                    return string.Format("{0}.{1}.{2}.", ipp[0], ipp[1], ipp[2]);
                }
                return null;
            }
        }

        public bool IsIPRule
        {
            get
            {
                return !RemoteAddresses.EndsWith(".0/255.255.255.0");
            }
        }
    }

    class TL
    {
        StreamWriter wr;
        public TL(string logFileName)
        {
            var fs = File.Open("clip.txt", FileMode.Append);
            wr = new StreamWriter(fs);
        }

        public void WI(string line)
        {
            var text = string.Format("[{0}] {1}.", DateTime.UtcNow, line);
            Console.WriteLine(text);
            wr.WriteLine(text);
            wr.Flush();
            Trace.TraceInformation(text);
            Trace.Flush();
        }
    }

    class Program
    {
        public static string AppName { get { return "[ClipMon]"; } }
        static List<FwOutRule> outRules = new List<FwOutRule>();
        static TL log = new TL("clip.txt");

        [STAThread]
        static void Main(string[] args)
        {
            log.WI("New session started");
            log.WI("Started load existing OUT rules");

            LoadOutRules();

            // try to create subnet rules
            var tmpRules = outRules.ToList();
            foreach (var rule in tmpRules)
            {
                MakeSubNetRules(rule);
            }

            log.WI(string.Format("{0} OUT rules loaded", outRules.Count));

            var lastText = "";
            while (true)
            {
                if (Clipboard.ContainsText())
                {
                    var text = Clipboard.GetText(TextDataFormat.Text);

                    if (text != lastText)
                    {
                        MakeOutRule(text);
                    }

                    lastText = text;
                }
                Thread.Sleep(100);
            }

        }

        static void MakeOutRule(string text)
        {
            if (text.StartsWith("http://")) text = text.Replace("http://", "");
            if (text.StartsWith("https://")) text = text.Replace("https://", "");

            IPAddress addr = null;
            if (!IPAddress.TryParse(text, out addr)) return;

            FwOutRule rule = new FwOutRule(addr);

            if (CheckRule(rule))
            {
                if (!MakeSubNetRules(rule))
                {
                    log.WI("Adding new rule for IP [" + rule.RemoteAddresses + "]");
                    AddFwRule(rule);
                    outRules.Add(rule);
                }
            }
            else
            {
                log.WI("Rule for IP [" + rule.RemoteAddresses + "] or subnet already exists. Skipped");
            }
        }

        static bool CheckRule(FwOutRule rule)
        {
            if (outRules.Exists(r => r.RemoteAddresses.StartsWith(rule.RemoteAddresses)))
            {
                return false;
            }

            if (outRules.Exists(r => !r.IsIPRule && r.SubNet == rule.SubNet))
            {
                return false;
            }

            return true;
        }

        static bool MakeSubNetRules(FwOutRule rule)
        {
            if (rule.IsIPRule && !outRules.Exists(r => !r.IsIPRule && r.SubNet == rule.SubNet))
            {
                var cnt = outRules.Count(r => r.Name != rule.Name && r.SubNet == rule.SubNet);
                if (cnt > 0)
                {
                    var sRule = new FwOutRule(rule);
                    sRule.RemoteAddresses = rule.SubNet + "0/255.255.255.0";
                    sRule.Name = string.Format("{0} Used to block an SubNet [{1}]",
                        AppName, sRule.RemoteAddresses);

                    log.WI("Adding new rule for SubNet [" + sRule.RemoteAddresses + "]");

                    AddFwRule(sRule);
                    outRules.Add(sRule);

                    return true;
                }
            }
            return false;
        }

        static void LoadOutRules()
        {
            INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(
               Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            List<INetFwRule> rules = new List<INetFwRule>();
            foreach (var ruleObj in firewallPolicy.Rules)
            {
                if (ruleObj is INetFwRule)
                {
                    rules.Add(ruleObj as INetFwRule);
                }
            }

            foreach (var fwRule in rules)
            {
                if (fwRule.Direction == NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT
                    && fwRule.Name.StartsWith(AppName))
                {
                    var rule = new FwOutRule(fwRule);
                    if (CheckRule(rule))
                    {
                        outRules.Add(rule);
                    }
                    else
                    {
                        firewallPolicy.Rules.Remove(fwRule.Name);
                        log.WI("Removed duplicate rule for IP [" + rule.RemoteAddresses + "]");
                    }
                }
            }

        }

        static void AddFwRule(FwOutRule rule)
        {
            INetFwRule firewallRule = (INetFwRule)Activator.CreateInstance(
                Type.GetTypeFromProgID("HNetCfg.FWRule"));
            firewallRule.Action = rule.Action;
            firewallRule.Description = rule.Description;
            firewallRule.Direction = rule.Direction;
            firewallRule.Enabled = rule.Enabled;
            firewallRule.InterfaceTypes = "All";
            firewallRule.Name = rule.Name;
            firewallRule.RemoteAddresses = rule.RemoteAddresses;

            if (!string.IsNullOrEmpty(rule.ApplicationName))
            {
                firewallRule.ApplicationName = rule.ApplicationName;
            }
            INetFwPolicy2 firewallPolicy = (INetFwPolicy2)Activator.CreateInstance(
                Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            firewallPolicy.Rules.Add(firewallRule);
        }
    }
}
