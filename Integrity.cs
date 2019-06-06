using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;
using System.Runtime.InteropServices;
using ProcessPrivileges;


namespace mbks2lab
{
    public partial class Integrity : Form
    {
        int procid = 0;
        bool isbrowse = false;
        int sel_int_lvl = -1;

        public Integrity(int pid)
        {
            InitializeComponent();
            procid = pid;
            textBox2.Text = procid.ToString();
            label3.Visible = false;
            comboBox1.Items.Add("LOW");
            comboBox1.Items.Add("MEDIUM");
            comboBox1.Items.Add("HIGH");
            comboBox1.Items.Add("SYSTEM");

            comboBox3.Items.Add("ENABLE");
            comboBox3.Items.Add("DISABLE");

            System.Diagnostics.Process process = System.Diagnostics.Process.GetProcessById(pid);
            PrivilegeAndAttributesCollection privileges = process.GetPrivileges();
            if (privileges.Count == 0)
            {
                comboBox2.Items.Add("NO PRIVS");
            }
            else
            {
                int maxPrivilegeLebgth = privileges.Max(privilege => privilege.Privilege.ToString().Length);
                foreach (PrivilegeAndAttributes PrivNAtrr in privileges)
                {
                    Privilege privilege = PrivNAtrr.Privilege;
                    PrivilegeState privilegeState = PrivNAtrr.PrivilegeState;
                    string StrComboBox2 = privilege.ToString();
                    comboBox2.Items.Add(StrComboBox2);
                }
                
            }
        }

        private void Integrity_Load(object sender, EventArgs e)
        {

        }

        public static string ShowIntegrity(int level)
        {
            switch (level)
            {
                case 1: return "low";
                case 2: return "medium";
                case 3: return "high";
                case 4: return "system";
                default: return "system"; // perhaps restricted access
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (textBox2.Text.Length != 0)
            {
                var id = Convert.ToInt32(textBox2.Text);
                var lvl = InfoOfProcesses.GetProcessIntegrityLevel(id);
                label3.Visible = true;
                label3.Text = ShowIntegrity(lvl);
            }
            else
            {
                MessageBox.Show("You must select PID or Path to file!!!\nIf you want to check file integrity level again, select him in Browse button.");
            }
            //if (rbtn_file_int.Checked == true)
            
        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        enum integrity_levels
        {
            low,
            medium,
            high,
            system
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (textBox2.Text.Length != 0)
            {
                var id = Convert.ToInt32(textBox2.Text);
                var sel = comboBox1.SelectedIndex + 1;
                InfoOfProcesses.SetProcessIntegrityLevel(id, sel);
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            /*
            if (textBox1.Text.Length != 0)
            {
                var id = textBox1.Text;
                var sel = comboBox1.SelectedIndex + 1; 
                InfoOfProcesses.SetFileIntegrityLevel(sel, id);
            }
            */
        }

        private void button4_Click(object sender, EventArgs e)
        {
            /*
            OpenFileDialog OFD = new OpenFileDialog();
            if (OFD.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                textBox1.Text = OFD.FileName;
                isbrowse = true;
            }
            */
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void label3_Click(object sender, EventArgs e)
        {

        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void textBox2_TextChanged(object sender, EventArgs e)
        {
            
        }

        private void label7_Click(object sender, EventArgs e)
        {

        }

        private void button3_Click_1(object sender, EventArgs e)
        {
            
        }

        private static string GetPadding(int length, int maxLength)
        {
            int paddingLength = maxLength - length;
            char[] padding = new char[paddingLength];
            for (int i = 0; i < paddingLength; i++)
            {
                padding[i] = ' ';
            }

            return new string(padding);
        }

        private void button3_Click_2(object sender, EventArgs e)
        {
            int id = Convert.ToInt32(textBox2.Text);
            //System.Diagnostics.Process proc = System.Diagnostics.Process.GetProcessById(id);

            //string argument = Convert.ToString(id);
            //var info = new System.Diagnostics.ProcessStartInfo(@"C:\Users\abuly_000\Documents\Visual Studio 2015\Projects\mbks2lab\x64\Debug\GetProcessPrivileges.exe", argument);
            //System.Diagnostics.Process.Start(info);

            //string text = System.IO.File.ReadAllText("C:\\Users\\abuly_000\\Documents\\Visual Studio 2015\\Projects\\mbks2lab\\Privileges.txt");
            //MessageBox.Show(text);
            System.Diagnostics.Process process = Process.GetProcessById(id);
            PrivilegeAndAttributesCollection privileges = process.GetPrivileges();
            if (privileges.Count == 0)
            {
                MessageBox.Show("NO PRIVILEGES");
            }
            else
            {
                int maxPrivilegeLength = privileges.Max(privilege => privilege.Privilege.ToString().Length);
                string Out = null;
                foreach (PrivilegeAndAttributes privilegeAndAttributes in privileges)
                {
                    Privilege privilege = privilegeAndAttributes.Privilege;
                    PrivilegeState privilegeState = privilegeAndAttributes.PrivilegeState;
                    string PaddingString = GetPadding(privilege.ToString().Length, maxPrivilegeLength);
                    Out += privilege + " " + PaddingString + " => " + privilegeState + "\n";

                }
                MessageBox.Show(Out);
            }
        }

        private void button4_Click_1(object sender, EventArgs e)
        {
            int id = Convert.ToInt32(textBox2.Text);
            string StrPrivilege = comboBox2.SelectedItem.ToString();
            string StrState = comboBox3.SelectedItem.ToString();
            System.Diagnostics.Process process = System.Diagnostics.Process.GetProcessById(id);
            PrivilegeAndAttributesCollection privileges = process.GetPrivileges();
            if(privileges.Count == 0)
            {
                MessageBox.Show("NO PRIVILEGES");
                return;
            }
            int maxPrivilegeLength = privileges.Max(privilege => privilege.ToString().Length);
            foreach (PrivilegeAndAttributes privilegeNattributes in privileges )
            {
                if(StrPrivilege == Privilege.AssignPrimaryToken.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.AssignPrimaryToken) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.AssignPrimaryToken);
                        }
                    }
                    else if(StrState == "DISABLE")
                    {
                        if(process.GetPrivilegeState(Privilege.AssignPrimaryToken) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.AssignPrimaryToken);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.Audit.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Audit) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.Audit);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Audit) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.Audit);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.Backup.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Backup) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.Backup);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Backup) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.Backup);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.ChangeNotify.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.ChangeNotify) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.ChangeNotify);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.ChangeNotify) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.ChangeNotify);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.CreateGlobal.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.CreateGlobal) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.CreateGlobal);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.CreateGlobal) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.CreateGlobal);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.CreatePageFile.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.CreatePageFile) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.CreatePageFile);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.CreatePageFile) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.CreatePageFile);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.CreatePermanent.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.CreatePermanent) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.CreatePermanent);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.CreatePermanent) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.CreatePermanent);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.CreateSymbolicLink.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.CreateSymbolicLink) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.CreateSymbolicLink);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.CreateSymbolicLink) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.CreateSymbolicLink);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.CreateToken.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.CreateToken) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.CreateToken);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.CreateToken) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.CreateToken);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.Debug.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Debug) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.Debug);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Debug) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.Debug);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.EnableDelegation.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.EnableDelegation) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.EnableDelegation);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.EnableDelegation) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.EnableDelegation);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.Impersonate.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Impersonate) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.Impersonate);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Impersonate) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.Impersonate);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.IncreaseBasePriority.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.IncreaseBasePriority) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.IncreaseBasePriority);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.IncreaseBasePriority) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.IncreaseBasePriority);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.IncreaseQuota.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.IncreaseQuota) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.IncreaseQuota);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.IncreaseQuota) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.IncreaseQuota);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.IncreaseWorkingSet.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.IncreaseWorkingSet) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.IncreaseWorkingSet);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.IncreaseWorkingSet) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.IncreaseWorkingSet);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.LoadDriver.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.LoadDriver) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.LoadDriver);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.LoadDriver) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.LoadDriver);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.LockMemory.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.LockMemory) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.LockMemory);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.LockMemory) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.LockMemory);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.MachineAccount.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.MachineAccount) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.MachineAccount);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.MachineAccount) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.MachineAccount);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.ManageVolume.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.ManageVolume) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.ManageVolume);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.ManageVolume) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.ManageVolume);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.ProfileSingleProcess.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.ProfileSingleProcess) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.ProfileSingleProcess);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.ProfileSingleProcess) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.ProfileSingleProcess);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.Relabel.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Relabel) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.Relabel);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Relabel) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.Relabel);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.RemoteShutdown.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.RemoteShutdown) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.RemoteShutdown);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.RemoteShutdown) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.RemoteShutdown);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.Restore.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Restore) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.Restore);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Restore) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.Restore);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.Security.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Security) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.Security);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Security) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.Security);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.Shutdown.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Shutdown) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.Shutdown);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Shutdown) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.Shutdown);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.SyncAgent.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.SyncAgent) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.SyncAgent);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.SyncAgent) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.SyncAgent);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.SystemEnvironment.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.SystemEnvironment) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.SystemEnvironment);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.SystemEnvironment) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.SystemEnvironment);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.SystemProfile.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.SystemProfile) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.SystemProfile);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.SystemProfile) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.SystemProfile);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.SystemTime.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.SystemTime) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.SystemTime);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.SystemTime) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.SystemTime);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.TakeOwnership.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.TakeOwnership) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.TakeOwnership);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.TakeOwnership) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.TakeOwnership);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.TimeZone.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.TimeZone) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.TimeZone);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.TimeZone) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.TimeZone);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.TrustedComputerBase.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.TrustedComputerBase) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.TrustedComputerBase);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.TrustedComputerBase) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.TrustedComputerBase);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.TrustedCredentialManagerAccess.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.TrustedCredentialManagerAccess) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.TrustedCredentialManagerAccess);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.TrustedCredentialManagerAccess) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.TrustedCredentialManagerAccess);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.Undock.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Undock) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.Undock);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.Undock) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.Undock);
                        }
                    }
                }
                else if (StrPrivilege == Privilege.UnsolicitedInput.ToString())
                {
                    if (StrState == "ENABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.UnsolicitedInput) == PrivilegeState.Disabled)
                        {
                            AdjustPrivilegeResult result = process.EnablePrivilege(Privilege.UnsolicitedInput);
                        }
                    }
                    else if (StrState == "DISABLE")
                    {
                        if (process.GetPrivilegeState(Privilege.UnsolicitedInput) == PrivilegeState.Enabled)
                        {
                            AdjustPrivilegeResult result = process.DisablePrivilege(Privilege.UnsolicitedInput);
                        }
                    }
                }
            }
        }

        private void comboBox3_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void comboBox2_SelectedIndexChanged(object sender, EventArgs e)
        {

        }
    }
}
