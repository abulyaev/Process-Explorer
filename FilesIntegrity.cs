using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Controls;
using System.Management;
using System.Security.Principal;
using System.IO;
using System.Security.AccessControl;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using System.Runtime.ConstrainedExecution;
using System.Security;

namespace mbks2lab
{
    public partial class FilesIntegrity : Form
    {
        public FilesIntegrity()
        {
            InitializeComponent();
            label3.Visible = false;
            label6.Visible = false;
            comboBox1.Items.Add("LOW");
            comboBox1.Items.Add("MEDIUM");
            comboBox1.Items.Add("HIGH");
            comboBox1.Items.Add("SYSTEM");

            comboBox3.Items.Add("/grant");
            comboBox3.Items.Add("/deny");

            comboBox4.Items.Add("N - no access");
            comboBox4.Items.Add("F - full access");
            comboBox4.Items.Add("M - modify access");
            comboBox4.Items.Add("RX - read and execute access");
            comboBox4.Items.Add("R - read-only access");
            comboBox4.Items.Add("W - write-only access");
            comboBox4.Items.Add("D - delete access");
            comboBox4.Items.Add("MA - maximum allowed");

            SelectQuery query = new SelectQuery("Win32_UserAccount");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject envVar in searcher.Get())
            {
                //Console.WriteLine("Username : {0}", envVar["Name"]);
                comboBox2.Items.Add(envVar["Name"]);
            }

            textBox2.PasswordChar = '*';
            textBox3.PasswordChar = '*';

        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void label3_Click(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            OpenFileDialog OFD = new OpenFileDialog();
            if (OFD.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                textBox1.Text = OFD.FileName;
            }
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

        private void button3_Click(object sender, EventArgs e)
        {
            if (textBox1.Text.Length != 0)
            {
                var id = textBox1.Text;
                var sel = comboBox1.SelectedIndex + 1;
                InfoOfProcesses.SetFileIntegrityLevel(sel, id);

                var lvl = InfoOfProcesses.GetFileIntegrityLevel(id);
                label3.Visible = true;
                label3.Text = ShowIntegrity(lvl);
            }
        }


        private void button2_Click(object sender, EventArgs e)
        {
            if (textBox1.Text.Length != 0)
            {
                var id = textBox1.Text;
                var lvl = InfoOfProcesses.GetFileIntegrityLevel(id);
                label3.Visible = true;
                label3.Text = ShowIntegrity(lvl);
            }
            else
            {
                MessageBox.Show("You must select path to file!!!\nIf you want to check file integrity level again, select him in Browse button.");
            }
            
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void label6_Click(object sender, EventArgs e)
        {

        }

        private void button4_Click(object sender, EventArgs e)
        {
            if (textBox1.Text.Length != 0)
            {
                string path = textBox1.Text;
                string user = System.IO.File.GetAccessControl(path).GetOwner(typeof(System.Security.Principal.NTAccount)).ToString();
                label6.Visible = true;
                label6.Text = user;
            }
        }

        private void comboBox2_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        public static void AddFileSecurity(string path, string Account, System.Security.AccessControl.FileSystemRights Rights, System.Security.AccessControl.AccessControlType ControlType)
        {
            System.IO.FileInfo FINFO = new System.IO.FileInfo(path);
            System.Security.AccessControl.FileSecurity FSECURITY = FINFO.GetAccessControl();
            FSECURITY.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(Account, Rights, ControlType));
            FINFO.SetAccessControl(FSECURITY);
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out IntPtr phToken
        );

        public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private SafeTokenHandle()
                : base(true)
            {
            }

            [DllImport("kernel32.dll")]
            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
            [SuppressUnmanagedCodeSecurity]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CloseHandle(IntPtr handle);

            protected override bool ReleaseHandle()
            {
                return CloseHandle(handle);
            }
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword,
                   int dwLogonType, int dwLogonProvider, out SafeTokenHandle phToken);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public extern static bool CloseHandle(IntPtr handle);

        public SafeTokenHandle LogInUser(string username, string passwd)
        {
            SafeTokenHandle safeTokenHandle;
            const int LOGON32_PROVIDER_DEFAULT = 0;
            //This parameter causes LogonUser to create a primary token.
            const int LOGON32_LOGON_INTERACTIVE = 2;
            bool returnValue = LogonUser(username, "RASHIT", passwd,
            LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
            out safeTokenHandle);
            if (false == returnValue)
            {
                int ret = Marshal.GetLastWin32Error();
                throw new System.ComponentModel.Win32Exception(ret);
            }
            return safeTokenHandle;
        }

        private void button5_Click(object sender, EventArgs e)
        {
            if (textBox1.Text.Length != 0 && textBox2.Text.Length != 0 && textBox3.Text.Length != 0)
            {
                if (comboBox2.SelectedIndex + 1.ToString() != null)
                {
                    string path = textBox1.Text;
                    string passwd = textBox2.Text;
                    string sel = comboBox2.SelectedItem.ToString();
                    string ownerpasswd = textBox3.Text;


                    string user = System.IO.File.GetAccessControl(path).GetOwner(typeof(System.Security.Principal.NTAccount)).ToString();
                    user = user.Split('\\').Last();
                    string userName = System.Security.Principal.WindowsIdentity.GetCurrent().Name.Split('\\').Last();
                    if (user != userName)
                    {
                        //SafeTokenHandle safeTokenHandle;
                        //safeTokenHandle = LogInUser(user, ownerpasswd);
                        SafeTokenHandle safeTokenHandle;
                        const int LOGON32_PROVIDER_DEFAULT = 0;
                        //This parameter causes LogonUser to create a primary token.
                        const int LOGON32_LOGON_INTERACTIVE = 2;
                        bool returnValue = LogonUser(user, "RASHIT", ownerpasswd,
                        LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                        out safeTokenHandle);
                        if (false == returnValue)
                        {
                            int ret = Marshal.GetLastWin32Error();
                            throw new System.ComponentModel.Win32Exception(ret);
                        }
                        using (safeTokenHandle)
                        {
                            // Use the token handle returned by LogonUser.
                            using (WindowsIdentity newId = new WindowsIdentity(safeTokenHandle.DangerousGetHandle()))
                            {
                                using (WindowsImpersonationContext impersonatedUser = newId.Impersonate())
                                {
                                    string file = Path.GetFileName(path);
                                    //Copy the file. This allows our service account to take ownership of the copied file
                                    var tempFileName = path + "_TEMP";//Path.Combine(Path.GetDirectoryName(file), "TEMP_" + file);

                                    File.Copy(path, tempFileName);
                                    var windowID = WindowsIdentity.GetCurrent();
                                    var currUserName = windowID.User.Translate(typeof(NTAccount)).Value;
                                    var splitChar = new[] { '\\' };
                                    var ediFileOwner = new NTAccount("RASHIT", sel);
                                    var fileSecurity = File.GetAccessControl(path);
                                    var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                                    fileSecurity.AddAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.FullControl, AccessControlType.Allow));
                                    File.SetAccessControl(path, fileSecurity);
                                    File.Delete(path);
                                    File.Move(Path.Combine(Path.GetDirectoryName(path), path + "_TEMP"), path);//tempFileName, file);
                                    fileSecurity = File.GetAccessControl(path);
                                    var aosSID = (SecurityIdentifier)ediFileOwner.Translate(typeof(SecurityIdentifier));
                                    fileSecurity.AddAccessRule(new FileSystemAccessRule(aosSID, FileSystemRights.FullControl, AccessControlType.Allow));
                                    File.SetAccessControl(path, fileSecurity);

                                    SafeTokenHandle OwnerTokenHandle;
                                    OwnerTokenHandle = LogInUser(sel, passwd);
                                    using (OwnerTokenHandle)
                                    {
                                        // Use the token handle returned by LogonUser.
                                        using (WindowsIdentity OwnerId = new WindowsIdentity(OwnerTokenHandle.DangerousGetHandle()))
                                        {
                                            using (WindowsImpersonationContext impersonatedOwnerUser = OwnerId.Impersonate())
                                            {

                                                // Check the identity.
                                                Console.WriteLine("After impersonation: "
                                                    + WindowsIdentity.GetCurrent().Name);
                                                fileSecurity = File.GetAccessControl(path);
                                                fileSecurity.SetOwner(ediFileOwner); //Change our owner from LocalAdmin to our chosen DAX User
                                                File.SetAccessControl(path, fileSecurity);
                                            }
                                        }
                                        // Releasing the context object stops the impersonation
                                    }

                                }
                            }
                            // Releasing the context object stops the impersonation
                        }

                        
                    }
                    else if (user == userName)
                    {
                        string file = Path.GetFileName(path);
                        //Copy the file. This allows our service account to take ownership of the copied file
                        var tempFileName = path + "_TEMP";//Path.Combine(Path.GetDirectoryName(file), "TEMP_" + file);

                        File.Copy(path, tempFileName);
                        var windowID = WindowsIdentity.GetCurrent();
                        var currUserName = windowID.User.Translate(typeof(NTAccount)).Value;
                        var splitChar = new[] { '\\' };
                        var ediFileOwner = new NTAccount("RASHIT", sel);
                        var fileSecurity = File.GetAccessControl(path);
                        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                        fileSecurity.AddAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.FullControl, AccessControlType.Allow));
                        File.SetAccessControl(path, fileSecurity);
                        File.Delete(path);
                        File.Move(Path.Combine(Path.GetDirectoryName(path), path + "_TEMP"), path);//tempFileName, file);
                        fileSecurity = File.GetAccessControl(path);
                        var aosSID = (SecurityIdentifier)ediFileOwner.Translate(typeof(SecurityIdentifier));
                        fileSecurity.AddAccessRule(new FileSystemAccessRule(aosSID, FileSystemRights.FullControl, AccessControlType.Allow));
                        File.SetAccessControl(path, fileSecurity);

                        SafeTokenHandle OwnerTokenHandle;
                        OwnerTokenHandle = LogInUser(sel, passwd);
                        using (OwnerTokenHandle)
                        {
                            // Use the token handle returned by LogonUser.
                            using (WindowsIdentity newId = new WindowsIdentity(OwnerTokenHandle.DangerousGetHandle()))
                            {
                                using (WindowsImpersonationContext impersonatedOwnerUser = newId.Impersonate())
                                {

                                    // Check the identity.
                                    Console.WriteLine("After impersonation: "
                                        + WindowsIdentity.GetCurrent().Name);
                                    fileSecurity = File.GetAccessControl(path);
                                    fileSecurity.SetOwner(ediFileOwner); //Change our owner from LocalAdmin to our chosen DAX User
                                    File.SetAccessControl(path, fileSecurity);
                                }
                            }
                            // Releasing the context object stops the impersonation
                        }

                    }
                }
            }
        }

        private void textBox2_TextChanged(object sender, EventArgs e)
        {
            
        }

        private void textBox3_TextChanged(object sender, EventArgs e)
        {

        }

        private string GetAceInformation(FileSystemAccessRule ace)
        {
            StringBuilder info = new StringBuilder();
            string line = string.Format("Account: {0}",
               ace.IdentityReference.Value);
            info.AppendLine(line);
            line = string.Format("Type: {0}", ace.AccessControlType);
            info.AppendLine(line);
            line = string.Format("Rights: {0}", ace.FileSystemRights);
            info.AppendLine(line);
            line = string.Format("Inherited ACE: {0}", ace.IsInherited);
            info.AppendLine(line);
            return info.ToString();
        }

        private void button6_Click(object sender, EventArgs e)
        {
            string path = textBox1.Text;
            FileInfo IFILE = new FileInfo(path);
            FileSecurity SFILE = IFILE.GetAccessControl(AccessControlSections.Access);
            string AccessInfo = string.Empty;

            FileSecurity fsec = File.GetAccessControl(path);
            AuthorizationRuleCollection acl = fsec.GetAccessRules(true, true, typeof(NTAccount));
            foreach(FileSystemAccessRule ace in acl)
            {
                AccessInfo += GetAceInformation(ace) + "\n";
            }

            MessageBox.Show(AccessInfo);

        }

        private void button7_Click(object sender, EventArgs e)
        {
            string path = textBox1.Text;
            string permission = comboBox3.SelectedItem.ToString();
            string username = comboBox2.SelectedItem.ToString();

            string access = null;
            if (comboBox4.SelectedItem.ToString() == "N - no access")
            {
                access = "N";
            }
            else if (comboBox4.SelectedItem.ToString() == "F - full access")
            {
                access = "F";
            }
            else if (comboBox4.SelectedItem.ToString() == "M - modify access")
            {
                access = "M";
            }
            else if (comboBox4.SelectedItem.ToString() == "RX - read and execute access")
            {
                access = "RX";
            }
            else if (comboBox4.SelectedItem.ToString() == "R - read-only access")
            {
                access = "R";
            }
            else if (comboBox4.SelectedItem.ToString() == "W - write-only access")
            {
                access = "W";
            }
            else if (comboBox4.SelectedItem.ToString() == "D - delete access")
            {
                access = "D";
            }
            else if(comboBox4.SelectedItem.ToString() == "MA - maximum allowed")
            {
                access = "MA";
            }

            string argument = path + " " + permission + " " + username + ":(" + access + ")"; //    D:\\Files\\7.jpg /grant abuly__000:(f);

            var info = new System.Diagnostics.ProcessStartInfo(@"C:\Windows\system32\icacls.exe", argument);
            System.Diagnostics.Process.Start(info);
        }

        private void comboBox3_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void comboBox4_SelectedIndexChanged(object sender, EventArgs e)
        {

        }
    }
}
