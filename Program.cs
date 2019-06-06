using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Principal;
using System.ComponentModel;

namespace mbks2lab
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new Form1());
        }
    }

    public struct processinfo
    {
        public string ProcName;
        public int PID;
        public string Description;
        public string Path;
        public string ParName;
        public int ParPID;
        public string Owner;
        public string SID;
        public string Arch;
        public bool DEP;
        public bool ASLR;
        public ProcessModuleCollection Module;
    }

    public static class InfoOfProcesses
    {
        public static List<processinfo> ListOfProcesses = new List<processinfo>();

        //===========PARENT PROCESS=======================

        private static string FindIndexedProcessName(int pid)
        {
            var processName = Process.GetProcessById(pid).ProcessName;
            var processesByName = Process.GetProcessesByName(processName);
            string processIndexdName = null;

            for (var index = 0; index < processesByName.Length; index++)
            {
                processIndexdName = index == 0 ? processName : processName + "#" + index;
                var processId = new PerformanceCounter("Process", "ID Process", processIndexdName);
                if ((int)processId.NextValue() == pid)
                {
                    return processIndexdName;
                }
            }
            return processIndexdName;
        }

        private static Process FindPidFromIndexedProcessName(string indexedProcessName)
        {
            var parentId = new PerformanceCounter("Process", "Creating Process ID", indexedProcessName);
            return Process.GetProcessById((int)parentId.NextValue());
        }

        public static Process Parent(this Process process)
        {
            return FindPidFromIndexedProcessName(FindIndexedProcessName(process.Id));
        }

        private static int GetParentProcces(int PID)
        {
            int PPID = -1;
            PPID = Process.GetProcessById(PID).Parent().Id;
            return PPID;
        }

        //==============PARENT PROCCESS========================

        //==========PROCESS OWNER, SID===============

        private static string GetOwnerSID(Process process)
        {
            IntPtr processHandle = IntPtr.Zero;
            try
            {
                OpenProcessToken(process.Handle, 8, out processHandle);
                WindowsIdentity wi = new WindowsIdentity(processHandle);
                SecurityIdentifier OwnerSID = wi.User;
                string SID = OwnerSID.ToString();
                return SID;
            }
            catch(Exception)
            {
                return "Unknown";
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                {
                    CloseHandle(processHandle);
                }
            }
        }

        private static string GetProcessOwner(Process process)
        {
            IntPtr processHandle = IntPtr.Zero;
            try
            {
                OpenProcessToken(process.Handle, 8, out processHandle);
                WindowsIdentity wi = new WindowsIdentity(processHandle);
                string user = wi.Name;
                return user.Contains(@"\") ? user.Substring(user.IndexOf(@"\") + 1) : user;
            }
            catch(Exception)
            {
                return null;
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                {
                    CloseHandle(processHandle);
                }
            }
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        //==========PROCESS OWNER===============
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]

        [return: MarshalAs(UnmanagedType.Bool)]

        public static extern bool IsWow64Process([In] IntPtr hProcess, [Out] out bool lpSystemInfo);

        private static string GetArchitecture(Process process)
        {
            /*if (Environment.Is64BitOperatingSystem)
            {
                bool is64;
                // On 64-bit OS, if a process is not running under Wow64 mode, 
                // the process must be a 64-bit process.
                if (IsWow64Process(process.Handle, out is64))
                {
                    return is64; // false 64 true 32
                }
            }

            return true;*/
            try
            {
                /*
                if (Environment.Is64BitOperatingSystem)
                    return "x64";
                    */
                bool isWow64;
                IsWow64Process(process.Handle, out isWow64);
                return isWow64 == true ? "x32" : "x64";
            }
            catch (Exception)
            {
                return "Unknown";
            }
        }

        //==========================descriptors===============================



        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool  bInheritHandle, int dwProcessId);

        [DllImport("Ntdll.dll")]
        static extern uint NtQuerySystemInformation(
             int SystemInformationClass,
             IntPtr                    SystemInformation,
             ulong                    SystemInformationLength,
             out uint ReturnLength
        );

        [DllImport("handles.dll")]
        unsafe public static extern int GetHandlesByPID(int _pid, char** res, uint size);

        [DllImport("handles.dll")]
        unsafe public static extern int GetProcessIntegrityLevel(int _pid);

        [DllImport("handles.dll")]
        unsafe public static extern int SetProcessIntegrityLevel(int _pid, int _level);

        [DllImport("handles.dll")]
        unsafe public static extern int SetFileIntegrityLevel(int _level, string path);

        [DllImport("handles.dll")]
        unsafe public static extern int GetFileIntegrityLevel(string path);

        [DllImport("kernel32.dll")]
        static extern bool GetProcessMitigationPolicy(
            IntPtr hProcess,
            /*PROCESS_MITIGATION_POLICY*/ int mitigationPolicy,
            ref PROCESS_MITIGATION_DEP_POLICY lpBuffer,
            int dwLength);

        [DllImport("kernel32.dll")]
        static extern bool GetProcessMitigationPolicy(
            IntPtr hProcess,
            /*PROCESS_MITIGATION_POLICY*/ int mitigationPolicy,
            ref PROCESS_MITIGATION_ASLR_POLICY lpBuffer,
            int dwLength);

        struct PROCESS_MITIGATION_DEP_POLICY
        {
            uint Flags;
            bool Permanent;

            public bool Enable
            {
                get { return (Flags & 1) > 0; }
            }

            bool DisableAtlThunkEmulation
            {
                get { return (Flags & 2) > 0; }
            }
        }

        struct PROCESS_MITIGATION_ASLR_POLICY
        {
            uint Flags;

            public bool Enable
            {
                get { return (Flags & 1) > 0; }
            }
        }
        
        public static void GetProccesses()
        {
            ListOfProcesses.Clear();
            var p = Process.GetProcesses();
            bool success;
            foreach(var pl in p)
            {
                processinfo proc = new processinfo();
                var dep = new PROCESS_MITIGATION_DEP_POLICY();
                var aslr = new PROCESS_MITIGATION_ASLR_POLICY();
                try
                {
                    proc.ProcName = pl.ProcessName;
                    proc.PID = pl.Id;
                    proc.Description = pl.MainModule.FileVersionInfo.FileDescription;
                    proc.Path = pl.MainModule.FileName;
                    proc.ParPID = GetParentProcces(pl.Id);
                    proc.ParName = Process.GetProcessById(proc.ParPID).ProcessName;
                    proc.Owner = GetProcessOwner(pl);
                    proc.SID = GetOwnerSID(pl);
                    proc.Arch = GetArchitecture(pl);
                    proc.Module = pl.Modules;
                    success = GetProcessMitigationPolicy(pl.Handle, 0, ref dep, Marshal.SizeOf(dep));
                    success = GetProcessMitigationPolicy(pl.Handle, 1, ref aslr, Marshal.SizeOf(aslr));
                    proc.DEP = dep.Enable;
                    proc.ASLR = aslr.Enable;
                    //var DEP
                    //var ASLR
                }
                catch (Exception)
                {
                    proc.ProcName = pl.ProcessName;
                    proc.PID = pl.Id;
                    proc.Description = "Access Denied";
                    proc.Path = "Access Denied";
                    proc.ParPID = 0;
                    proc.ParName = "System";
                    proc.Owner = "System";
                    proc.Arch = "x64";
                    proc.DEP = true;
                    proc.ASLR = true;
                    continue;
                }
                ListOfProcesses.Add(proc);
            }
        }
    }
}
