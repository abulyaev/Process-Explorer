using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Text.RegularExpressions;

namespace mbks2lab
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        List<processinfo> ListOfProcesses = new List<processinfo>();
        List<ProcessModuleCollection> ListOfModules = new List<ProcessModuleCollection>();

        private void FillTable()
        {
            dataGridView1.ColumnCount = 11;
            dataGridView1.Columns[0].Name = "ProcName";
            dataGridView1.Columns[1].Name = "PID";
            dataGridView1.Columns[2].Name = "Description";
            dataGridView1.Columns[3].Name = "Path";
            dataGridView1.Columns[4].Name = "ParName";
            dataGridView1.Columns[5].Name = "ParPID";
            dataGridView1.Columns[6].Name = "Owner";
            dataGridView1.Columns[7].Name = "SID";
            dataGridView1.Columns[8].Name = "Arc-t";
            dataGridView1.Columns[9].Name = "DEP";
            dataGridView1.Columns[10].Name = "ASLR";

            ListOfProcesses.Clear();
            InfoOfProcesses.GetProccesses();
            ListOfProcesses = InfoOfProcesses.ListOfProcesses;

            dataGridView1.Rows.Clear();

            foreach(var proc in ListOfProcesses)
            {
                dataGridView1.Rows.Add(proc.ProcName, proc.PID, proc.Description, proc.Path, proc.ParName, proc.ParPID, proc.Owner, proc.SID, proc.Arch,
                    proc.DEP, proc.ASLR);
                ListOfModules.Add(proc.Module);
            }
        }


        private void button1_Click(object sender, EventArgs e)
        {
            FillTable();
        }

        private void dataGridView1_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {

        }
        
        //TODO: Parse type and get it to box separately

        unsafe private void button2_Click(object sender, EventArgs e)
        {
            List<string> handle = new List<string>();
            List<string> handlers = new List<string>();
            List<string> types = new List<string>();

            var CurInd = dataGridView1.CurrentCell.RowIndex;

            int sel_pid = Convert.ToInt32(dataGridView1.Rows[CurInd].Cells[1].Value);
            if (sel_pid == 0)
                return;

            char* str = null;
            InfoOfProcesses.GetHandlesByPID(sel_pid, &str, 4 * 1024);

            string result_handles = new string(str);
            string tmpstr = result_handles;
            string tmptmp = result_handles;
            var pattern = "[*\n]";
            var ptrn = "[:*\n]";       ////tmpstr  "[0x4]Directory : \\KnownDlls " string
            string[] substrings = Regex.Split(tmpstr, pattern);
            string[] substr = Regex.Split(tmptmp, ptrn);
            string[] subtypes = new string[substr.Length];

            int j = 0;

            for (int i = 0; i < substr.Length; ++i)
            {
                if(i % 2 == 0)
                {
                    subtypes[j] = substr[i];
                    j++;
                }
            }

            foreach (string strs in substrings)
            {
                handlers.Add(strs);
            }

            foreach(string strs in subtypes)
            {
                types.Add(strs);
            }

            for (int i = 0; i < ListOfModules[CurInd].Count; ++i)
            {
                handle.Add(ListOfModules[CurInd][i].ModuleName);
            }

            var ShowModule = new DLLs(handle, handlers, types);
            ShowModule.Show();
        }

        private void button3_Click(object sender, EventArgs e)
        {
            var CurInd = dataGridView1.CurrentCell.RowIndex;
            int pid = Convert.ToInt32(dataGridView1.Rows[CurInd].Cells[1].Value);
            var IntegrityBox = new Integrity(pid);
            IntegrityBox.Show();
        }

        private void button4_Click(object sender, EventArgs e)
        {
            var FilesIntegrityBox = new FilesIntegrity();
            FilesIntegrityBox.Show();
        }
    }
}
