using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Text.RegularExpressions;

namespace mbks2lab
{
    public partial class DLLs : Form
    {
        public DLLs(List<string> handle, List<string> handlers, List<string> types)
        {
            InitializeComponent();
            FillTable(handle, handlers, types);
        }


        public void FillTable(List<string> handle, List<string> handlers, List<string> types)
        {
            dataGridView1.ColumnCount = 2;
            dataGridView1.Columns[0].Name = "DLL";
            //dataGridView1.Columns[1].Name = "Type";
            dataGridView1.Columns[1].Name = "Handles";
            
            for(int i = 0; i <= dataGridView1.Columns.Count - 1; i++) {
                dataGridView1.Columns[i].AutoSizeMode = DataGridViewAutoSizeColumnMode.AllCells;
            }

            //tmpstr  "[0x4]Directory : \\KnownDlls " string
            for (int i = 0, j = 0; i  < handle.Count && j < handlers.Count; ++i, ++j)
            {
                dataGridView1.Rows.Add(handle[i], handlers[j]);
            }
        }

        private void dataGridView1_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {

        }

    }
}
