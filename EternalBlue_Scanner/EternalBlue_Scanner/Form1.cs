using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Net;
using System.Net.NetworkInformation;
using System.Windows.Forms;

namespace EternalBlue_Scanner
{
    public partial class Form1 : Form
    {
        List<String> Adapters = new List<String>();
        List<String> StartingAddress = new List<String>();
        List<String> EndingAddress = new List<String>();
        public Form1()
        {
            InitializeComponent();
        }

        public void SearchAndDestroy(Form1 main, String StartingAddress, String EndingAddress)
        {
            uint current = StartingAddress.ToUInt(), last = EndingAddress.ToUInt();
            while(current <= last)
            {
                IPAddress Address = current++.ToIPAddress();
                UpdateTitle(main, "EternalBlue Scanner - " + Address.ToString());
                String Message = "";
                MachineScanResult.VulnerabilityStatus AddressStatus = new MachineScanResult.VulnerabilityStatus();
                EternalBlueToolkit eternalBlueToolkit = new EternalBlueToolkit();
                AddressStatus = EternalBlueToolkit.IsVulnerableStub(Address.ToString(), out Message);
                ListViewItem lvi = new ListViewItem();
                lvi.Text = Address.ToString();
                lvi.SubItems.Add(AddressStatus.ToString());
                UpdateList(main, lvi);
            }
            UpdateTitle(main, "EternalBlue Scanner");
        }

        public void UpdateTitle(Form1 main, String Title)
        {
            if (main.InvokeRequired)
            {
               main.BeginInvoke((MethodInvoker)delegate ()
               {
                   main.Text = Title;
               });
            }
            else
            {
                main.Text = Title;
            }
        }

        public void UpdateList(Form1 main, ListViewItem lvi)
        {
            if (main.listView1.InvokeRequired)
            {
               main.listView1.BeginInvoke((MethodInvoker)delegate ()
               {
                   main.listView1.Items.Add(lvi);
               });
            }
            else
            {
                main.listView1.Items.Add(lvi);
            }
        }

        public List<List<String>> GrabInfo()
        {
            List<List<String>> Complete = new List<List<String>>();
            List<String> NetworkAdapters = new List<String>();
            List<String> BeginAddresses = new List<String>();
            List<String> EndingAddresses = new List<String>();
            NetworkInterface[] Cards = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface CurrCard in Cards)                                           //Cycle through each adapter
            {
                if (CurrCard.OperationalStatus == OperationalStatus.Up)                            //Check if the adapter is currently enabled
                {
                    try                                                                            //try incase we have a card that has a incorrect IP configuration
                    {
                        IPInterfaceProperties AdapterProperties = CurrCard.GetIPProperties();      //Get adapter properties
                        foreach (UnicastIPAddressInformation ip in CurrCard.GetIPProperties().UnicastAddresses)   //Cycle through Unicast info
                        {
                            if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)        //Check for internetwork info
                            {
                                IPAddress CurrentAddress = ip.Address;                                                //Our IP Address
                                IPAddress SubnetMask = ip.IPv4Mask;                                                   //Network subnet mask (we will use these to calculate the IP range)
                                byte[] AddressBytes = CurrentAddress.GetAddressBytes();                               //Grab byte format of IP Address
                                byte[] SubnetBytes = SubnetMask.GetAddressBytes();                                    //Grab byte format of Subnet
                                if (AddressBytes.Length != SubnetBytes.Length)                                        //Ensure that Subnet and IP are the same length
                                {
                                    //Error! IP Address length and subnet length dont match!
                                }
                                else
                                {
                                    byte[] broadcastBytes = new byte[AddressBytes.Length];                            //Create broadcast byte[] that will hold our starting address bytes
                                    for (int i = 0; i < broadcastBytes.Length; i++)                                   //Cycle through each byte
                                    {
                                        broadcastBytes[i] = (byte)(AddressBytes[i] | (SubnetBytes[i] ^ 255));         //Current byte = Address Value OR Subnet value XOR 255
                                    }                                                                                 //Note: I did not create this design, I learned this method a very long time ago
                                    IPAddress EndingAddress = new IPAddress(broadcastBytes);                          //Construct the address using the modified bytes
                                    byte[] networkBytes = new byte[AddressBytes.Length];                              //Create network byte[] that will hold our ending address bytes
                                    for (int i = 0; i < networkBytes.Length; i++)                                     //Cycle through each byte
                                    {
                                        networkBytes[i] = (byte)(AddressBytes[i] & (SubnetBytes[i]));                 //Current byte = Adress Value AND Subnet value
                                    }
                                    IPAddress StartingAddress = new IPAddress(networkBytes);                          //Construct the address using the modified bytes
                                    NetworkAdapters.Add(CurrCard.Name.ToString());
                                    BeginAddresses.Add(StartingAddress.ToString());
                                    EndingAddresses.Add(EndingAddress.ToString());
                                }
                            }
                        }


                    }
                    catch (ArgumentOutOfRangeException)
                    {
                        //Skips Network Adapters that dont have a gateway address
                    }
                }
            }
            Complete.Add(NetworkAdapters);
            Complete.Add(BeginAddresses);
            Complete.Add(EndingAddresses);
            return Complete;
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            List<List<String>> Info = new List<List<String>>();
            Info = GrabInfo();
            Adapters = Info[0];
            StartingAddress = Info[1];
            EndingAddress = Info[2];
            foreach (String CurrAdapter in Adapters)
            {
                comboBox1.Items.Add(CurrAdapter);
            }
            comboBox1.Text = Adapters[Adapters.Count - 1];
            textBox1.Text = StartingAddress[Adapters.IndexOf(comboBox1.Text)];
            textBox2.Text = EndingAddress[Adapters.IndexOf(comboBox1.Text)];
        }

        private void button1_Click(object sender, EventArgs e)
        {
            Thread Scan = new Thread((new ThreadStart(() => SearchAndDestroy(this, textBox1.Text, textBox2.Text))));
            Scan.Start();
        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            textBox1.Text = StartingAddress[Adapters.IndexOf(comboBox1.Text)];
            textBox2.Text = EndingAddress[Adapters.IndexOf(comboBox1.Text)];
        }
    }

    public static class IPCalculator
    {
        //This code is a very old snippet from a source years ago, I cannot find the original source
        //but I thought that I should mention that this was not originally my code

        public static uint ToUInt(this string ipAddress)   //Convert IPAddress to uint type object
        {
            var ip = IPAddress.Parse(ipAddress);
            var bytes = ip.GetAddressBytes();
            Array.Reverse(bytes);
            return BitConverter.ToUInt32(bytes, 0);
        }
        public static string ToString(this uint ipInt)      //Add ToString method for uint objects
        {
            return ToIPAddress(ipInt).ToString();           //Return string format
        }
        public static IPAddress ToIPAddress(this uint ipInt)   //Convert uint to IPAddress type object
        {
            var bytes = BitConverter.GetBytes(ipInt);
            Array.Reverse(bytes);
            return new IPAddress(bytes);
        }
        public static IPAddress ToIPAddress(this String ipString)
        {
            return IPAddress.Parse(ipString);
        }
    }
}
