using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.IO;
using System.Runtime.InteropServices;

namespace EternalBlue_Scanner
{
    internal class Configuration
    {
        public static readonly string MESSAGE_BOX_HEADER = "Eternal Blues";
        public static readonly int MAX_COMPUTERS_TO_SCAN = 16384;
        public static readonly int RANDOM_ID = new Random().Next();
        public static readonly bool IS_DEBUG = false;
        public static readonly bool REPORT_USAGE = true;
    }

    public class MachineScanResult
    {
        public enum VulnerabilityStatus
        {
            UNKNOWN,
            YES,
            NO_SMB1_DISABLED,
            NO_SMB1_ENABLED,
            NO_RESPONSE_FROM_HOST
        }

        public enum ScanningStatus
        {
            Queued,
            Scanning,
            Done
        }

        private static string DEFAULT_HOST_NAME = "";

        public string ipAddress
        {
            get;
            private set;
        }

        public ScanningStatus scanningStatus
        {
            get;
            private set;
        }

        public VulnerabilityStatus vulnerabilityStatus
        {
            get;
            private set;
        } = VulnerabilityStatus.NO_RESPONSE_FROM_HOST;


        public string hostname
        {
            get;
            private set;
        } = DEFAULT_HOST_NAME;


        public MachineScanResult(string ipAddress)
        {
            this.ipAddress = ipAddress;
        }

        public void UpdateScanningStatus()
        {
            scanningStatus = ScanningStatus.Scanning;
        }

        public string GetHostName()
        {
            if (!hostname.Equals(DEFAULT_HOST_NAME))
            {
                return hostname;
            }
            try
            {
                if (Configuration.IS_DEBUG)
                {
                    return "HOST " + new Random().Next(256);
                }
                IPHostEntry hostEntry = Dns.GetHostEntry(ipAddress);
                if (hostEntry != null)
                {
                    hostname = hostEntry.HostName;
                    return hostname;
                }
            }
            catch (Exception)
            {
            }
            return DEFAULT_HOST_NAME;
        }

        public void UpdateFinishedResult(VulnerabilityStatus vulnerabilityStatus)
        {
            this.vulnerabilityStatus = vulnerabilityStatus;
            scanningStatus = ScanningStatus.Done;
            if (IsLiveMachine())
            {
                hostname = GetHostName();
            }
        }

        public bool IsVulnerable()
        {
            return vulnerabilityStatus == VulnerabilityStatus.YES;
        }

        public bool IsSmb1Enabled()
        {
            if (vulnerabilityStatus != VulnerabilityStatus.NO_RESPONSE_FROM_HOST)
            {
                return vulnerabilityStatus != VulnerabilityStatus.NO_SMB1_DISABLED;
            }
            return false;
        }

        public bool IsLiveMachine()
        {
            return vulnerabilityStatus != VulnerabilityStatus.NO_RESPONSE_FROM_HOST;
        }

        public string VulnerabilityStatusToString()
        {
            if (scanningStatus != ScanningStatus.Done)
            {
                return "";
            }
            if (vulnerabilityStatus == VulnerabilityStatus.NO_RESPONSE_FROM_HOST)
            {
                return "NO RESPONSE";
            }
            if (vulnerabilityStatus == VulnerabilityStatus.NO_SMB1_ENABLED)
            {
                return "NO (SMBv1 enabled)";
            }
            if (vulnerabilityStatus == VulnerabilityStatus.NO_SMB1_DISABLED)
            {
                return "NO";
            }
            return vulnerabilityStatus.ToString();
        }
    }

    public class EternalBlueToolkit
    {
        public static readonly int MAX_COMPUTERS_TO_SCAN = 16384;
        public static readonly int RANDOM_ID = new Random().Next();
        public static readonly bool IS_DEBUG = false;
        public static readonly bool REPORT_USAGE = true;
        private static uint STATUS_SUCCESS = 0u;
        private static uint STATUS_INSUFF_SERVER_RESOURCES = 3221225989u;
        private static uint STATUS_INVALID_HANDLE = 3221225480u;
        private static uint STATUS_ACCESS_DENIED = 3221225506u;
        private static int SEND_TIMEOUT_IN_MILLISECONDS = 5000;
        private static int RECEIVE_TIMEOUT_IN_MILLISECONDS = 5000;
        private enum SmbPayloadStatus
        {
            Connect,
            Neogtiate,
            SessionSetup,
            TreeConnect,
            PeekNamedPipe,
            ReturnCodesCheck
        }
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SMBHeader
        {
            public uint server_component;
            public byte smb_command;
            public uint smb_status;
            public byte flags;
            public ushort flags2;
            public ushort process_id_high;
            public ulong signature;
            public ushort reserved2;
            public ushort tree_id;
            public ushort process_id;
            public ushort user_id;
            public ushort multiplex_id;
        }

        private static bool isSuccessfullSMB(SMBHeader smbHeader)
        {
            return smbHeader.smb_status == STATUS_SUCCESS;
        }

        private static string SmbStatusToMessage(SMBHeader smbHeader)
        {
            return "SMB Status = 0x" + smbHeader.smb_status.ToString("X");
        }

        private static SMBHeader DataToSmbHeader(byte[] data, int receivedBytes, bool allowSuccessfulStatusOnly)
        {
            SMBHeader sMBHeader = default(SMBHeader);
            int num = 4;
            int num2 = Marshal.SizeOf((object)sMBHeader);
            int num3 = num2 + num;
            if (receivedBytes < num3)
            {
                throw new Exception("Bytes received = " + receivedBytes + " while required size = " + num3);
            }
            IntPtr intPtr = Marshal.AllocHGlobal(num2);
            Marshal.Copy(data, num, intPtr, num2);
            sMBHeader = (SMBHeader)Marshal.PtrToStructure(intPtr, typeof(SMBHeader));
            Marshal.FreeHGlobal(intPtr);
            if (allowSuccessfulStatusOnly && !isSuccessfullSMB(sMBHeader))
            {
                throw new Exception(SmbStatusToMessage(sMBHeader));
            }
            return sMBHeader;
        }

        private static void CheckSmbStatus(byte[] data, int receivedBytes)
        {
            DataToSmbHeader(data, receivedBytes, allowSuccessfulStatusOnly: true);
        }

        private static byte[] generateSmbProtoPayload(byte[] netbios, byte[] smb_header, byte[] data)
        {
            return netbios.Concat(smb_header).Concat(data).ToArray();
        }

        private static byte[] negotiateProtoRequest()
        {
            byte[] netbios = new byte[4]
            {
        0,
        0,
        0,
        84
            };
            byte[] smb_header = new byte[32]
            {
        255,
        83,
        77,
        66,
        114,
        0,
        0,
        0,
        0,
        24,
        1,
        40,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        47,
        75,
        0,
        0,
        197,
        94
            };
            byte[] data = new byte[52]
            {
        0,
        49,
        0,
        2,
        76,
        65,
        78,
        77,
        65,
        78,
        49,
        46,
        48,
        0,
        2,
        76,
        77,
        49,
        46,
        50,
        88,
        48,
        48,
        50,
        0,
        2,
        78,
        84,
        32,
        76,
        65,
        78,
        77,
        65,
        78,
        32,
        49,
        46,
        48,
        0,
        2,
        78,
        84,
        32,
        76,
        77,
        32,
        48,
        46,
        49,
        50,
        0
            };
            return generateSmbProtoPayload(netbios, smb_header, data);
        }

        private static byte[] sessionSetupAndxRequest()
        {
            byte[] netbios = new byte[4]
            {
        0,
        0,
        0,
        99
            };
            byte[] smb_header = new byte[32]
            {
        255,
        83,
        77,
        66,
        115,
        0,
        0,
        0,
        0,
        24,
        1,
        32,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        47,
        75,
        0,
        0,
        197,
        94
            };
            byte[] data = new byte[67]
            {
        13,
        255,
        0,
        0,
        0,
        223,
        255,
        2,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        64,
        0,
        0,
        0,
        38,
        0,
        0,
        46,
        0,
        87,
        105,
        110,
        100,
        111,
        119,
        115,
        32,
        50,
        48,
        48,
        48,
        32,
        50,
        49,
        57,
        53,
        0,
        87,
        105,
        110,
        100,
        111,
        119,
        115,
        32,
        50,
        48,
        48,
        48,
        32,
        53,
        46,
        48,
        0
            };
            return generateSmbProtoPayload(netbios, smb_header, data);
        }

        private static byte[] treeConnectAndxRequest(string ip, ushort user_id)
        {
            byte[] array = new byte[4]
            {
        0,
        0,
        0,
        71
            };
            byte[] bytes = BitConverter.GetBytes(user_id);
            byte[] obj = new byte[32]
            {
        255,
        83,
        77,
        66,
        117,
        0,
        0,
        0,
        0,
        24,
        1,
        32,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        47,
        75,
        0,
        0,
        197,
        94
            };
            obj[28] = bytes[0];
            obj[29] = bytes[1];
            byte[] array2 = obj;
            byte[] first = new byte[12]
            {
        4,
        255,
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        26,
        0,
        0
            };
            string s = $"\\\\{ip}\\IPC$";
            byte[] bytes2 = Encoding.UTF8.GetBytes(s);
            byte[] second = new byte[7]
            {
        0,
        63,
        63,
        63,
        63,
        63,
        0
            };
            byte[] array3 = first.Concat(bytes2).Concat(second).ToArray();
            int num = array2.Length;
            int num2 = array3.Length;
            array[3] = (byte)(array2.Length + array3.Length);
            return generateSmbProtoPayload(array, array2, array3);
        }

        private static byte[] peekNamedPipeRequest(ushort tree_id, ushort process_id, ushort user_id, ushort multiplex_id)
        {
            byte[] netbios = new byte[4]
            {
        0,
        0,
        0,
        74
            };
            byte[] smb_header = new byte[24]
            {
        255,
        83,
        77,
        66,
        37,
        0,
        0,
        0,
        0,
        24,
        1,
        40,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0
            }.Concat(BitConverter.GetBytes(tree_id)).Concat(BitConverter.GetBytes(process_id)).Concat(BitConverter.GetBytes(user_id))
                .Concat(BitConverter.GetBytes(multiplex_id))
                .ToArray();
            byte[] data = new byte[42]
            {
        16,
        0,
        0,
        0,
        0,
        255,
        255,
        255,
        255,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        74,
        0,
        0,
        0,
        74,
        0,
        2,
        0,
        35,
        0,
        0,
        0,
        7,
        0,
        92,
        80,
        73,
        80,
        69,
        92,
        0
            };
            return generateSmbProtoPayload(netbios, smb_header, data);
        }

        private static MachineScanResult.VulnerabilityStatus IsVulnerableDebug(string ip, out string statusMessage)
        {
            Random random = new Random();
            Thread.Sleep(random.Next(1000));
            MachineScanResult.VulnerabilityStatus vulnerabilityStatus = (MachineScanResult.VulnerabilityStatus)random.Next(5);
            statusMessage = ip + " is " + ((vulnerabilityStatus == MachineScanResult.VulnerabilityStatus.YES) ? "" : "NOT ") + "vulnerable";
            return vulnerabilityStatus;
        }

        public static MachineScanResult.VulnerabilityStatus IsVulnerableStub(string ip, out string statusMessage)
        {
            statusMessage = "";
            if (!Configuration.IS_DEBUG)
            {
                return IsVulnerable(ip, out statusMessage);
            }
            return IsVulnerableDebug(ip, out statusMessage);
        }

        private static MachineScanResult.VulnerabilityStatus IsVulnerable(string ip, out string statusMessage)
        {
            SmbPayloadStatus smbPayloadStatus = SmbPayloadStatus.Connect;
            MachineScanResult.VulnerabilityStatus vulnerabilityStatus = MachineScanResult.VulnerabilityStatus.NO_RESPONSE_FROM_HOST;
            try
            {
                IPEndPoint iPEndPoint = new IPEndPoint(IPAddress.Parse(ip), 445);
                Socket socket = new Socket(iPEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                socket.SendTimeout = SEND_TIMEOUT_IN_MILLISECONDS;
                socket.ReceiveTimeout = RECEIVE_TIMEOUT_IN_MILLISECONDS;
                socket.ReceiveBufferSize = 1024;
                socket.Connect(iPEndPoint);
                if (!socket.Connected)
                {
                    throw new Exception("Connect failed");
                }
                vulnerabilityStatus = MachineScanResult.VulnerabilityStatus.NO_SMB1_DISABLED;
                smbPayloadStatus = SmbPayloadStatus.Neogtiate;
                byte[] array = new byte[socket.ReceiveBufferSize];
                byte[] buffer = negotiateProtoRequest();
                socket.Send(buffer);
                int receivedBytes = socket.Receive(array);
                CheckSmbStatus(array, receivedBytes);
                vulnerabilityStatus = MachineScanResult.VulnerabilityStatus.NO_SMB1_ENABLED;
                smbPayloadStatus = SmbPayloadStatus.SessionSetup;
                buffer = sessionSetupAndxRequest();
                socket.Send(buffer);
                Array.Clear(array, 0, socket.ReceiveBufferSize);
                receivedBytes = socket.Receive(array);
                SMBHeader sMBHeader = DataToSmbHeader(array, receivedBytes, allowSuccessfulStatusOnly: true);
                smbPayloadStatus = SmbPayloadStatus.TreeConnect;
                buffer = treeConnectAndxRequest(ip, sMBHeader.user_id);
                socket.Send(buffer);
                Array.Clear(array, 0, socket.ReceiveBufferSize);
                receivedBytes = socket.Receive(array);
                SMBHeader sMBHeader2 = DataToSmbHeader(array, receivedBytes, allowSuccessfulStatusOnly: true);
                smbPayloadStatus = SmbPayloadStatus.PeekNamedPipe;
                buffer = peekNamedPipeRequest(sMBHeader2.tree_id, sMBHeader2.process_id, sMBHeader2.user_id, sMBHeader2.multiplex_id);
                socket.Send(buffer);
                Array.Clear(array, 0, socket.ReceiveBufferSize);
                receivedBytes = socket.Receive(array);
                SMBHeader sMBHeader3 = DataToSmbHeader(array, receivedBytes, allowSuccessfulStatusOnly: false);
                smbPayloadStatus = SmbPayloadStatus.ReturnCodesCheck;
                if (sMBHeader3.smb_status != STATUS_INSUFF_SERVER_RESOURCES)
                {
                    if (sMBHeader3.smb_status != STATUS_INVALID_HANDLE && sMBHeader3.smb_status != STATUS_ACCESS_DENIED)
                    {
                        vulnerabilityStatus = MachineScanResult.VulnerabilityStatus.UNKNOWN;
                    }
                    throw new Exception(SmbStatusToMessage(sMBHeader3));
                }
                statusMessage = ip.ToString() + " is VULNERABLE!!!!!!";
                return MachineScanResult.VulnerabilityStatus.YES;
            }
            catch (Exception ex)
            {
                statusMessage = ip.ToString() + " ; Check Status = " + smbPayloadStatus + " ; Vulnerability Status = " + vulnerabilityStatus + " ; Message = " + ex.ToString();
                return vulnerabilityStatus;
            }
        }

    }
}
