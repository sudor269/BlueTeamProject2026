using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

public sealed class DriverComm : IDisposable
{
    private readonly ILogger<DriverComm> _log;
    private IntPtr _port = IntPtr.Zero;
    private readonly object _sync = new();

    private const string PortName = @"\UsbGuardPort";

    public DriverComm(ILogger<DriverComm> log)
    {
        _log = log;
    }

    public void Dispose()
    {
        lock (_sync)
        {
            ClosePort_NoLock();
        }
        GC.SuppressFinalize(this);
    }

    ~DriverComm()
    {
        try { Dispose(); } catch { }
    }

    public static ulong ParseHex64(string hex)
    {
        if (string.IsNullOrWhiteSpace(hex))
            throw new ArgumentException("Empty hash", nameof(hex));

        hex = hex.Trim();

        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            hex = hex[2..];

        return ulong.Parse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    }

    public void SetPolicy(bool auditOnly, bool defaultAllowNoSerial)
    {
        lock (_sync)
        {
            EnsureConnected_NoLock();

            var msg = new UgMsgSetPolicy
            {
                Hdr = new UgMsgHeader
                {
                    Command = (uint)UgCmd.SetPolicy,
                    Size = (uint)Marshal.SizeOf<UgMsgSetPolicy>()
                },
                AuditOnly = auditOnly ? (byte)1 : (byte)0,
                DefaultAllowIfNoSerial = defaultAllowNoSerial ? (byte)1 : (byte)0,
                Reserved0 = 0,
                Reserved1 = 0
            };

            byte[] inBytes = StructToBytes(msg);
            SendMessage_NoLock(inBytes, null);

            _log.LogInformation("Driver policy applied: AuditOnly={AuditOnly}, DefaultAllowIfNoSerial={DefaultAllowIfNoSerial}",
                auditOnly, defaultAllowNoSerial);
        }
    }

    public void SetWhitelist(ulong version, ulong[] hashes)
    {
        hashes ??= Array.Empty<ulong>();

        lock (_sync)
        {
            EnsureConnected_NoLock();

            int headerSize = Marshal.SizeOf<UgMsgSetWhitelist>();
            int payloadSize = checked(hashes.Length * sizeof(ulong));
            int totalSize = checked(headerSize + payloadSize);

            byte[] buffer = new byte[totalSize];

            var hdr = new UgMsgSetWhitelist
            {
                Hdr = new UgMsgHeader
                {
                    Command = (uint)UgCmd.SetWhitelist,
                    Size = (uint)totalSize
                },
                Version = checked((uint)version),
                Count = checked((uint)hashes.Length)
            };

            byte[] hdrBytes = StructToBytes(hdr);
            Buffer.BlockCopy(hdrBytes, 0, buffer, 0, hdrBytes.Length);

            for (int i = 0; i < hashes.Length; i++)
            {
                byte[] u64 = BitConverter.GetBytes(hashes[i]); 
                Buffer.BlockCopy(u64, 0, buffer, headerSize + i * sizeof(ulong), sizeof(ulong));
            }

            SendMessage_NoLock(buffer, null);

            _log.LogInformation("Driver whitelist applied: Version={Version}, Count={Count}", version, hashes.Length);
        }
    }

    public void SetWhitelist(ulong version, List<ulong> hashes)
    {
        SetWhitelist(version, hashes?.ToArray() ?? Array.Empty<ulong>());
    }

    public void SetWhitelist(ulong version, IReadOnlyList<ulong> hashes)
    {
        if (hashes == null || hashes.Count == 0)
        {
            SetWhitelist(version, Array.Empty<ulong>());
            return;
        }

        var arr = new ulong[hashes.Count];
        for (int i = 0; i < hashes.Count; i++)
            arr[i] = hashes[i];

        SetWhitelist(version, arr);
    }

    public DriverStatus GetStatus()
    {
        lock (_sync)
        {
            EnsureConnected_NoLock();

            var req = new UgMsgHeader
            {
                Command = (uint)UgCmd.GetStatus,
                Size = (uint)Marshal.SizeOf<UgMsgHeader>()
            };

            byte[] inBytes = StructToBytes(req);
            int outSize = Marshal.SizeOf<UgMsgStatusReply>();
            byte[] outBytes = new byte[outSize];

            int received = SendMessage_NoLock(inBytes, outBytes);
            if (received < outSize)
                throw new InvalidOperationException($"Driver returned too small status reply: {received} bytes");

            var rep = BytesToStruct<UgMsgStatusReply>(outBytes);

            return new DriverStatus
            {
                WlCount = rep.WlCount,
                WlVersion = rep.WlVersion,
                AuditOnly = rep.AuditOnly != 0,
                DefaultAllowIfNoSerial = rep.DefaultAllowIfNoSerial != 0
            };
        }
    }

    private void EnsureConnected_NoLock()
    {
        if (_port != IntPtr.Zero)
            return;

        IntPtr hPort;
        int hr = FilterConnectCommunicationPort(
            PortName,
            0,
            IntPtr.Zero,
            0,
            IntPtr.Zero,
            out hPort);

        if (hr != 0 || hPort == IntPtr.Zero)
        {
            int lastErr = Marshal.GetLastWin32Error();
            throw new Win32Exception(lastErr == 0 ? hr : lastErr,
                $"FilterConnectCommunicationPort failed: hr=0x{hr:X8}, lastError=0x{lastErr:X8}, port={PortName}");
        }

        _port = hPort;
        _log.LogInformation("Connected to driver port {PortName}", PortName);
    }

    private int SendMessage_NoLock(byte[] inBuffer, byte[]? outBuffer)
    {
        if (_port == IntPtr.Zero)
            throw new InvalidOperationException("Driver port is not connected");

        IntPtr inPtr = IntPtr.Zero;
        IntPtr outPtr = IntPtr.Zero;

        try
        {
            inPtr = Marshal.AllocHGlobal(inBuffer.Length);
            Marshal.Copy(inBuffer, 0, inPtr, inBuffer.Length);

            uint outLen = 0;
            uint outCap = 0;

            if (outBuffer != null && outBuffer.Length > 0)
            {
                outCap = (uint)outBuffer.Length;
                outPtr = Marshal.AllocHGlobal(outBuffer.Length);
                for (int i = 0; i < outBuffer.Length; i++) outBuffer[i] = 0;
            }

            int hr = FilterSendMessage(
                _port,
                inPtr,
                (uint)inBuffer.Length,
                outPtr,
                outCap,
                ref outLen);

            if (hr != 0)
            {
                int lastErr = Marshal.GetLastWin32Error();

                if (lastErr == 0x6 || lastErr == 0xE8 || lastErr == 0x1F)
                {
                    _log.LogWarning("Driver communication handle invalid, will reconnect");
                    ClosePort_NoLock();
                }

                throw new Win32Exception(lastErr == 0 ? hr : lastErr,
                    $"FilterSendMessage failed: hr=0x{hr:X8}, lastError=0x{lastErr:X8}");
            }

            if (outBuffer != null && outPtr != IntPtr.Zero && outLen > 0)
            {
                int copyLen = (int)Math.Min((uint)outBuffer.Length, outLen);
                Marshal.Copy(outPtr, outBuffer, 0, copyLen);
                return copyLen;
            }

            return 0;
        }
        finally
        {
            if (inPtr != IntPtr.Zero) Marshal.FreeHGlobal(inPtr);
            if (outPtr != IntPtr.Zero) Marshal.FreeHGlobal(outPtr);
        }
    }

    private void ClosePort_NoLock()
    {
        if (_port != IntPtr.Zero)
        {
            try { CloseHandle(_port); } catch { }
            _port = IntPtr.Zero;
        }
    }

    private static byte[] StructToBytes<T>(T value) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        byte[] bytes = new byte[size];
        IntPtr ptr = IntPtr.Zero;

        try
        {
            ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(value, ptr, false);
            Marshal.Copy(ptr, bytes, 0, size);
            return bytes;
        }
        finally
        {
            if (ptr != IntPtr.Zero)
            {
                Marshal.DestroyStructure<T>(ptr);
                Marshal.FreeHGlobal(ptr);
            }
        }
    }

    private static T BytesToStruct<T>(byte[] bytes) where T : struct
    {
        IntPtr ptr = IntPtr.Zero;
        try
        {
            ptr = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, ptr, bytes.Length);
            return Marshal.PtrToStructure<T>(ptr)!;
        }
        finally
        {
            if (ptr != IntPtr.Zero) Marshal.FreeHGlobal(ptr);
        }
    }

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int FilterConnectCommunicationPort(
        string lpPortName,
        uint dwOptions,
        IntPtr lpContext,
        ushort wSizeOfContext,
        IntPtr lpSecurityAttributes,
        out IntPtr hPort);

    [DllImport("fltlib.dll", SetLastError = true)]
    private static extern int FilterSendMessage(
        IntPtr hPort,
        IntPtr lpInBuffer,
        uint dwInBufferSize,
        IntPtr lpOutBuffer,
        uint dwOutBufferSize,
        ref uint lpBytesReturned);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private enum UgCmd : uint
    {
        SetWhitelist = 1,
        GetStatus = 2,
        SetPolicy = 3
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct UgMsgHeader
    {
        public uint Command;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct UgMsgSetWhitelist
    {
        public UgMsgHeader Hdr;
        public uint Version;
        public uint Count;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct UgMsgSetPolicy
    {
        public UgMsgHeader Hdr;
        public byte AuditOnly;
        public byte DefaultAllowIfNoSerial;
        public byte Reserved0;
        public byte Reserved1;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct UgMsgStatusReply
    {
        public uint WlCount;
        public uint WlVersion;
        public byte AuditOnly;
        public byte DefaultAllowIfNoSerial;
        public byte Reserved0;
        public byte Reserved1;
    }
}

public sealed class DriverStatus
{
    public uint WlCount { get; set; }
    public uint WlVersion { get; set; }
    public bool AuditOnly { get; set; }
    public bool DefaultAllowIfNoSerial { get; set; }
}