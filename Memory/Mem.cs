using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Memory;

public class Mem
{
	internal enum MINIDUMP_TYPE
	{
		MiniDumpNormal = 0,
		MiniDumpWithDataSegs = 1,
		MiniDumpWithFullMemory = 2,
		MiniDumpWithHandleData = 4,
		MiniDumpFilterMemory = 8,
		MiniDumpScanMemory = 0x10,
		MiniDumpWithUnloadedModules = 0x20,
		MiniDumpWithIndirectlyReferencedMemory = 0x40,
		MiniDumpFilterModulePaths = 0x80,
		MiniDumpWithProcessThreadData = 0x100,
		MiniDumpWithPrivateReadWriteMemory = 0x200,
		MiniDumpWithoutOptionalData = 0x400,
		MiniDumpWithFullMemoryInfo = 0x800,
		MiniDumpWithThreadInfo = 0x1000,
		MiniDumpWithCodeSegs = 0x2000
	}

	[Flags]
	public enum ThreadAccess
	{
		TERMINATE = 1,
		SUSPEND_RESUME = 2,
		GET_CONTEXT = 8,
		SET_CONTEXT = 0x10,
		SET_INFORMATION = 0x20,
		QUERY_INFORMATION = 0x40,
		SET_THREAD_TOKEN = 0x80,
		IMPERSONATE = 0x100,
		DIRECT_IMPERSONATION = 0x200
	}

	public struct SYSTEM_INFO
	{
		public ushort processorArchitecture;

		private ushort reserved;

		public uint pageSize;

		public UIntPtr minimumApplicationAddress;

		public UIntPtr maximumApplicationAddress;

		public IntPtr activeProcessorMask;

		public uint numberOfProcessors;

		public uint processorType;

		public uint allocationGranularity;

		public ushort processorLevel;

		public ushort processorRevision;
	}

	public struct MEMORY_BASIC_INFORMATION32
	{
		public UIntPtr BaseAddress;

		public UIntPtr AllocationBase;

		public uint AllocationProtect;

		public uint RegionSize;

		public uint State;

		public uint Protect;

		public uint Type;
	}

	public struct MEMORY_BASIC_INFORMATION64
	{
		public UIntPtr BaseAddress;

		public UIntPtr AllocationBase;

		public uint AllocationProtect;

		public uint __alignment1;

		public ulong RegionSize;

		public uint State;

		public uint Protect;

		public uint Type;

		public uint __alignment2;
	}

	public struct MEMORY_BASIC_INFORMATION
	{
		public UIntPtr BaseAddress;

		public UIntPtr AllocationBase;

		public uint AllocationProtect;

		public long RegionSize;

		public uint State;

		public uint Protect;

		public uint Type;
	}

	private const int PROCESS_CREATE_THREAD = 2;

	private const int PROCESS_QUERY_INFORMATION = 1024;

	private const int PROCESS_VM_OPERATION = 8;

	private const int PROCESS_VM_WRITE = 32;

	private const int PROCESS_VM_READ = 16;

	private const uint MEM_FREE = 65536u;

	private const uint MEM_COMMIT = 4096u;

	private const uint MEM_RESERVE = 8192u;

	private const uint PAGE_READONLY = 2u;

	private const uint PAGE_READWRITE = 4u;

	private const uint PAGE_WRITECOPY = 8u;

	private const uint PAGE_EXECUTE_READWRITE = 64u;

	private const uint PAGE_EXECUTE_WRITECOPY = 128u;

	private const uint PAGE_EXECUTE = 16u;

	private const uint PAGE_EXECUTE_READ = 32u;

	private const uint PAGE_GUARD = 256u;

	private const uint PAGE_NOACCESS = 1u;

	private uint MEM_PRIVATE = 131072u;

	private uint MEM_IMAGE = 16777216u;

	public IntPtr pHandle;

	private Dictionary<string, CancellationTokenSource> FreezeTokenSrcs = new Dictionary<string, CancellationTokenSource>();

	public Process? theProc;

	private bool _is64Bit;

	public Dictionary<string, IntPtr> modules = new Dictionary<string, IntPtr>();

	private ProcessModule? mainModule;

	public bool Is64Bit
	{
		get
		{
			return _is64Bit;
		}
		private set
		{
			_is64Bit = value;
		}
	}

	[DllImport("kernel32.dll")]
	public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

	[DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
	public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION32 lpBuffer, UIntPtr dwLength);

	[DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
	public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, UIntPtr dwLength);

	[DllImport("kernel32.dll")]
	private static extern uint GetLastError();

	public UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer)
	{
		if (Is64Bit || IntPtr.Size == 8)
		{
			MEMORY_BASIC_INFORMATION64 lpBuffer2 = default(MEMORY_BASIC_INFORMATION64);
			UIntPtr result = Native_VirtualQueryEx(hProcess, lpAddress, out lpBuffer2, new UIntPtr((uint)Marshal.SizeOf(lpBuffer2)));
			lpBuffer.BaseAddress = lpBuffer2.BaseAddress;
			lpBuffer.AllocationBase = lpBuffer2.AllocationBase;
			lpBuffer.AllocationProtect = lpBuffer2.AllocationProtect;
			lpBuffer.RegionSize = (long)lpBuffer2.RegionSize;
			lpBuffer.State = lpBuffer2.State;
			lpBuffer.Protect = lpBuffer2.Protect;
			lpBuffer.Type = lpBuffer2.Type;
			return result;
		}
		MEMORY_BASIC_INFORMATION32 lpBuffer3 = default(MEMORY_BASIC_INFORMATION32);
		UIntPtr result2 = Native_VirtualQueryEx(hProcess, lpAddress, out lpBuffer3, new UIntPtr((uint)Marshal.SizeOf(lpBuffer3)));
		lpBuffer.BaseAddress = lpBuffer3.BaseAddress;
		lpBuffer.AllocationBase = lpBuffer3.AllocationBase;
		lpBuffer.AllocationProtect = lpBuffer3.AllocationProtect;
		lpBuffer.RegionSize = lpBuffer3.RegionSize;
		lpBuffer.State = lpBuffer3.State;
		lpBuffer.Protect = lpBuffer3.Protect;
		lpBuffer.Type = lpBuffer3.Type;
		return result2;
	}

	[DllImport("kernel32.dll")]
	private static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

	[DllImport("kernel32.dll")]
	private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

	[DllImport("kernel32.dll")]
	private static extern uint SuspendThread(IntPtr hThread);

	[DllImport("kernel32.dll")]
	private static extern int ResumeThread(IntPtr hThread);

	[DllImport("dbghelp.dll")]
	private static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, IntPtr hFile, MINIDUMP_TYPE DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallackParam);

	[DllImport("user32.dll", SetLastError = true)]
	private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

	[DllImport("user32.dll", CharSet = CharSet.Auto)]
	public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr w, IntPtr l);

	[DllImport("kernel32.dll")]
	private static extern bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, string lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesWritten);

	[DllImport("kernel32.dll")]
	private static extern int GetProcessId(IntPtr handle);

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
	private static extern uint GetPrivateProfileString(string lpAppName, string lpKeyName, string lpDefault, StringBuilder lpReturnedString, uint nSize, string lpFileName);

	[DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
	private static extern bool VirtualFreeEx(IntPtr hProcess, UIntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

	[DllImport("kernel32.dll")]
	private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesRead);

	[DllImport("kernel32.dll")]
	private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, out ulong lpNumberOfBytesRead);

	[DllImport("kernel32.dll")]
	private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] IntPtr lpBuffer, UIntPtr nSize, out ulong lpNumberOfBytesRead);

	[DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
	private static extern UIntPtr VirtualAllocEx(IntPtr hProcess, UIntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

	[DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
	public static extern UIntPtr GetProcAddress(IntPtr hModule, string procName);

	[DllImport("kernel32.dll", EntryPoint = "CloseHandle")]
	private static extern bool _CloseHandle(IntPtr hObject);

	[DllImport("kernel32.dll")]
	public static extern int CloseHandle(IntPtr hObject);

	[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
	public static extern IntPtr GetModuleHandle(string lpModuleName);

	[DllImport("kernel32", ExactSpelling = true, SetLastError = true)]
	internal static extern int WaitForSingleObject(IntPtr handle, int milliseconds);

	[DllImport("kernel32.dll")]
	private static extern bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesWritten);

	[DllImport("kernel32.dll")]
	private static extern bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesWritten);

	[DllImport("kernel32")]
	public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, UIntPtr lpStartAddress, UIntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

	[DllImport("kernel32")]
	public static extern bool IsWow64Process(IntPtr hProcess, out bool lpSystemInfo);

	[DllImport("user32.dll")]
	private static extern bool SetForegroundWindow(IntPtr hWnd);

	private bool IsDigitsOnly(string str)
	{
		foreach (char c in str)
		{
			if (c < '0' || c > '9')
			{
				return false;
			}
		}
		return true;
	}

	public void FreezeValue(string address, string type, string value, string file = "")
	{
		CancellationTokenSource cts = new CancellationTokenSource();
		if (FreezeTokenSrcs.ContainsKey(address))
		{
			try
			{
				FreezeTokenSrcs[address].Cancel();
				FreezeTokenSrcs.Remove(address);
			}
			catch
			{
			}
		}
		FreezeTokenSrcs.Add(address, cts);
		Task.Factory.StartNew(delegate
		{
			while (!cts.Token.IsCancellationRequested)
			{
				writeMemory(address, type, value, file);
				Thread.Sleep(25);
			}
		}, cts.Token);
	}

	public void UnfreezeValue(string address)
	{
		try
		{
			FreezeTokenSrcs[address].Cancel();
			FreezeTokenSrcs.Remove(address);
		}
		catch
		{
		}
	}

	public bool OpenProcess(int pid)
	{
		try
		{
			if (theProc != null && theProc.Id == pid)
			{
				return true;
			}
			if (pid <= 0)
			{
				return false;
			}
			theProc = Process.GetProcessById(pid);
			if (theProc != null && !theProc.Responding)
			{
				return false;
			}
			pHandle = OpenProcess(2035711u, bInheritHandle: true, pid);
			if (pHandle == IntPtr.Zero)
			{
				Marshal.GetLastWin32Error();
			}
			mainModule = theProc!.MainModule;
			getModules();
			Is64Bit = Environment.Is64BitOperatingSystem && IsWow64Process(pHandle, out var lpSystemInfo) && !lpSystemInfo;
			return true;
		}
		catch
		{
			return false;
		}
	}

	public bool OpenProcess(string proc)
	{
		return OpenProcess(getProcIDFromName(proc));
	}

	public bool isAdmin()
	{
		using WindowsIdentity ntIdentity = WindowsIdentity.GetCurrent();
		return new WindowsPrincipal(ntIdentity).IsInRole(WindowsBuiltInRole.Administrator);
	}

	public bool is64bit()
	{
		return Is64Bit;
	}

	public void getModules()
	{
		if (theProc == null)
		{
			return;
		}
		modules.Clear();
		foreach (ProcessModule module in theProc!.Modules)
		{
			if (!string.IsNullOrEmpty(module.ModuleName) && !modules.ContainsKey(module.ModuleName))
			{
				modules.Add(module.ModuleName, module.BaseAddress);
			}
		}
	}

	public void setFocus()
	{
		if (theProc != null)
		{
			SetForegroundWindow(theProc.MainWindowHandle);
		}
	}

	public int getProcIDFromName(string name)
	{
		Process[] processes = Process.GetProcesses();
		if (name.Contains(".exe"))
		{
			name = name.Replace(".exe", "");
		}
		Process[] array = processes;
		foreach (Process process in array)
		{
			if (process.ProcessName.Equals(name, StringComparison.CurrentCultureIgnoreCase))
			{
				return process.Id;
			}
		}
		return 0;
	}

	public string byteArrayToString(byte[] buffer)
	{
		StringBuilder stringBuilder = new StringBuilder();
		int num = 1;
		foreach (byte b in buffer)
		{
			stringBuilder.Append($"0x{b:X}");
			if (num < buffer.Count())
			{
				stringBuilder.Append(" ");
			}
			num++;
		}
		return stringBuilder.ToString();
	}

	public string LoadCode(string name, string file)
	{
		StringBuilder stringBuilder = new StringBuilder(1024);
		if (file != "")
		{
			GetPrivateProfileString("codes", name, "", stringBuilder, (uint)stringBuilder.Capacity, file);
		}
		else
		{
			stringBuilder.Append(name);
		}
		return stringBuilder.ToString();
	}

	private int LoadIntCode(string name, string path)
	{
		try
		{
			int num = Convert.ToInt32(LoadCode(name, path), 16);
			if (num >= 0)
			{
				return num;
			}
			return 0;
		}
		catch
		{
			return 0;
		}
	}

	public void ThreadStartClient(string func, string name)
	{
		using NamedPipeClientStream namedPipeClientStream = new NamedPipeClientStream(name);
		if (!namedPipeClientStream.IsConnected)
		{
			namedPipeClientStream.Connect();
		}
		using StreamWriter streamWriter = new StreamWriter(namedPipeClientStream);
		if (!streamWriter.AutoFlush)
		{
			streamWriter.AutoFlush = true;
		}
		streamWriter.WriteLine(func);
	}

	public string CutString(string str)
	{
		StringBuilder stringBuilder = new StringBuilder();
		foreach (char c in str)
		{
			if (c < ' ' || c > '~')
			{
				break;
			}
			stringBuilder.Append(c);
		}
		return stringBuilder.ToString();
	}

	public string sanitizeString(string str)
	{
		StringBuilder stringBuilder = new StringBuilder();
		foreach (char c in str)
		{
			if (c >= ' ' && c <= '~')
			{
				stringBuilder.Append(c);
			}
		}
		return stringBuilder.ToString();
	}

	public byte[]? readBytes(string code, long length, string file = "")
	{
		byte[] array = new byte[length];
		UIntPtr code2 = getCode(code, file);
		if (!ReadProcessMemory(pHandle, code2, array, (UIntPtr)(ulong)length, IntPtr.Zero))
		{
			return null;
		}
		return array;
	}

	public float readFloat(string code, string file = "", bool round = false)
	{
		byte[] array = new byte[4];
		UIntPtr code2 = getCode(code, file);
		try
		{
			if (ReadProcessMemory(pHandle, code2, array, (UIntPtr)4uL, IntPtr.Zero))
			{
				float num = BitConverter.ToSingle(array, 0);
				float result = num;
				if (round)
				{
					result = (float)Math.Round(num, 2);
				}
				return result;
			}
			return 0f;
		}
		catch
		{
			return 0f;
		}
	}

	public string readString(string code, string file = "", int length = 64, bool zeroTerminated = true)
	{
		byte[] array = new byte[length];
		UIntPtr code2 = getCode(code, file);
		if (ReadProcessMemory(pHandle, code2, array, (UIntPtr)(ulong)length, IntPtr.Zero))
		{
			if (!zeroTerminated)
			{
				return Encoding.UTF8.GetString(array);
			}
			return Encoding.UTF8.GetString(array).Split(default(char))[0];
		}
		return "";
	}

	public double readDouble(string code, string file = "", bool round = true)
	{
		byte[] array = new byte[8];
		UIntPtr code2 = getCode(code, file);
		try
		{
			if (ReadProcessMemory(pHandle, code2, array, (UIntPtr)8uL, IntPtr.Zero))
			{
				double num = BitConverter.ToDouble(array, 0);
				double result = num;
				if (round)
				{
					result = Math.Round(num, 2);
				}
				return result;
			}
			return 0.0;
		}
		catch
		{
			return 0.0;
		}
	}

	public int readUIntPtr(UIntPtr code)
	{
		byte[] array = new byte[4];
		if (ReadProcessMemory(pHandle, code, array, (UIntPtr)4uL, IntPtr.Zero))
		{
			return BitConverter.ToInt32(array, 0);
		}
		return 0;
	}

	public int readInt(string code, string file = "")
	{
		byte[] array = new byte[4];
		UIntPtr code2 = getCode(code, file);
		if (ReadProcessMemory(pHandle, code2, array, (UIntPtr)4uL, IntPtr.Zero))
		{
			return BitConverter.ToInt32(array, 0);
		}
		return 0;
	}

	public long readLong(string code, string file = "")
	{
		byte[] array = new byte[16];
		UIntPtr code2 = getCode(code, file);
		if (ReadProcessMemory(pHandle, code2, array, (UIntPtr)16uL, IntPtr.Zero))
		{
			return BitConverter.ToInt64(array, 0);
		}
		return 0L;
	}

	public ulong readUInt(string code, string file = "")
	{
		byte[] array = new byte[4];
		UIntPtr code2 = getCode(code, file);
		if (ReadProcessMemory(pHandle, code2, array, (UIntPtr)4uL, IntPtr.Zero))
		{
			return BitConverter.ToUInt64(array, 0);
		}
		return 0uL;
	}

	public int read2ByteMove(string code, int moveQty, string file = "")
	{
		byte[] array = new byte[4];
		UIntPtr lpBaseAddress = UIntPtr.Add(getCode(code, file), moveQty);
		if (ReadProcessMemory(pHandle, lpBaseAddress, array, (UIntPtr)2uL, IntPtr.Zero))
		{
			return BitConverter.ToInt32(array, 0);
		}
		return 0;
	}

	public int readIntMove(string code, int moveQty, string file = "")
	{
		byte[] array = new byte[4];
		UIntPtr lpBaseAddress = UIntPtr.Add(getCode(code, file), moveQty);
		if (ReadProcessMemory(pHandle, lpBaseAddress, array, (UIntPtr)4uL, IntPtr.Zero))
		{
			return BitConverter.ToInt32(array, 0);
		}
		return 0;
	}

	public ulong readUIntMove(string code, int moveQty, string file = "")
	{
		byte[] array = new byte[8];
		UIntPtr lpBaseAddress = UIntPtr.Add(getCode(code, file), moveQty);
		if (ReadProcessMemory(pHandle, lpBaseAddress, array, (UIntPtr)8uL, IntPtr.Zero))
		{
			return BitConverter.ToUInt64(array, 0);
		}
		return 0uL;
	}

	public int read2Byte(string code, string file = "")
	{
		byte[] array = new byte[4];
		UIntPtr code2 = getCode(code, file);
		if (ReadProcessMemory(pHandle, code2, array, (UIntPtr)2uL, IntPtr.Zero))
		{
			return BitConverter.ToInt32(array, 0);
		}
		return 0;
	}

	public int readByte(string code, string file = "")
	{
		byte[] array = new byte[1];
		UIntPtr code2 = getCode(code, file);
		if (ReadProcessMemory(pHandle, code2, array, (UIntPtr)1uL, IntPtr.Zero))
		{
			return array[0];
		}
		return 0;
	}

	public bool[] readBits(string code, string file = "")
	{
		byte[] array = new byte[1];
		UIntPtr code2 = getCode(code, file);
		bool[] array2 = new bool[8];
		if (!ReadProcessMemory(pHandle, code2, array, (UIntPtr)1uL, IntPtr.Zero))
		{
			return array2;
		}
		if (!BitConverter.IsLittleEndian)
		{
			throw new Exception("Should be little endian");
		}
		for (int i = 0; i < 8; i++)
		{
			array2[i] = Convert.ToBoolean(array[0] & (1 << i));
		}
		return array2;
	}

	public int readPByte(UIntPtr address, string code, string file = "")
	{
		byte[] array = new byte[4];
		if (ReadProcessMemory(pHandle, UIntPtr.Add(address, LoadIntCode(code, file)), array, (UIntPtr)1uL, IntPtr.Zero))
		{
			return BitConverter.ToInt32(array, 0);
		}
		return 0;
	}

	public float readPFloat(UIntPtr address, string code, string file = "")
	{
		byte[] array = new byte[4];
		if (ReadProcessMemory(pHandle, UIntPtr.Add(address, LoadIntCode(code, file)), array, (UIntPtr)4uL, IntPtr.Zero))
		{
			return (float)Math.Round(BitConverter.ToSingle(array, 0), 2);
		}
		return 0f;
	}

	public int readPInt(UIntPtr address, string code, string file = "")
	{
		byte[] array = new byte[4];
		if (ReadProcessMemory(pHandle, UIntPtr.Add(address, LoadIntCode(code, file)), array, (UIntPtr)4uL, IntPtr.Zero))
		{
			return BitConverter.ToInt32(array, 0);
		}
		return 0;
	}

	public string readPString(UIntPtr address, string code, string file = "")
	{
		byte[] array = new byte[32];
		if (ReadProcessMemory(pHandle, UIntPtr.Add(address, LoadIntCode(code, file)), array, (UIntPtr)32uL, IntPtr.Zero))
		{
			return CutString(Encoding.ASCII.GetString(array));
		}
		return "";
	}

	public bool writeMemory(string code, string type, string write, string file = "")
	{
		byte[] array = new byte[4];
		int num = 4;
		UIntPtr code2 = getCode(code, file);
		switch (type)
		{
		case "float":
			array = BitConverter.GetBytes(Convert.ToSingle(write));
			num = 4;
			break;
		case "int":
			array = BitConverter.GetBytes(Convert.ToInt32(write));
			num = 4;
			break;
		case "byte":
			array = new byte[1] { Convert.ToByte(write, 16) };
			num = 1;
			break;
		case "2bytes":
			array = new byte[2]
			{
				(byte)(Convert.ToInt32(write) % 256),
				(byte)(Convert.ToInt32(write) / 256)
			};
			num = 2;
			break;
		case "bytes":
			if (write.Contains(",") || write.Contains(" "))
			{
				string[] array2 = ((!write.Contains(",")) ? write.Split(' ') : write.Split(','));
				int num2 = array2.Count();
				array = new byte[num2];
				for (int i = 0; i < num2; i++)
				{
					array[i] = Convert.ToByte(array2[i], 16);
				}
				num = array2.Count();
			}
			else
			{
				array = new byte[1] { Convert.ToByte(write, 16) };
				num = 1;
			}
			break;
		case "double":
			array = BitConverter.GetBytes(Convert.ToDouble(write));
			num = 8;
			break;
		case "long":
			array = BitConverter.GetBytes(Convert.ToInt64(write));
			num = 8;
			break;
		case "string":
			array = new byte[write.Length];
			array = Encoding.UTF8.GetBytes(write);
			num = write.Length;
			break;
		}
		return WriteProcessMemory(pHandle, code2, array, (UIntPtr)(ulong)num, IntPtr.Zero);
	}

	public bool writeMove(string code, string type, string write, int moveQty, string file = "")
	{
		byte[] lpBuffer = new byte[4];
		int num = 4;
		UIntPtr code2 = getCode(code, file);
		switch (type)
		{
		case "float":
			lpBuffer = new byte[write.Length];
			lpBuffer = BitConverter.GetBytes(Convert.ToSingle(write));
			num = write.Length;
			break;
		case "int":
			lpBuffer = BitConverter.GetBytes(Convert.ToInt32(write));
			num = 4;
			break;
		case "double":
			lpBuffer = BitConverter.GetBytes(Convert.ToDouble(write));
			num = 8;
			break;
		case "long":
			lpBuffer = BitConverter.GetBytes(Convert.ToInt64(write));
			num = 8;
			break;
		case "byte":
			lpBuffer = new byte[1] { Convert.ToByte(write, 16) };
			num = 1;
			break;
		case "string":
			lpBuffer = new byte[write.Length];
			lpBuffer = Encoding.UTF8.GetBytes(write);
			num = write.Length;
			break;
		}
		UIntPtr lpBaseAddress = UIntPtr.Add(code2, moveQty);
		Thread.Sleep(1000);
		return WriteProcessMemory(pHandle, lpBaseAddress, lpBuffer, (UIntPtr)(ulong)num, IntPtr.Zero);
	}

	public void writeBytes(string code, byte[] write, string file = "")
	{
		UIntPtr code2 = getCode(code, file);
		WriteProcessMemory(pHandle, code2, write, (UIntPtr)(ulong)write.Length, IntPtr.Zero);
	}

	public void writeBits(string code, bool[] bits, string file = "")
	{
		if (bits.Length != 8)
		{
			throw new ArgumentException("Not enough bits for a whole byte", "bits");
		}
		byte[] array = new byte[1];
		UIntPtr code2 = getCode(code, file);
		for (int i = 0; i < 8; i++)
		{
			if (bits[i])
			{
				array[0] |= (byte)(1 << i);
			}
		}
		WriteProcessMemory(pHandle, code2, array, (UIntPtr)1uL, IntPtr.Zero);
	}

	public void writeBytes(UIntPtr address, byte[] write)
	{
		WriteProcessMemory(pHandle, address, write, (UIntPtr)(ulong)write.Length, out var _);
	}

	public UIntPtr getCode(string name, string path = "", int size = 8)
	{
		string text = "";
		if (is64bit())
		{
			if (size == 8)
			{
				size = 16;
			}
			return get64bitCode(name, path, size);
		}
		text = ((!(path != "")) ? name : LoadCode(name, path));
		if (text == "")
		{
			return UIntPtr.Zero;
		}
		if (text.Contains(" "))
		{
			text.Replace(" ", string.Empty);
		}
		if (!text.Contains("+") && !text.Contains(","))
		{
			return new UIntPtr(Convert.ToUInt32(text, 16));
		}
		string text2 = text;
		if (text.Contains("+"))
		{
			text2 = text.Substring(text.IndexOf('+') + 1);
		}
		byte[] array = new byte[size];
		if (text2.Contains(','))
		{
			List<int> list = new List<int>();
			string[] array2 = text2.Split(',');
			foreach (string text3 in array2)
			{
				string text4 = text3;
				if (text3.Contains("0x"))
				{
					text4 = text3.Replace("0x", "");
				}
				int num = 0;
				if (!text3.Contains("-"))
				{
					num = int.Parse(text4, NumberStyles.AllowHexSpecifier);
				}
				else
				{
					text4 = text4.Replace("-", "");
					num = int.Parse(text4, NumberStyles.AllowHexSpecifier);
					num *= -1;
				}
				list.Add(num);
			}
			int[] array3 = list.ToArray();
			if (text.Contains("base") || text.Contains("main"))
			{
				ReadProcessMemory(pHandle, (UIntPtr)(ulong)((int)(mainModule?.BaseAddress ?? IntPtr.Zero) + array3[0]), array, (UIntPtr)(ulong)size, IntPtr.Zero);
			}
			else if (!text.Contains("base") && !text.Contains("main") && text.Contains("+"))
			{
				string[] array4 = text.Split('+');
				IntPtr intPtr = IntPtr.Zero;
				if (!array4[0].Contains(".dll") && !array4[0].Contains(".exe"))
				{
					string text5 = array4[0];
					if (text5.Contains("0x"))
					{
						text5 = text5.Replace("0x", "");
					}
					intPtr = (IntPtr)int.Parse(text5, NumberStyles.HexNumber);
				}
				else
				{
					try
					{
						intPtr = modules[array4[0]];
					}
					catch
					{
					}
				}
				ReadProcessMemory(pHandle, (UIntPtr)(ulong)((int)intPtr + array3[0]), array, (UIntPtr)(ulong)size, IntPtr.Zero);
			}
			else
			{
				ReadProcessMemory(pHandle, (UIntPtr)(ulong)array3[0], array, (UIntPtr)(ulong)size, IntPtr.Zero);
			}
			uint num2 = BitConverter.ToUInt32(array, 0);
			UIntPtr uIntPtr = (UIntPtr)0uL;
			for (int j = 1; j < array3.Length; j++)
			{
				uIntPtr = new UIntPtr(Convert.ToUInt32(num2 + array3[j]));
				ReadProcessMemory(pHandle, uIntPtr, array, (UIntPtr)(ulong)size, IntPtr.Zero);
				num2 = BitConverter.ToUInt32(array, 0);
			}
			return uIntPtr;
		}
		int num3 = Convert.ToInt32(text2, 16);
		IntPtr intPtr2 = IntPtr.Zero;
		if (text.Contains("base") || text.Contains("main"))
		{
			intPtr2 = mainModule?.BaseAddress ?? IntPtr.Zero;
		}
		else if (!text.Contains("base") && !text.Contains("main") && text.Contains("+"))
		{
			string[] array5 = text.Split('+');
			if (!array5[0].Contains(".dll") && !array5[0].Contains(".exe"))
			{
				string text6 = array5[0];
				if (text6.Contains("0x"))
				{
					text6 = text6.Replace("0x", "");
				}
				intPtr2 = (IntPtr)int.Parse(text6, NumberStyles.HexNumber);
			}
			else
			{
				try
				{
					intPtr2 = modules[array5[0]];
				}
				catch
				{
				}
			}
		}
		else
		{
			intPtr2 = modules[text.Split('+')[0]];
		}
		return (UIntPtr)(ulong)((int)intPtr2 + num3);
	}

	public UIntPtr get64bitCode(string name, string path = "", int size = 16)
	{
		string text = "";
		text = ((!(path != "")) ? name : LoadCode(name, path));
		if (text == "")
		{
			return UIntPtr.Zero;
		}
		if (text.Contains(" "))
		{
			text.Replace(" ", string.Empty);
		}
		string text2 = text;
		if (text.Contains("+"))
		{
			text2 = text.Substring(text.IndexOf('+') + 1);
		}
		byte[] array = new byte[size];
		if (!text.Contains("+") && !text.Contains(","))
		{
			return new UIntPtr(Convert.ToUInt64(text, 16));
		}
		if (text2.Contains(','))
		{
			List<long> list = new List<long>();
			string[] array2 = text2.Split(',');
			foreach (string text3 in array2)
			{
				string text4 = text3;
				if (text3.Contains("0x"))
				{
					text4 = text3.Replace("0x", "");
				}
				long num = 0L;
				if (!text3.Contains("-"))
				{
					num = long.Parse(text4, NumberStyles.AllowHexSpecifier);
				}
				else
				{
					text4 = text4.Replace("-", "");
					num = long.Parse(text4, NumberStyles.AllowHexSpecifier);
					num *= -1;
				}
				list.Add(num);
			}
			long[] array3 = list.ToArray();
			if (text.Contains("base") || text.Contains("main"))
			{
				ReadProcessMemory(pHandle, (UIntPtr)(ulong)((long)(mainModule?.BaseAddress ?? IntPtr.Zero) + array3[0]), array, (UIntPtr)(ulong)size, IntPtr.Zero);
			}
			else if (!text.Contains("base") && !text.Contains("main") && text.Contains("+"))
			{
				string[] array4 = text.Split('+');
				IntPtr intPtr = IntPtr.Zero;
				if (!array4[0].Contains(".dll") && !array4[0].Contains(".exe"))
				{
					intPtr = (IntPtr)long.Parse(array4[0], NumberStyles.HexNumber);
				}
				else
				{
					try
					{
						intPtr = modules[array4[0]];
					}
					catch
					{
					}
				}
				ReadProcessMemory(pHandle, (UIntPtr)(ulong)((long)intPtr + array3[0]), array, (UIntPtr)(ulong)size, IntPtr.Zero);
			}
			else
			{
				ReadProcessMemory(pHandle, (UIntPtr)(ulong)array3[0], array, (UIntPtr)(ulong)size, IntPtr.Zero);
			}
			long num2 = BitConverter.ToInt64(array, 0);
			UIntPtr uIntPtr = (UIntPtr)0uL;
			for (int j = 1; j < array3.Length; j++)
			{
				uIntPtr = new UIntPtr(Convert.ToUInt64(num2 + array3[j]));
				ReadProcessMemory(pHandle, uIntPtr, array, (UIntPtr)(ulong)size, IntPtr.Zero);
				num2 = BitConverter.ToInt64(array, 0);
			}
			return uIntPtr;
		}
		long num3 = Convert.ToInt64(text2, 16);
		IntPtr intPtr2 = IntPtr.Zero;
		if (text.Contains("base") || text.Contains("main"))
		{
			intPtr2 = mainModule?.BaseAddress ?? IntPtr.Zero;
		}
		else if (!text.Contains("base") && !text.Contains("main") && text.Contains("+"))
		{
			string[] array5 = text.Split('+');
			if (!array5[0].Contains(".dll") && !array5[0].Contains(".exe"))
			{
				string text5 = array5[0];
				if (text5.Contains("0x"))
				{
					text5 = text5.Replace("0x", "");
				}
				intPtr2 = (IntPtr)long.Parse(text5, NumberStyles.HexNumber);
			}
			else
			{
				try
				{
					intPtr2 = modules[array5[0]];
				}
				catch
				{
				}
			}
		}
		else
		{
			intPtr2 = modules[text.Split('+')[0]];
		}
		return (UIntPtr)(ulong)((long)intPtr2 + num3);
	}

	public void closeProcess()
	{
		_ = pHandle;
		CloseHandle(pHandle);
		theProc = null;
	}

	public unsafe void InjectDLL(string strDLLName)
	{
		if (theProc == null) return;
		foreach (ProcessModule module in theProc.Modules)
		{
			if (module.ModuleName.StartsWith("inject", StringComparison.InvariantCultureIgnoreCase))
			{
				return;
			}
		}
		if (theProc.Responding)
		{
			int num = strDLLName.Length + 1;
			UIntPtr uIntPtr = VirtualAllocEx(pHandle, (UIntPtr)(void*)null, (uint)num, 12288u, 4u);
			WriteProcessMemory(pHandle, uIntPtr, strDLLName, (UIntPtr)(ulong)num, out var lpNumberOfBytesWritten);
			UIntPtr procAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
			IntPtr intPtr = CreateRemoteThread(pHandle, (IntPtr)(void*)null, 0u, procAddress, uIntPtr, 0u, out lpNumberOfBytesWritten);
			int num2 = WaitForSingleObject(intPtr, 10000);
			if ((long)num2 == 128 || (long)num2 == 258)
			{
				CloseHandle(intPtr);
				return;
			}
			VirtualFreeEx(pHandle, uIntPtr, (UIntPtr)0uL, 32768u);
			CloseHandle(intPtr);
		}
	}

	public UIntPtr CreateCodeCave(string code, byte[] newBytes, int replaceCount, int size = 65536, string file = "")
	{
		if (replaceCount < 5)
		{
			return UIntPtr.Zero;
		}
		UIntPtr code2 = getCode(code, file);
		UIntPtr uIntPtr = UIntPtr.Zero;
		UIntPtr uIntPtr2 = code2;
		for (int i = 0; i < 10; i++)
		{
			if (!(uIntPtr == UIntPtr.Zero))
			{
				break;
			}
			uIntPtr = VirtualAllocEx(pHandle, FindFreeBlockForRegion(uIntPtr2, (uint)newBytes.Length), (uint)size, 12288u, 64u);
			if (uIntPtr == UIntPtr.Zero)
			{
				uIntPtr2 = UIntPtr.Add(uIntPtr2, 65536);
			}
		}
		if (uIntPtr == UIntPtr.Zero)
		{
			uIntPtr = VirtualAllocEx(pHandle, UIntPtr.Zero, (uint)size, 12288u, 64u);
		}
		int num = ((replaceCount > 5) ? (replaceCount - 5) : 0);
		int value = (int)((ulong)uIntPtr - (ulong)code2 - 5);
		byte[] array = new byte[5 + num];
		array[0] = 233;
		BitConverter.GetBytes(value).CopyTo(array, 1);
		for (int j = 5; j < array.Length; j++)
		{
			array[j] = 144;
		}
		writeBytes(code2, array);
		byte[] array2 = new byte[5 + newBytes.Length];
		int value2 = (int)((long)(ulong)code2 + (long)array.Length - ((long)(ulong)uIntPtr + (long)newBytes.Length) - 5);
		newBytes.CopyTo(array2, 0);
		array2[newBytes.Length] = 233;
		BitConverter.GetBytes(value2).CopyTo(array2, newBytes.Length + 1);
		writeBytes(uIntPtr, array2);
		return uIntPtr;
	}

	private UIntPtr FindFreeBlockForRegion(UIntPtr baseAddress, uint size)
	{
		UIntPtr uIntPtr = UIntPtr.Subtract(baseAddress, 1879048192);
		UIntPtr uIntPtr2 = UIntPtr.Add(baseAddress, 1879048192);
		UIntPtr uIntPtr3 = UIntPtr.Zero;
		UIntPtr zero = UIntPtr.Zero;
		GetSystemInfo(out var lpSystemInfo);
		if (Is64Bit)
		{
			if ((long)(ulong)uIntPtr > (long)(ulong)lpSystemInfo.maximumApplicationAddress || (long)(ulong)uIntPtr < (long)(ulong)lpSystemInfo.minimumApplicationAddress)
			{
				uIntPtr = lpSystemInfo.minimumApplicationAddress;
			}
			if ((long)(ulong)uIntPtr2 < (long)(ulong)lpSystemInfo.minimumApplicationAddress || (long)(ulong)uIntPtr2 > (long)(ulong)lpSystemInfo.maximumApplicationAddress)
			{
				uIntPtr2 = lpSystemInfo.maximumApplicationAddress;
			}
		}
		else
		{
			uIntPtr = lpSystemInfo.minimumApplicationAddress;
			uIntPtr2 = lpSystemInfo.maximumApplicationAddress;
		}
		UIntPtr uIntPtr4 = uIntPtr;
		UIntPtr uIntPtr5 = uIntPtr4;
		MEMORY_BASIC_INFORMATION lpBuffer;
		while (VirtualQueryEx(pHandle, uIntPtr4, out lpBuffer).ToUInt64() != 0L)
		{
			if ((long)(ulong)lpBuffer.BaseAddress > (long)(ulong)uIntPtr2)
			{
				return UIntPtr.Zero;
			}
			if (lpBuffer.State == 65536 && lpBuffer.RegionSize > size)
			{
				if ((long)(ulong)lpBuffer.BaseAddress % (long)lpSystemInfo.allocationGranularity > 0)
				{
					zero = lpBuffer.BaseAddress;
					int num = (int)(lpSystemInfo.allocationGranularity - (long)(ulong)zero % (long)lpSystemInfo.allocationGranularity);
					if (lpBuffer.RegionSize - num >= size)
					{
						zero = UIntPtr.Add(zero, num);
						if ((long)(ulong)zero < (long)(ulong)baseAddress)
						{
							zero = UIntPtr.Add(zero, (int)(lpBuffer.RegionSize - num - size));
							if ((long)(ulong)zero > (long)(ulong)baseAddress)
							{
								zero = baseAddress;
							}
							zero = UIntPtr.Subtract(zero, (int)((long)(ulong)zero % (long)lpSystemInfo.allocationGranularity));
						}
						if (Math.Abs((long)((ulong)zero - (ulong)baseAddress)) < Math.Abs((long)((ulong)uIntPtr3 - (ulong)baseAddress)))
						{
							uIntPtr3 = zero;
						}
					}
				}
				else
				{
					zero = lpBuffer.BaseAddress;
					if ((long)(ulong)zero < (long)(ulong)baseAddress)
					{
						zero = UIntPtr.Add(zero, (int)(lpBuffer.RegionSize - size));
						if ((long)(ulong)zero > (long)(ulong)baseAddress)
						{
							zero = baseAddress;
						}
						zero = UIntPtr.Subtract(zero, (int)((long)(ulong)zero % (long)lpSystemInfo.allocationGranularity));
					}
					if (Math.Abs((long)((ulong)zero - (ulong)baseAddress)) < Math.Abs((long)((ulong)uIntPtr3 - (ulong)baseAddress)))
					{
						uIntPtr3 = zero;
					}
				}
			}
			if (lpBuffer.RegionSize % lpSystemInfo.allocationGranularity > 0)
			{
				lpBuffer.RegionSize += lpSystemInfo.allocationGranularity - lpBuffer.RegionSize % lpSystemInfo.allocationGranularity;
			}
			uIntPtr5 = uIntPtr4;
			uIntPtr4 = UIntPtr.Add(lpBuffer.BaseAddress, (int)lpBuffer.RegionSize);
			if ((long)(ulong)uIntPtr4 > (long)(ulong)uIntPtr2)
			{
				return uIntPtr3;
			}
			if ((long)(ulong)uIntPtr5 > (long)(ulong)uIntPtr4)
			{
				return uIntPtr3;
			}
		}
		return uIntPtr3;
	}

	public static void SuspendProcess(int pid)
	{
		Process processById = Process.GetProcessById(pid);
		if (processById.ProcessName == string.Empty)
		{
			return;
		}
		foreach (ProcessThread thread in processById.Threads)
		{
			IntPtr intPtr = OpenThread(ThreadAccess.SUSPEND_RESUME, bInheritHandle: false, (uint)thread.Id);
			if (!(intPtr == IntPtr.Zero))
			{
				SuspendThread(intPtr);
				CloseHandle(intPtr);
			}
		}
	}

	public static void ResumeProcess(int pid)
	{
		Process processById = Process.GetProcessById(pid);
		if (processById.ProcessName == string.Empty)
		{
			return;
		}
		foreach (ProcessThread thread in processById.Threads)
		{
			IntPtr intPtr = OpenThread(ThreadAccess.SUSPEND_RESUME, bInheritHandle: false, (uint)thread.Id);
			if (!(intPtr == IntPtr.Zero))
			{
				int num = 0;
				do
				{
					num = ResumeThread(intPtr);
				}
				while (num > 0);
				CloseHandle(intPtr);
			}
		}
	}

	private async Task PutTaskDelay(int delay)
	{
		await Task.Delay(delay);
	}

	private void AppendAllBytes(string path, byte[] bytes)
	{
		using FileStream fileStream = new FileStream(path, FileMode.Append);
		fileStream.Write(bytes, 0, bytes.Length);
	}

	public byte[] fileToBytes(string path, bool dontDelete = false)
	{
		byte[] result = File.ReadAllBytes(path);
		if (!dontDelete)
		{
			File.Delete(path);
		}
		return result;
	}

	public string mSize()
	{
		if (is64bit())
		{
			return "x16";
		}
		return "x8";
	}

	public static string ByteArrayToHexString(byte[] ba)
	{
		StringBuilder stringBuilder = new StringBuilder(ba.Length * 2);
		int num = 1;
		foreach (byte b in ba)
		{
			if (num == 16)
			{
				stringBuilder.AppendFormat("{0:x2}{1}", b, Environment.NewLine);
				num = 0;
			}
			else
			{
				stringBuilder.AppendFormat("{0:x2} ", b);
			}
			num++;
		}
		return stringBuilder.ToString().ToUpper();
	}

	public static string ByteArrayToString(byte[] ba)
	{
		StringBuilder stringBuilder = new StringBuilder(ba.Length * 2);
		foreach (byte b in ba)
		{
			stringBuilder.AppendFormat("{0:x2} ", b);
		}
		return stringBuilder.ToString();
	}

	public ulong getMinAddress()
	{
		GetSystemInfo(out var lpSystemInfo);
		return (ulong)lpSystemInfo.minimumApplicationAddress;
	}
	public bool DumpMemory(string file = "dump.dmp")
	{
		if (theProc == null) return false;
		SYSTEM_INFO lpSystemInfo = default(SYSTEM_INFO);
		GetSystemInfo(out lpSystemInfo);
		UIntPtr uIntPtr = lpSystemInfo.minimumApplicationAddress;
		long num = (long)(ulong)uIntPtr;
		long num2 = theProc.VirtualMemorySize64 + num;
		if (File.Exists(file))
		{
			File.Delete(file);
		}
		MEMORY_BASIC_INFORMATION lpBuffer = default(MEMORY_BASIC_INFORMATION);
		while (num < num2)
		{
			VirtualQueryEx(pHandle, uIntPtr, out lpBuffer);
			byte[] array = new byte[lpBuffer.RegionSize];
			UIntPtr nSize = (UIntPtr)(ulong)lpBuffer.RegionSize;
			UIntPtr lpBaseAddress = (UIntPtr)(ulong)lpBuffer.BaseAddress;
			ReadProcessMemory(pHandle, lpBaseAddress, array, nSize, IntPtr.Zero);
			AppendAllBytes(file, array);
			num += lpBuffer.RegionSize;
			uIntPtr = new UIntPtr((ulong)num);
		}
		return true;
	}

	public Task<IEnumerable<long>> AoBScan(string search, bool writable = false, bool executable = true, string file = "")
	{
		return AoBScan(0L, long.MaxValue, search, writable, executable, file);
	}

	public Task<IEnumerable<long>> AoBScan(string search, bool readable, bool writable, bool executable, string file = "")
	{
		return AoBScan(0L, long.MaxValue, search, readable, writable, executable, file);
	}

	public Task<IEnumerable<long>> AoBScan(long start, long end, string search, bool writable = false, bool executable = true, string file = "")
	{
		return AoBScan(start, end, search, readable: false, writable, executable, file);
	}

	public Task<IEnumerable<long>> AoBScan(long start, long end, string search, bool readable, bool writable, bool executable, string file = "")
	{
		return Task.Run(delegate
		{
			List<MemoryRegionResult> list = new List<MemoryRegionResult>();
			string[] array = LoadCode(search, file).Split(' ');
			byte[] aobPattern = new byte[array.Length];
			byte[] mask = new byte[array.Length];
			for (int i = 0; i < array.Length; i++)
			{
				string text = array[i];
				if (text == "??" || (text.Length == 1 && text == "?"))
				{
					mask[i] = 0;
					array[i] = "0x00";
				}
				else if (char.IsLetterOrDigit(text[0]) && text[1] == '?')
				{
					mask[i] = 240;
					array[i] = text[0] + "0";
				}
				else if (char.IsLetterOrDigit(text[1]) && text[0] == '?')
				{
					mask[i] = 15;
					array[i] = "0" + text[1];
				}
				else
				{
					mask[i] = byte.MaxValue;
				}
			}
			for (int j = 0; j < array.Length; j++)
			{
				aobPattern[j] = (byte)(Convert.ToByte(array[j], 16) & mask[j]);
			}
			SYSTEM_INFO lpSystemInfo = default(SYSTEM_INFO);
			GetSystemInfo(out lpSystemInfo);
			UIntPtr minimumApplicationAddress = lpSystemInfo.minimumApplicationAddress;
			UIntPtr maximumApplicationAddress = lpSystemInfo.maximumApplicationAddress;
			if (start < (long)minimumApplicationAddress.ToUInt64())
			{
				start = (long)minimumApplicationAddress.ToUInt64();
			}
			if (end > (long)maximumApplicationAddress.ToUInt64())
			{
				end = (long)maximumApplicationAddress.ToUInt64();
			}
			UIntPtr uIntPtr = new UIntPtr((ulong)start);
			MEMORY_BASIC_INFORMATION lpBuffer = default(MEMORY_BASIC_INFORMATION);
			while (VirtualQueryEx(pHandle, uIntPtr, out lpBuffer).ToUInt64() != 0L && uIntPtr.ToUInt64() < (ulong)end && (ulong)((long)uIntPtr.ToUInt64() + lpBuffer.RegionSize) > uIntPtr.ToUInt64())
			{
				bool flag = lpBuffer.State == 4096;
				flag &= lpBuffer.BaseAddress.ToUInt64() < maximumApplicationAddress.ToUInt64();
				flag &= (lpBuffer.Protect & 0x100) == 0;
				flag &= (lpBuffer.Protect & 1) == 0;
				flag &= lpBuffer.Type == MEM_PRIVATE || lpBuffer.Type == MEM_IMAGE;
				if (flag)
				{
					bool flag2 = (lpBuffer.Protect & 2) != 0;
					bool flag3 = (lpBuffer.Protect & 4) != 0 || (lpBuffer.Protect & 8) != 0 || (lpBuffer.Protect & 0x40) != 0 || (lpBuffer.Protect & 0x80) != 0;
					bool flag4 = (lpBuffer.Protect & 0x10) != 0 || (lpBuffer.Protect & 0x20) != 0 || (lpBuffer.Protect & 0x40) != 0 || (lpBuffer.Protect & 0x80) != 0;
					flag2 = flag2 && readable;
					flag3 = flag3 && writable;
					flag4 = flag4 && executable;
					flag = flag && (flag2 || flag3 || flag4);
				}
				if (!flag)
				{
					uIntPtr = new UIntPtr(lpBuffer.BaseAddress.ToUInt64() + (ulong)lpBuffer.RegionSize);
				}
				else
				{
					MemoryRegionResult item = new MemoryRegionResult
					{
						CurrentBaseAddress = uIntPtr,
						RegionSize = lpBuffer.RegionSize,
						RegionBase = lpBuffer.BaseAddress
					};
					uIntPtr = new UIntPtr(lpBuffer.BaseAddress.ToUInt64() + (ulong)lpBuffer.RegionSize);
					if (list.Count > 0)
					{
						MemoryRegionResult memoryRegionResult = list[list.Count - 1];
						if ((long)(ulong)memoryRegionResult.RegionBase + memoryRegionResult.RegionSize == (long)(ulong)lpBuffer.BaseAddress)
						{
							list[list.Count - 1] = new MemoryRegionResult
							{
								CurrentBaseAddress = memoryRegionResult.CurrentBaseAddress,
								RegionBase = memoryRegionResult.RegionBase,
								RegionSize = memoryRegionResult.RegionSize + lpBuffer.RegionSize
							};
							continue;
						}
					}
					list.Add(item);
				}
			}
			ConcurrentBag<long> bagResult = new ConcurrentBag<long>();
			Parallel.ForEach(list, delegate(MemoryRegionResult item2, ParallelLoopState parallelLoopState, long index)
			{
				long[] array2 = CompareScan(item2, aobPattern, mask);
				foreach (long item3 in array2)
				{
					bagResult.Add(item3);
				}
			});
			return (from c in bagResult.ToList()
				orderby c
				select c).AsEnumerable();
		});
	}

	public async Task<long> AoBScan(string code, long end, string search, string file = "")
	{
		long start = (long)getCode(code, file).ToUInt64();
		return (await AoBScan(start, end, search, readable: true, writable: true, executable: true, file)).FirstOrDefault();
	}

	private unsafe long[] CompareScan(MemoryRegionResult item, byte[] aobPattern, byte[] mask)
	{
		if (mask.Length != aobPattern.Length)
		{
			throw new ArgumentException("aobPattern.Length != mask.Length");
		}
		IntPtr intPtr = Marshal.AllocHGlobal((int)item.RegionSize);
		ReadProcessMemory(pHandle, item.CurrentBaseAddress, intPtr, (UIntPtr)(ulong)item.RegionSize, out var lpNumberOfBytesRead);
		int num = -aobPattern.Length;
		List<long> list = new List<long>();
		do
		{
			num = FindPattern((byte*)intPtr.ToPointer(), (int)lpNumberOfBytesRead, aobPattern, mask, num + aobPattern.Length);
			if (num >= 0)
			{
				list.Add((long)(ulong)item.CurrentBaseAddress + (long)num);
			}
		}
		while (num != -1);
		Marshal.FreeHGlobal(intPtr);
		return list.ToArray();
	}

	private int FindPattern(byte[] body, byte[] pattern, byte[] masks, int start = 0)
	{
		int result = -1;
		if (body.Length == 0 || pattern.Length == 0 || start > body.Length - pattern.Length || pattern.Length > body.Length)
		{
			return result;
		}
		for (int i = start; i <= body.Length - pattern.Length; i++)
		{
			if ((body[i] & masks[0]) != (pattern[0] & masks[0]))
			{
				continue;
			}
			bool flag = true;
			for (int j = 1; j <= pattern.Length - 1; j++)
			{
				if ((body[i + j] & masks[j]) != (pattern[j] & masks[j]))
				{
					flag = false;
					break;
				}
			}
			if (flag)
			{
				result = i;
				break;
			}
		}
		return result;
	}

	private unsafe int FindPattern(byte* body, int bodyLength, byte[] pattern, byte[] masks, int start = 0)
	{
		int result = -1;
		if (bodyLength <= 0 || pattern.Length == 0 || start > bodyLength - pattern.Length || pattern.Length > bodyLength)
		{
			return result;
		}
		for (int i = start; i <= bodyLength - pattern.Length; i++)
		{
			if ((body[i] & masks[0]) != (pattern[0] & masks[0]))
			{
				continue;
			}
			bool flag = true;
			for (int j = 1; j <= pattern.Length - 1; j++)
			{
				if ((body[i + j] & masks[j]) != (pattern[j] & masks[j]))
				{
					flag = false;
					break;
				}
			}
			if (flag)
			{
				result = i;
				break;
			}
		}
		return result;
	}
}
