using System.Diagnostics;

public static class Utils
{
	public static string ToLiteralByteArrayString(this byte[] bytes)
	{
		string text = "";
		foreach (byte b in bytes)
		{
			text = text + b.ToString("X2") + " ";
		}
		return text.TrimEnd(' ');
	}

	public static Process GetProcess(string processName)
	{
		return Process.GetProcessesByName(processName)[0];
	}

	public static bool ProcessOpen(string processName)
	{
		return Process.GetProcessesByName(processName).Length != 0;
	}
}
