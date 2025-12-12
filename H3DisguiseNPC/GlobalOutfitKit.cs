namespace H3DisguiseNPC;

public class GlobalOutfitKit
{
	public long Address;

	public string CommonName => Program.mem.readString((Address + 88).ToString("X2") + ",0x00");

	public string Name => Program.mem.readString((Address + 104).ToString("X2") + ",0x00");

	public bool HeroDisguiseAvailable => Program.mem.readLong((Address + 168).ToString("X2")) == -4647714815446351616L;

	public GlobalOutfitKit(long address)
	{
		Address = address;
	}

	public void EnableHeroDisguiseAvailability()
	{
		Program.mem.writeMemory((Address + 168).ToString("X2"), "long", "-4647714815446351616");
	}

	public static async Task<long> GetPointerAddress()
	{
		// TODO: Verify AOB signature and offsets for HITMAN 3. These values are from HITMAN 2 and may need adjustment.
		return (await Program.mem.AoBScan(536870912L, 805306368L, "00 01 00 00 00 00 80 BF 00 00 00 00 00 00 00 00", writable: true, executable: false)).FirstOrDefault() - 168;
	}

	public static long GetPointer(long ptr)
	{
		return Program.mem.readLong(ptr.ToString("X2"));
	}

	public static bool PointerAddressValid(long address)
	{
		if (address <= 0 || GetPointer(address) <= 0)
		{
			return false;
		}
		return Program.mem.readLong((address + 72).ToString("X2")) != 0;
	}
}
