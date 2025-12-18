using System.Diagnostics;
using Memory;

namespace H3DisguiseNPC;

internal class Program
{
    public static Mem mem = new Mem();

    private static Process? process;

    private static int currentStatus = -1;

    private static bool modding = false;

    private static long gokPtr;

    private static long ovcPtr;

    private static string charsetType = "0x08";

    private static long gokCheckAddress;

    private static long outfitVariationCollectionCheckAddress;

    private static async void Mod()
    {
        if (modding)
        {
            return;
        }
        modding = true;
        switch (currentStatus)
        {
            case -1:
            {
                long num3 = await GlobalOutfitKit.GetPointerAddress();
                if (GlobalOutfitKit.PointerAddressValid(num3))
                {
                    if (gokPtr == 0L)
                    {
                        gokPtr = GlobalOutfitKit.GetPointer(num3);
                    }
                    if (GlobalOutfitKit.GetPointer(num3) == gokPtr)
                    {
                        Console.WriteLine(
                            "\nGlobalOutfitKit Ptr Address: 0x"
                                + num3.ToString("X2")
                                + "\nGlobalOutfitKit Ptr: "
                                + gokPtr
                        );
                        currentStatus++;
                    }
                }
                else
                {
                    Console.WriteLine("Attempting to find GlobalOutfitKit Pointer...");
                }
                await Task.Delay(3000);
                break;
            }
            case 0:
            {
                IEnumerable<long> gokAddresses = await mem.AoBScan(
                    536870912L,
                    805306368L,
                    BitConverter.GetBytes(gokPtr).ToLiteralByteArrayString(),
                    writable: true,
                    executable: false
                );
                ovcPtr = mem.readLong(
                    (gokAddresses.LastOrDefault() + 152).ToString("X2") + ",0x00"
                );
                Console.WriteLine("\nOutfitVariationCollection Ptr: " + ovcPtr);
                foreach (long item in gokAddresses)
                {
                    GlobalOutfitKit globalOutfitKit = new GlobalOutfitKit(item);
                    Console.WriteLine(
                        "GlobalOutfitKit\n{\n\tAddress: 0x"
                            + globalOutfitKit.Address.ToString("X2")
                            + "\n\tCommonName: "
                            + globalOutfitKit.CommonName
                            + "\n\tName: "
                            + globalOutfitKit.Name
                            + "\n\tHeroDisguiseAvailable: "
                            + globalOutfitKit.HeroDisguiseAvailable
                            + "\n}"
                    );
                    if (!globalOutfitKit.HeroDisguiseAvailable)
                    {
                        Console.WriteLine(
                            "\nEnabling Hero Disguise Availability for: "
                                + globalOutfitKit.CommonName
                                + "\n"
                        );
                        globalOutfitKit.EnableHeroDisguiseAvailability();
                    }
                }
                IEnumerable<long> enumerable = await mem.AoBScan(
                    536870912L,
                    805306368L,
                    BitConverter.GetBytes(ovcPtr).ToLiteralByteArrayString(),
                    writable: true,
                    executable: false
                );
                foreach (long item2 in enumerable)
                {
                    Console.WriteLine(
                        "OutfitVariationCollection\n{\n\tAddress: 0x" + item2.ToString("X2") + "\n}"
                    );
                    long num4 = mem.readLong((item2 + 24).ToString("X2") + "," + charsetType);
                    mem.writeMemory((item2 + 24).ToString("X2") + ",0x28", "long", num4.ToString());
                }
                gokCheckAddress = gokAddresses.LastOrDefault();
                outfitVariationCollectionCheckAddress = enumerable.FirstOrDefault();
                Console.WriteLine(
                    "Finished modifying "
                        + gokAddresses.Count()
                        + " GlobalOutfkitKits and "
                        + enumerable.Count()
                        + " OutfitVariationCollections! Now auto-checking for reapply."
                );
                currentStatus++;
                break;
            }
            case 1:
            {
                long num = mem.readLong(
                    (outfitVariationCollectionCheckAddress + 24).ToString("X2") + "," + charsetType
                );
                long num2 = mem.readLong(
                    (outfitVariationCollectionCheckAddress + 24).ToString("X2") + ",0x28"
                );
                if (GlobalOutfitKit.GetPointer(gokCheckAddress) != gokPtr)
                {
                    currentStatus = -1;
                }
                else if (num != num2)
                {
                    currentStatus = 0;
                }
                break;
            }
        }
        modding = false;
    }

    private static void Main(string[] args)
    {
        Console.Title = "HITMAN 3: Disguise & Play as NPC (Mod)";
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(Console.Title + "\n");
        Console.ForegroundColor = ConsoleColor.White;
        if (!Utils.ProcessOpen("HITMAN3"))
        {
            Console.WriteLine("Waiting for HITMAN3.exe...\n");
            if (!Utils.ProcessOpen("Launcher") && File.Exists("Launcher.exe"))
            {
                Process.Start(new ProcessStartInfo("Launcher.exe"));
            }
        }
        while (!Utils.ProcessOpen("HITMAN3"))
        {
            Thread.Sleep(100);
        }
        process = Utils.GetProcess("HITMAN3");
        mem.OpenProcess(process.Id);
        Console.WriteLine("Attached to HITMAN3.exe...\n");
        while (true)
        {
            Mod();
            if (process.HasExited)
            {
                Environment.Exit(1);
            }
        }
    }
}
