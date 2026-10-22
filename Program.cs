// ============================================================================
// 传颂之物 · 二人白皇 (Utawarerumono: Mask of Truth) — 全人物属性修改器
// 数据来源：CE 表「二人白皇ce修改（第二部）.ct」
//   CT 里是静态地址（模块基址 0x400000），运行时地址 = 实际模块基址 + (表内地址 - 0x400000)
// 编译：csc /nologo /target:winexe /platform:anycpu /optimize+ /codepage:65001
//              /win32manifest:app.manifest Program.cs
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace UtaTruth
{
    // ---------------------------------------------------------------- Win32 API
    internal static class Native
    {
        public const int PROCESS_VM_READ = 0x0010;
        public const int PROCESS_VM_WRITE = 0x0020;
        public const int PROCESS_VM_OPERATION = 0x0008;
        public const int PROCESS_QUERY_INFORMATION = 0x0400;
        public const int ACCESS = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;

        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint MEM_RELEASE = 0x8000;
        public const uint PAGE_READWRITE = 0x04;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFree(IntPtr lpAddress, IntPtr dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool AttachConsole(int dwProcessId);

        public const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool wow64);

        // ---- 进程枚举：用 Toolhelp 快照，不需要目标进程的任何权限，
        //      比 Process.GetProcesses()（受限于调用方令牌/沙箱）完整得多
        public const uint TH32CS_SNAPPROCESS = 0x00000002;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags,
            StringBuilder lpExeName, ref int lpdwSize);

        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        public static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    }

    // ---------------------------------------------------------------- 数据模型
    // 角色属性块布局（与 CT 表逐条核对过，16 个角色完全一致）：
    //   生命/血量 = 基址 + 0x00   (2 字节)
    //   攻击     = 基址 + 0x04   (2 字节)
    //   防御     = 基址 + 0x06   (2 字节)
    //   敏捷     = 基址 + 0x08   (4 字节)
    //   移动     = 基址 + 0x0C   (2 字节)
    //   跳跃     = 基址 + 0x0E   (2 字节)
    //   经验     = 基址 - 0x0A   (仅久远 / 环 / 莎莎拉 有)
    internal sealed class CharInfo
    {
        public readonly string Name;
        public readonly long HpAbs;
        public readonly bool HasExp;

        public CharInfo(string name, long hpAbs, bool hasExp)
        {
            Name = name;
            HpAbs = hpAbs;
            HasExp = hasExp;
        }

        public long AtkAbs { get { return HpAbs + 4; } }
        public long DefAbs { get { return HpAbs + 6; } }
        public long AgiAbs { get { return HpAbs + 8; } }
        public long MovAbs { get { return HpAbs + 0xC; } }
        public long JmpAbs { get { return HpAbs + 0xE; } }
        public long ExpAbs { get { return HpAbs - 0xA; } }
    }

    internal sealed class PowerInfo
    {
        public readonly string Name;
        public readonly long Abs;

        public PowerInfo(string name, long abs)
        {
            Name = name;
            Abs = abs;
        }
    }

    internal static class Table
    {
        // CT 表中的模块基址固定为 0x400000
        public const long ImageBase = 0x400000L;

        // 离线自检 / 假进程测试用的覆盖区域（0xB06000 ~ 0xB0E000 覆盖全部地址）
        public const long RegionAbs = 0xB06000L;
        public const int RegionSize = 0x8000;

        // 真实可执行文件名：Aquaplus 移植版是 UT3.exe（任务管理器里显示「受讚頌者 兩人的白皇」）。
        // 不同版本/汉化可能不同，所以另有进程选择器兜底。
        public static readonly string ProcessHint = "UT3.exe";
        public static readonly string GameTitle = "受讚頌者 兩人的白皇";

        // 「气力」字段宽度：本作是 2 字节（第一部是 1 字节）
        public const int PowBytes = 2;

        // 「全人物属性修改」16 个角色：基址 = CT 里的「生命 / 血量」地址
        public static readonly CharInfo[] Chars = new CharInfo[]
        {
            new CharInfo("奥修特尔（哈克）", 0x00B06740L, false),
            new CharInfo("久远",             0x00B069E8L, true),
            new CharInfo("露露提耶",         0x00B06F38L, false),
            new CharInfo("乌璐鲁萨拉拉",     0x00B071E0L, false),
            new CharInfo("鵟",               0x00B07488L, false),
            new CharInfo("扇",               0x00B07730L, false),
            new CharInfo("猫音",             0x00B079D8L, false),
            new CharInfo("奇羽",             0x00B07C80L, false),
            new CharInfo("阿图依",           0x00B07F28L, false),
            new CharInfo("杏树",             0x00B081D0L, false),
            new CharInfo("亚库托瓦尔特",     0x00B08478L, false),
            new CharInfo("宗近",             0x00B08720L, false),
            new CharInfo("福米璐璐",         0x00B089C8L, false),
            new CharInfo("环",               0x00B09C60L, true),
            new CharInfo("莎莎拉",           0x00B09F08L, true),
            new CharInfo("神 哈克",          0x00B0DEC8L, false),
        };

        // CT 表顶层「力气」组：20 条，独立的 2 字节地址
        public static readonly PowerInfo[] Powers = new PowerInfo[]
        {
            new PowerInfo("久远气力",       0x00B06A40L),
            new PowerInfo("奥修特尔（哈克）", 0x00B06798L),
            new PowerInfo("三",             0x00B06CE8L),
            new PowerInfo("露露缇耶",       0x00B06F90L),
            new PowerInfo("乌璐鲁萨拉拉",   0x00B07238L),
            new PowerInfo("鵟",             0x00B074E0L),
            new PowerInfo("扇",             0x00B07788L),
            new PowerInfo("猫音",           0x00B07A30L),
            new PowerInfo("奇羽",           0x00B07CD8L),
            new PowerInfo("阿图依",         0x00B07F80L),
            new PowerInfo("杏树",           0x00B08228L),
            new PowerInfo("亚库托瓦尔特",   0x00B084D0L),
            new PowerInfo("宗近",           0x00B08778L),
            new PowerInfo("福米璐璐",       0x00B08A20L),
            new PowerInfo("海马",           0x00B08CC8L),
            new PowerInfo("十六",           0x00B08F70L),
            new PowerInfo("鱼雷",           0x00B09218L),
            new PowerInfo("环",             0x00B09CB8L),
            new PowerInfo("莎莎拉",         0x00B09F60L),
            new PowerInfo("哈克神",         0x00B0DF20L),
        };
    }

    // ---------------------------------------------------------------- 备份存档
    internal sealed class BackupStore
    {
        public readonly Dictionary<long, ushort> U16 = new Dictionary<long, ushort>();
        public readonly Dictionary<long, uint> U32 = new Dictionary<long, uint>();

        public static string FilePath
        {
            get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "二人白皇-属性备份.ini"); }
        }

        public bool IsEmpty { get { return U16.Count == 0 && U32.Count == 0; } }

        public void Clear()
        {
            U16.Clear();
            U32.Clear();
        }

        public void Save()
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("# 二人白皇 属性修改器 — 原始数值备份（请勿手改）");
                foreach (KeyValuePair<long, ushort> kv in U16)
                    sb.AppendLine(kv.Key.ToString("X") + "=" + kv.Value.ToString(CultureInfo.InvariantCulture) + "|2");
                foreach (KeyValuePair<long, uint> kv in U32)
                    sb.AppendLine(kv.Key.ToString("X") + "=" + kv.Value.ToString(CultureInfo.InvariantCulture) + "|4");
                File.WriteAllText(FilePath, sb.ToString(), new UTF8Encoding(false));
            }
            catch
            {
                // 备份失败不影响主流程
            }
        }

        public void Load()
        {
            try
            {
                if (!File.Exists(FilePath)) return;
                foreach (string raw in File.ReadAllLines(FilePath))
                {
                    string line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith("#")) continue;
                    int eq = line.IndexOf('=');
                    if (eq <= 0) continue;
                    string[] vv = line.Substring(eq + 1).Split('|');
                    if (vv.Length != 2) continue;

                    long addr;
                    ulong val;
                    int size;
                    if (!long.TryParse(line.Substring(0, eq).Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out addr)) continue;
                    if (!ulong.TryParse(vv[0].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out val)) continue;
                    if (!int.TryParse(vv[1].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out size)) continue;

                    if (size == 2) U16[addr] = (ushort)val;
                    else if (size == 4) U32[addr] = (uint)val;
                }
            }
            catch
            {
            }
        }
    }

    // ---------------------------------------------------------------- 进程连接
    internal sealed class GameLink : IDisposable
    {
        // 不同版本 / 汉化补丁的可执行文件名不一样，按包含关系匹配（越靠前优先级越高）
        public static readonly string[] NameHints = new string[]
        {
            "UT3",
            "Mask of Truth",
            "UtawarerumonoMaskOfTruth",
            "兩人的白皇",
            "二人的白皇",
            "白皇",
        };

        // 第一部（虚伪的假面，UT2.exe）绝对不连；本工具自己也不连
        public static readonly string[] ExcludeHints = new string[]
        {
            "UT2",
            "Deception",
            "虛偽的假面",
            "虚伪的假面",
            "屬性修改器",
            "属性修改器",
            "修改器",
            "UtaTruth",
        };

        // 窗口标题里出现这些词，也认定是游戏（有的版本改名了，光看 exe 名找不到）
        // 注意：不要放单独的「白皇」，太容易撞上本工具自己的窗口/其他文档标题
        public static readonly string[] TitleHints = new string[]
        {
            "受讚頌者",
            "受赞颂者",
            "傳頌之物",
            "传颂之物",
            "兩人的白皇",
            "两人的白皇",
            "二人的白皇",
        };

        public static bool IsExcludedName(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            for (int i = 0; i < ExcludeHints.Length; i++)
                if (name.IndexOf(ExcludeHints[i], StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        // 标题判定：命中了标题词、且不是第一部，就算游戏
        public static bool TitleLooksLikeGame(string title)
        {
            if (string.IsNullOrEmpty(title)) return false;
            for (int i = 0; i < ExcludeHints.Length; i++)
                if (title.IndexOf(ExcludeHints[i], StringComparison.OrdinalIgnoreCase) >= 0) return false;
            for (int i = 0; i < TitleHints.Length; i++)
                if (title.IndexOf(TitleHints[i], StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        public static int ScoreName(string name)
        {
            if (string.IsNullOrEmpty(name) || IsExcludedName(name)) return 0;
            for (int i = 0; i < NameHints.Length; i++)
                if (name.IndexOf(NameHints[i], StringComparison.OrdinalIgnoreCase) >= 0) return 100 - i;
            return 0;
        }

        private IntPtr _handle = IntPtr.Zero;

        public int Pid;
        public long ModuleBase;
        public string ProcessPath = "";
        public string ProcessName = "";

        public bool IsAttached { get { return _handle != IntPtr.Zero; } }

        // 表内地址 → 运行时地址
        public long Addr(long tableAbs)
        {
            return ModuleBase + (tableAbs - Table.ImageBase);
        }

        public bool AttachAuto(out string err)
        {
            err = null;

            // 用 Toolhelp 快照枚举（不依赖调用方令牌，比 Process.GetProcesses() 完整）
            List<ProcEntry> all = ProcScan.List(false, false);

            List<ProcEntry> cand = new List<ProcEntry>();
            List<int> scores = new List<int>();

            foreach (ProcEntry e in all)
            {
                string nm = e.Name;
                if (IsExcludedName(nm)) continue;

                int score = ScoreName(nm);
                if (score == 0 && TitleLooksLikeGame(e.Title)) score = 60;
                // 上次用过的进程名优先（默认继承上一次的选择）
                if (!string.IsNullOrEmpty(Config.LastProcess))
                {
                    string last = Config.LastProcess;
                    if (nm.Equals(last, StringComparison.OrdinalIgnoreCase)
                        || nm.Equals(last + ".exe", StringComparison.OrdinalIgnoreCase)
                        || nm.Equals(last.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase))
                    {
                        score = score > 0 ? score + 1000 : 900;
                    }
                }
                if (score == 0) continue;

                // 按分数从高到低插入候选表
                int at = 0;
                while (at < scores.Count && scores[at] >= score) at++;
                cand.Insert(at, e);
                scores.Insert(at, score);
            }

            if (cand.Count == 0)
            {
                err = "没找到游戏进程（请先启动「" + Table.GameTitle + "」，或用「选择进程」手动指定）";
                return false;
            }

            // 逐个试：分数最高的可能是管理员权限的另一份游戏，打不开就退而求其次
            string lastErr = null;
            foreach (ProcEntry e in cand)
            {
                string e1;
                if (AttachPid(e.Pid, e.ExePath, out e1)) return true;
                lastErr = e1;
            }

            err = lastErr;
            return false;
        }

        public bool AttachPid(int pid, string knownPath, out string err)
        {
            err = null;
            Detach();

            IntPtr h = Native.OpenProcess(Native.ACCESS, false, pid);
            if (h == IntPtr.Zero)
            {
                int code = Marshal.GetLastWin32Error();
                err = "OpenProcess 失败 (Win32 " + code + ")，请以管理员身份运行本工具";
                return false;
            }

            long baseAddr = 0;
            string path = knownPath;
            string pname = "";
            try
            {
                Process p = Process.GetProcessById(pid);
                pname = p.ProcessName;
                if (path == null || path.Length == 0) path = p.MainModule.FileName;
                baseAddr = p.MainModule.BaseAddress.ToInt64();
                p.Dispose();
            }
            catch (Exception ex)
            {
                Native.CloseHandle(h);
                err = "读取模块基址失败：" + ex.Message + "（请以管理员身份运行本工具）";
                return false;
            }

            _handle = h;
            Pid = pid;
            ModuleBase = baseAddr;
            ProcessPath = path == null ? "" : path;
            ProcessName = pname;

            // 记住这次连上的进程名，下次启动默认继承
            if (!string.IsNullOrEmpty(pname))
            {
                Config.LastProcess = pname;
                Config.LastPid = pid;
                Config.Save();
            }
            return true;
        }

        // 只给 --selftest / 假进程校验用：把任意已分配内存当成「模块基址」
        public bool AttachSelfForTest(long fakeModuleBase, out string err)
        {
            err = null;
            IntPtr h = Native.OpenProcess(Native.ACCESS, false, Process.GetCurrentProcess().Id);
            if (h == IntPtr.Zero)
            {
                err = "OpenProcess(self) 失败：" + Marshal.GetLastWin32Error();
                return false;
            }
            _handle = h;
            ModuleBase = fakeModuleBase;
            Pid = Process.GetCurrentProcess().Id;
            ProcessPath = "self";
            ProcessName = "self";
            return true;
        }

        public bool IsAlive()
        {
            if (_handle == IntPtr.Zero) return false;
            try
            {
                Process p = Process.GetProcessById(Pid);
                bool alive = !p.HasExited;
                p.Dispose();
                return alive;
            }
            catch
            {
                return false;
            }
        }

        public bool ReadU16(long tableAbs, out ushort value)
        {
            value = 0;
            if (_handle == IntPtr.Zero) return false;
            byte[] buf = new byte[2];
            IntPtr read;
            if (!Native.ReadProcessMemory(_handle, new IntPtr(Addr(tableAbs)), buf, 2, out read)) return false;
            value = (ushort)(buf[0] | (buf[1] << 8));
            return true;
        }

        public bool ReadU32(long tableAbs, out uint value)
        {
            value = 0;
            if (_handle == IntPtr.Zero) return false;
            byte[] buf = new byte[4];
            IntPtr read;
            if (!Native.ReadProcessMemory(_handle, new IntPtr(Addr(tableAbs)), buf, 4, out read)) return false;
            value = (uint)(buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24));
            return true;
        }

        public bool WriteU16(long tableAbs, ushort value)
        {
            if (_handle == IntPtr.Zero) return false;
            byte[] buf = new byte[] { (byte)(value & 0xFF), (byte)((value >> 8) & 0xFF) };
            IntPtr written;
            return Native.WriteProcessMemory(_handle, new IntPtr(Addr(tableAbs)), buf, 2, out written);
        }

        public bool WriteU32(long tableAbs, uint value)
        {
            if (_handle == IntPtr.Zero) return false;
            byte[] buf = new byte[]
            {
                (byte)(value & 0xFF), (byte)((value >> 8) & 0xFF),
                (byte)((value >> 16) & 0xFF), (byte)((value >> 24) & 0xFF)
            };
            IntPtr written;
            return Native.WriteProcessMemory(_handle, new IntPtr(Addr(tableAbs)), buf, 4, out written);
        }

        public void Detach()
        {
            if (_handle != IntPtr.Zero)
            {
                Native.CloseHandle(_handle);
                _handle = IntPtr.Zero;
            }
            Pid = 0;
            ModuleBase = 0;
        }

        public void Dispose()
        {
            Detach();
        }
    }

    // ---------------------------------------------------------------- 设置记忆
    // 记住上一次连上的进程名，下次启动直接继承（跟 CE 一个体验）
    internal sealed class Config
    {
        public static string LastProcess = "";
        public static int LastPid;

        public static string FilePath
        {
            get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "二人白皇-设置.ini"); }
        }

        public static void Load()
        {
            try
            {
                if (!File.Exists(FilePath)) return;
                foreach (string raw in File.ReadAllLines(FilePath, Encoding.UTF8))
                {
                    string line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith("#")) continue;
                    int eq = line.IndexOf('=');
                    if (eq <= 0) continue;
                    string k = line.Substring(0, eq).Trim();
                    string v = line.Substring(eq + 1).Trim();
                    if (k.Equals("last-process", StringComparison.OrdinalIgnoreCase)) LastProcess = v;
                    else if (k.Equals("last-pid", StringComparison.OrdinalIgnoreCase)) int.TryParse(v, out LastPid);
                }
            }
            catch { }
        }

        public static void Save()
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("# 二人白皇-属性修改器 设置（自动生成）");
                sb.AppendLine("last-process=" + LastProcess);
                sb.AppendLine("last-pid=" + LastPid);
                File.WriteAllText(FilePath, sb.ToString(), new UTF8Encoding(false));
            }
            catch { }
        }
    }

    // ---------------------------------------------------------------- 进程枚举
    internal sealed class ProcEntry
    {
        public int Pid;
        public string Name = "";      // 映像名，带 .exe
        public string ExePath = "";
        public string Title = "";
        public bool Is32;
        public long MemMB;
        public bool Likely;      // 名字命中游戏候选
        public bool CanRead;     // 有权限读写内存（否则需要以管理员身份重启）
    }

    internal static class ProcScan
    {
        public static bool Is32Bit(int pid)
        {
            IntPtr h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return false;
            try
            {
                bool wow;
                if (Native.IsWow64Process(h, out wow)) return wow;
                return false;
            }
            catch { return false; }
            finally { Native.CloseHandle(h); }
        }

        public static string QueryPath(int pid)
        {
            IntPtr h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return "";
            try
            {
                StringBuilder sb = new StringBuilder(1024);
                int size = sb.Capacity;
                if (Native.QueryFullProcessImageName(h, 0, sb, ref size)) return sb.ToString(0, size);
                return "";
            }
            catch { return ""; }
            finally { Native.CloseHandle(h); }
        }

        // 直接用最终权限（含 VM_WRITE）试开一次，能开就说明这个进程可改
        public static bool CanRead(int pid)
        {
            IntPtr h = Native.OpenProcess(Native.ACCESS, false, pid);
            if (h == IntPtr.Zero) return false;
            Native.CloseHandle(h);
            return true;
        }

        public static long MemMB(int pid)
        {
            try
            {
                using (Process p = Process.GetProcessById(pid))
                    return p.WorkingSet64 / (1024L * 1024L);
            }
            catch { return 0; }
        }

        // pid -> 可见窗口标题
        public static Dictionary<int, string> WindowTitles()
        {
            Dictionary<int, string> map = new Dictionary<int, string>();
            Native.EnumWindowsProc cb = delegate (IntPtr hWnd, IntPtr lParam)
            {
                try
                {
                    if (!Native.IsWindowVisible(hWnd)) return true;
                    int len = Native.GetWindowTextLength(hWnd);
                    if (len <= 0) return true;
                    uint pid;
                    Native.GetWindowThreadProcessId(hWnd, out pid);
                    if (pid == 0 || pid > int.MaxValue) return true;
                    StringBuilder sb = new StringBuilder(len + 2);
                    Native.GetWindowText(hWnd, sb, sb.Capacity);
                    string t = sb.ToString().Trim();
                    if (t.Length > 0 && !map.ContainsKey((int)pid)) map[(int)pid] = t;
                }
                catch { }
                return true;
            };
            try { Native.EnumWindows(cb, IntPtr.Zero); }
            catch { }
            GC.KeepAlive(cb);
            return map;
        }

        // 繁简归一：让「传颂之物」也能搜到标题「受讚頌者 兩人的白皇」
        private const string TradChars = "傳頌讚贊兩虛偽為與這個們時實戲遊說語體統開關車門長東馬鳥";
        private const string SimpChars = "传颂赞赞两虚伪为与这个们时实戏游说语体统开关车门长东马鸟";

        public static string Norm(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            char[] a = s.ToCharArray();
            for (int i = 0; i < a.Length; i++)
            {
                int k = TradChars.IndexOf(a[i]);
                if (k >= 0) a[i] = SimpChars[k];
            }
            return new string(a);
        }

        // 三个来源取并集：Toolhelp 快照 / .NET 进程枚举 / 可见窗口。
        // 不同环境下三者的可见范围不一样（沙箱、权限、会话隔离都会各自过滤），
        // 并集能保证「用户正在前台跑的程序」一定出现在列表里。
        public static List<ProcEntry> List(bool onlyLikely, bool onlyWindowed)
        {
            int self = Process.GetCurrentProcess().Id;
            Dictionary<int, string> titles = WindowTitles();
            Dictionary<int, ProcEntry> map = new Dictionary<int, ProcEntry>();

            AddFromSnapshot(map, self, titles);
            AddFromDotNet(map, self, titles);
            AddFromWindows(map, self, titles);

            List<ProcEntry> list = new List<ProcEntry>();
            foreach (ProcEntry e in map.Values)
            {
                if (onlyWindowed && string.IsNullOrEmpty(e.Title)) continue;
                e.Likely = GameLink.ScoreName(e.Name) > 0 || GameLink.TitleLooksLikeGame(e.Title);
                if (onlyLikely && !e.Likely) continue;
                list.Add(e);
            }

            foreach (ProcEntry e in list)
            {
                if (e.ExePath == null || e.ExePath.Length == 0) e.ExePath = QueryPath(e.Pid);
                e.Is32 = Is32Bit(e.Pid);
                e.MemMB = MemMB(e.Pid);
                e.CanRead = CanRead(e.Pid);
            }

            list.Sort(delegate (ProcEntry a, ProcEntry b)
            {
                if (a.Likely != b.Likely) return a.Likely ? -1 : 1;
                bool wa = !string.IsNullOrEmpty(a.Title);
                bool wb = !string.IsNullOrEmpty(b.Title);
                if (wa != wb) return wa ? -1 : 1;
                if (a.CanRead != b.CanRead) return a.CanRead ? -1 : 1;
                if (a.MemMB != b.MemMB) return a.MemMB > b.MemMB ? -1 : 1;
                int c = string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
                if (c != 0) return c;
                return a.Pid.CompareTo(b.Pid);
            });
            return list;
        }

        private static ProcEntry Slot(Dictionary<int, ProcEntry> map, int pid, string name, Dictionary<int, string> titles)
        {
            ProcEntry e;
            if (!map.TryGetValue(pid, out e))
            {
                e = new ProcEntry();
                e.Pid = pid;
                e.Name = name ?? "";
                map[pid] = e;
            }
            else if ((e.Name == null || e.Name.Length == 0) && !string.IsNullOrEmpty(name))
            {
                e.Name = name;
            }

            string t;
            if (titles.TryGetValue(pid, out t) && (e.Title == null || e.Title.Length == 0)) e.Title = t;
            return e;
        }

        private static void AddFromSnapshot(Dictionary<int, ProcEntry> map, int self, Dictionary<int, string> titles)
        {
            IntPtr snap = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPPROCESS, 0);
            if (snap == IntPtr.Zero || snap.ToInt64() == -1) return;
            try
            {
                Native.PROCESSENTRY32 pe = new Native.PROCESSENTRY32();
                pe.dwSize = (uint)Marshal.SizeOf(typeof(Native.PROCESSENTRY32));
                if (Native.Process32First(snap, ref pe))
                {
                    do
                    {
                        int pid = (int)pe.th32ProcessID;
                        if (pid <= 4 || pid == self) continue;
                        Slot(map, pid, (pe.szExeFile ?? "").Trim(), titles);
                    }
                    while (Native.Process32Next(snap, ref pe));
                }
            }
            catch { }
            finally { Native.CloseHandle(snap); }
        }

        private static void AddFromDotNet(Dictionary<int, ProcEntry> map, int self, Dictionary<int, string> titles)
        {
            Process[] all;
            try { all = Process.GetProcesses(); }
            catch { return; }

            foreach (Process p in all)
            {
                try
                {
                    if (p.Id <= 4 || p.Id == self) continue;
                    Slot(map, p.Id, p.ProcessName + ".exe", titles);
                }
                catch { }
                finally
                {
                    try { p.Dispose(); }
                    catch { }
                }
            }
        }

        private static void AddFromWindows(Dictionary<int, ProcEntry> map, int self, Dictionary<int, string> titles)
        {
            foreach (KeyValuePair<int, string> kv in titles)
            {
                if (kv.Key <= 4 || kv.Key == self) continue;
                ProcEntry e = Slot(map, kv.Key, "", titles);
                if (e.Name == null || e.Name.Length == 0)
                {
                    string path = QueryPath(kv.Key);
                    e.ExePath = path;
                    e.Name = path.Length > 0 ? Path.GetFileName(path) : ("pid-" + kv.Key);
                }
            }
        }
    }

    // ---------------------------------------------------------------- 选择进程窗口
    // 跟 CE 的进程列表一个用法：列出全部进程，双击或回车即连接
    internal sealed class ProcessPickerForm : Form
    {
        private readonly DataGridView _grid = new DataGridView();
        private readonly TextBox _search = new TextBox();
        private readonly CheckBox _only = new CheckBox();
        private readonly CheckBox _win = new CheckBox();
        private readonly PillButton _ok = new PillButton();
        private readonly PillButton _cancel = new PillButton();
        private readonly PillButton _refresh = new PillButton();
        private readonly Label _hint = new Label();
        private readonly List<ProcEntry> _all = new List<ProcEntry>();

        public ProcEntry Picked;

        public ProcessPickerForm(int wantPid)
        {
            Text = "选择进程 — 传颂之物 · 二人白皇";
            ClientSize = new Size(900, 580);
            MinimumSize = new Size(760, 460);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = Theme.Bg;
            ForeColor = Theme.Text;
            Font = Theme.FBody;
            KeyPreview = true;

            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.ColumnCount = 1;
            root.RowCount = 4;
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 52f));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 56f));
            root.Padding = new Padding(14, 10, 14, 8);
            root.BackColor = Theme.Bg;
            Controls.Add(root);

            // ---- 顶部工具条
            FlowLayoutPanel top = new FlowLayoutPanel();
            top.Dock = DockStyle.Fill;
            top.FlowDirection = FlowDirection.LeftToRight;
            top.WrapContents = false;
            top.BackColor = Theme.Bg;
            top.Padding = new Padding(0, 8, 0, 0);
            root.Controls.Add(top, 0, 0);

            Label lb = new Label();
            lb.Text = "搜索";
            lb.AutoSize = true;
            lb.ForeColor = Theme.Dim;
            lb.Margin = new Padding(0, 6, 6, 0);
            top.Controls.Add(lb);

            _search.Width = 230;
            _search.BorderStyle = BorderStyle.FixedSingle;
            _search.BackColor = Theme.Input;
            _search.ForeColor = Theme.Text;
            _search.Font = Theme.FBody;
            _search.Margin = new Padding(0, 2, 12, 0);
            _search.TextChanged += delegate { Fill(0); };
            top.Controls.Add(_search);

            _only.Text = "只看疑似游戏进程";
            _only.AutoSize = true;
            _only.ForeColor = Theme.Dim;
            _only.Margin = new Padding(0, 6, 12, 0);
            _only.CheckedChanged += delegate { Reload(0); };
            top.Controls.Add(_only);

            _win.Text = "只看有窗口的";
            _win.AutoSize = true;
            _win.ForeColor = Theme.Dim;
            _win.Margin = new Padding(0, 6, 12, 0);
            _win.CheckedChanged += delegate { Reload(0); };
            top.Controls.Add(_win);

            _refresh.Text = "刷新";
            _refresh.Size = new Size(88, 30);
            _refresh.Outlined = true;
            _refresh.Margin = new Padding(0, 0, 0, 0);
            _refresh.Click += delegate { Reload(_selPid()); };
            top.Controls.Add(_refresh);

            _hint.Text = "正在枚举进程…";
            _hint.AutoSize = false;
            _hint.ForeColor = Theme.Dim;
            _hint.Margin = new Padding(4, 10, 0, 0);
            _hint.Size = new Size(520, 20);

            // ---- 列表
            StyleGrid();
            _grid.Margin = new Padding(0, 0, 0, 0);
            _grid.Dock = DockStyle.Fill;
            _grid.CellDoubleClick += delegate { Accept(); };
            _grid.CellClick += delegate { };
            root.Controls.Add(_grid, 0, 1);

            AddCol("进程名", 220, "Name");
            AddCol("PID", 76, "Pid");
            AddCol("位数", 68, "Bits");
            AddCol("内存(MB)", 92, "Mem");
            AddCol("读写", 58, "Rw");
            AddCol("窗口标题 / 路径", 380, "Note");

            // ---- 底部
            TableLayoutPanel bottom = new TableLayoutPanel();
            bottom.Dock = DockStyle.Fill;
            bottom.BackColor = Theme.Bg;
            bottom.ColumnCount = 2;
            bottom.RowCount = 1;
            bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 240f));
            bottom.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            root.Controls.Add(bottom, 0, 2);

            bottom.Controls.Add(_hint, 0, 0);

            FlowLayoutPanel btns = new FlowLayoutPanel();
            btns.Dock = DockStyle.Fill;
            btns.FlowDirection = FlowDirection.RightToLeft;
            btns.WrapContents = false;
            btns.BackColor = Theme.Bg;
            btns.Padding = new Padding(0, 6, 0, 0);
            bottom.Controls.Add(btns, 1, 0);

            _ok.Text = "连接该进程";
            _ok.Size = new Size(120, 32);
            _ok.Font = Theme.Make(9f, FontStyle.Bold);
            _ok.Margin = new Padding(6, 0, 0, 0);
            _ok.Click += delegate { Accept(); };
            btns.Controls.Add(_ok);

            _cancel.Text = "取消";
            _cancel.Size = new Size(96, 32);
            _cancel.Outlined = true;
            _cancel.Margin = new Padding(0, 0, 0, 0);
            _cancel.Click += delegate { DialogResult = DialogResult.Cancel; Close(); };
            btns.Controls.Add(_cancel);

            Shown += delegate
            {
                Reload(wantPid);
                _search.Focus();
            };
            KeyDown += delegate (object s, KeyEventArgs e)
            {
                if (e.KeyCode == Keys.Escape) { DialogResult = DialogResult.Cancel; Close(); }
                else if (e.KeyCode == Keys.Enter) Accept();
            };
        }

        private void AddCol(string title, int width, string tag)
        {
            DataGridViewTextBoxColumn c = new DataGridViewTextBoxColumn();
            c.HeaderText = title;
            c.Width = width;
            c.SortMode = DataGridViewColumnSortMode.Automatic;
            c.Name = tag;
            if (tag == "Note") c.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            _grid.Columns.Add(c);
        }

        private void StyleGrid()
        {
            _grid.BackgroundColor = Theme.Card;
            _grid.BorderStyle = BorderStyle.None;
            _grid.EnableHeadersVisualStyles = false;
            _grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None;
            _grid.ColumnHeadersHeight = 30;
            _grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(0x1B, 0x22, 0x2C);
            _grid.ColumnHeadersDefaultCellStyle.ForeColor = Theme.Dim;
            _grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = Color.FromArgb(0x1B, 0x22, 0x2C);
            _grid.ColumnHeadersDefaultCellStyle.SelectionForeColor = Theme.Dim;
            _grid.ColumnHeadersDefaultCellStyle.Font = Theme.Make(9f, FontStyle.Bold);
            _grid.RowTemplate.Height = 27;
            _grid.DefaultCellStyle.BackColor = Theme.Card;
            _grid.DefaultCellStyle.ForeColor = Theme.Text;
            _grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(0x1B, 0x3A, 0x31);
            _grid.DefaultCellStyle.SelectionForeColor = Theme.Text;
            _grid.DefaultCellStyle.Font = Theme.FBody;
            _grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(0x18, 0x1E, 0x26);
            _grid.GridColor = Color.FromArgb(0x22, 0x2A, 0x35);
            _grid.AllowUserToAddRows = false;
            _grid.AllowUserToDeleteRows = false;
            _grid.AllowUserToResizeRows = false;
            _grid.MultiSelect = false;
            _grid.ReadOnly = true;
            _grid.RowHeadersVisible = false;
            _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            _grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None;
            _grid.AutoGenerateColumns = false;
            _grid.StandardTab = true;
        }

        private int _selPid()
        {
            if (_grid.CurrentRow == null) return 0;
            return (int)_grid.CurrentRow.Tag;
        }

        private void Reload(int keepPid)
        {
            _all.Clear();
            _all.AddRange(ProcScan.List(_only.Checked, _win.Checked));
            Fill(keepPid);
        }

        private void Fill(int keepPid)
        {
            string q = _search.Text.Trim();
            _grid.Rows.Clear();
            int selectIdx = -1;
            for (int i = 0; i < _all.Count; i++)
            {
                ProcEntry e = _all[i];
                if (q.Length > 0)
                {
                    string nq = ProcScan.Norm(q);
                    bool hit = ProcScan.Norm(e.Name).IndexOf(nq, StringComparison.OrdinalIgnoreCase) >= 0
                               || ProcScan.Norm(e.ExePath).IndexOf(nq, StringComparison.OrdinalIgnoreCase) >= 0
                               || ProcScan.Norm(e.Title).IndexOf(nq, StringComparison.OrdinalIgnoreCase) >= 0
                               || e.Pid.ToString() == q;
                    if (!hit) continue;
                }
                string note = e.Title;
                if (note.Length == 0) note = e.ExePath;
                else if (e.ExePath.Length > 0) note = e.Title + "   " + e.ExePath;
                int idx = _grid.Rows.Add(e.Name, e.Pid.ToString(),
                    e.Is32 ? "32 位" : "64 位", e.MemMB.ToString(),
                    e.CanRead ? "✔" : "✖", note);
                _grid.Rows[idx].Tag = e.Pid;
                if (e.Likely)
                {
                    _grid.Rows[idx].DefaultCellStyle.ForeColor = Theme.Accent;
                }
                else if (!e.CanRead)
                {
                    _grid.Rows[idx].DefaultCellStyle.ForeColor = Theme.Dim;
                }
                if (e.Pid == keepPid) selectIdx = idx;
            }

            _hint.Text = "共 " + _grid.Rows.Count + " / " + _all.Count
                + " 个进程　·　✖ = 需管理员权限（游戏是 32 位）";

            if (_grid.Rows.Count > 0)
            {
                int pick = selectIdx >= 0 ? selectIdx : 0;
                _grid.CurrentCell = _grid.Rows[pick].Cells[0];
                _grid.Rows[pick].Selected = true;
            }
        }

        private void Accept()
        {
            if (_grid.CurrentRow == null) return;
            int pid = (int)_grid.CurrentRow.Tag;
            foreach (ProcEntry e in _all)
            {
                if (e.Pid == pid)
                {
                    Picked = e;
                    DialogResult = DialogResult.OK;
                    Close();
                    return;
                }
            }
        }
    }

    // ---------------------------------------------------------------- 主题
    internal static class Theme
    {
        public static readonly Color Bg = Color.FromArgb(0x0E, 0x10, 0x14);
        public static readonly Color Card = Color.FromArgb(0x16, 0x1B, 0x22);
        public static readonly Color Input = Color.FromArgb(0x0F, 0x14, 0x1A);
        public static readonly Color Line = Color.FromArgb(0x25, 0x2E, 0x3A);
        public static readonly Color Text = Color.FromArgb(0xE6, 0xED, 0xF5);
        public static readonly Color Dim = Color.FromArgb(0x8A, 0x96, 0xA6);
        public static readonly Color Accent = Color.FromArgb(0x3A, 0xD9, 0x9B);
        public static readonly Color AccentDim = Color.FromArgb(0x22, 0x8A, 0x6B);
        public static readonly Color Danger = Color.FromArgb(0xFF, 0x6B, 0x5B);

        public static readonly Font FTitle = new Font("微软雅黑", 16f, FontStyle.Bold, GraphicsUnit.Point);
        public static readonly Font FCard = new Font("微软雅黑", 9.5f, FontStyle.Bold, GraphicsUnit.Point);
        public static readonly Font FSub = new Font("微软雅黑", 8.5f, FontStyle.Regular, GraphicsUnit.Point);
        public static readonly Font FBody = new Font("微软雅黑", 9f, FontStyle.Regular, GraphicsUnit.Point);
        public static readonly Font FBold = new Font("微软雅黑", 9f, FontStyle.Bold, GraphicsUnit.Point);
        public static readonly Font FNum = new Font("微软雅黑", 9.5f, FontStyle.Bold, GraphicsUnit.Point);

        public static Font Make(float size, FontStyle style)
        {
            return new Font("微软雅黑", size, style, GraphicsUnit.Point);
        }
    }

    internal static class Geom
    {
        public static GraphicsPath Round(Rectangle r, int radius)
        {
            GraphicsPath p = new GraphicsPath();
            int d = radius * 2;
            if (d <= 0)
            {
                p.AddRectangle(r);
                return p;
            }
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }
    }

    // ---------------------------------------------------------------- 自绘控件
    internal sealed class CardPanel : Panel
    {
        public string Title = "";

        public CardPanel()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer
                     | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Card;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            Rectangle r = new Rectangle(0, 0, Width - 1, Height - 1);
            using (GraphicsPath p = Geom.Round(r, 8))
            {
                using (SolidBrush b = new SolidBrush(Theme.Card)) g.FillPath(b, p);
                using (Pen pen = new Pen(Theme.Line)) g.DrawPath(pen, p);
            }

            if (Title.Length > 0)
            {
                using (SolidBrush accent = new SolidBrush(Theme.Accent)) g.FillRectangle(accent, 14, 14, 3, 12);
                using (SolidBrush tb = new SolidBrush(Theme.Text)) g.DrawString(Title, Theme.FCard, tb, 24, 10);
                using (Pen line = new Pen(Color.FromArgb(0x1F, 0x26, 0x30)))
                    g.DrawLine(line, 14, 34, Width - 15, 34);
            }
        }
    }

    internal sealed class PillButton : Control
    {
        public Color Fill = Theme.Accent;
        public Color FillText = Color.FromArgb(0x07, 0x0E, 0x0B);
        public bool Outlined = false;
        public Color OutlineColor = Theme.Line;

        private bool _hover;
        private bool _down;

        public PillButton()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer
                     | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            Cursor = Cursors.Hand;
            Font = Theme.Make(9.5f, FontStyle.Bold);
            Size = new Size(120, 38);
            BackColor = Theme.Bg;
        }

        protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { _hover = false; _down = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { _down = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { _down = false; Invalidate(); base.OnMouseUp(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            Color parent = Parent != null ? Parent.BackColor : Theme.Bg;
            using (SolidBrush bg = new SolidBrush(parent)) g.FillRectangle(bg, ClientRectangle);

            Rectangle r = new Rectangle(0, 0, Width - 1, Height - 1);
            bool enabled = Enabled;

            using (GraphicsPath p = Geom.Round(r, 7))
            {
                if (Outlined)
                {
                    Color fill = _down ? Color.FromArgb(0x1E, 0x26, 0x30) : (_hover ? Color.FromArgb(0x1A, 0x21, 0x2A) : Theme.Card);
                    using (SolidBrush b = new SolidBrush(enabled ? fill : Color.FromArgb(0x13, 0x17, 0x1D))) g.FillPath(b, p);
                    using (Pen pen = new Pen(enabled ? Theme.Line : Color.FromArgb(0x1C, 0x22, 0x2A))) g.DrawPath(pen, p);
                }
                else
                {
                    Color baseColor = enabled ? Fill : Color.FromArgb(0x2A, 0x33, 0x3D);
                    if (_hover) baseColor = Lighten(baseColor, 0.10f);
                    if (_down) baseColor = Lighten(baseColor, -0.10f);
                    using (SolidBrush b = new SolidBrush(baseColor)) g.FillPath(b, p);
                }
            }

            Color txt = Outlined ? (enabled ? Theme.Text : Theme.Dim) : (enabled ? FillText : Theme.Dim);
            using (SolidBrush tb = new SolidBrush(txt))
            {
                StringFormat sf = new StringFormat();
                sf.Alignment = StringAlignment.Center;
                sf.LineAlignment = StringAlignment.Center;
                g.DrawString(Text, Font, tb, new RectangleF(0, 0, Width, Height), sf);
                sf.Dispose();
            }
        }

        private static Color Lighten(Color c, float amount)
        {
            int r = (int)(c.R + (255 - c.R) * amount);
            int g = (int)(c.G + (255 - c.G) * amount);
            int b = (int)(c.B + (255 - c.B) * amount);
            if (amount < 0)
            {
                r = (int)(c.R * (1 + amount));
                g = (int)(c.G * (1 + amount));
                b = (int)(c.B * (1 + amount));
            }
            return Color.FromArgb(Clamp(r), Clamp(g), Clamp(b));
        }

        private static int Clamp(int v)
        {
            if (v < 0) return 0;
            if (v > 255) return 255;
            return v;
        }
    }

    internal sealed class MiniSwitch : Control
    {
        private bool _on;

        public event EventHandler Toggled;

        public bool On
        {
            get { return _on; }
            set
            {
                if (_on == value) return;
                _on = value;
                Invalidate();
                if (Toggled != null) Toggled(this, EventArgs.Empty);
            }
        }

        public MiniSwitch()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer
                     | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            Size = new Size(40, 20);
            Cursor = Cursors.Hand;
            BackColor = Theme.Card;
        }

        protected override void OnClick(EventArgs e)
        {
            On = !On;
            base.OnClick(e);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            using (SolidBrush bg = new SolidBrush(Parent != null ? Parent.BackColor : Theme.Card))
                g.FillRectangle(bg, ClientRectangle);

            Rectangle track = new Rectangle(0, 2, Width - 1, Height - 5);
            using (GraphicsPath p = Geom.Round(track, track.Height / 2))
            {
                using (SolidBrush b = new SolidBrush(_on ? Theme.Accent : Color.FromArgb(0x2C, 0x36, 0x42))) g.FillPath(b, p);
            }

            int d = Height - 8;
            int kx = _on ? Width - d - 2 : 2;
            using (SolidBrush knob = new SolidBrush(_on ? Color.FromArgb(0x08, 0x14, 0x10) : Color.FromArgb(0x8B, 0x97, 0xA6)))
                g.FillEllipse(knob, kx, 4, d, d);
        }
    }

    /// <summary>
    /// 深色主题数字输入框：圆角底 + 居中无边框编辑区 + 右侧自绘 ▲▼。
    /// 系统 NumericUpDown 的微调按钮是浅色系统绘制，放进深色界面里非常突兀，所以自绘。
    /// </summary>
    internal sealed class NumBox : Control
    {
        private readonly TextBox _edit = new TextBox();
        private long _value;
        private long _min;
        private long _max = 100;
        private long _inc = 1;
        private int _hot;
        private bool _sync;

        public event EventHandler ValueChanged;

        public NumBox()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer
                     | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Input;
            ForeColor = Theme.Text;
            Size = new Size(96, 26);

            _edit.BorderStyle = BorderStyle.None;
            _edit.BackColor = Theme.Input;
            _edit.ForeColor = Theme.Text;
            _edit.Font = Theme.FNum;
            _edit.TextAlign = HorizontalAlignment.Center;
            _edit.TextChanged += OnEditChanged;
            _edit.LostFocus += delegate { SyncText(); };
            _edit.KeyPress += OnEditKeyPress;
            Controls.Add(_edit);
        }

        public long Value
        {
            get { return _value; }
            set { SetValue(value, true); }
        }

        public long Minimum
        {
            get { return _min; }
            set { _min = value; SetValue(_value, false); }
        }

        public long Maximum
        {
            get { return _max; }
            set { _max = value < _min ? _min : value; SetValue(_value, false); }
        }

        public long Increment
        {
            get { return _inc; }
            set { _inc = value < 1 ? 1 : value; }
        }

        public override string Text
        {
            get { return _value.ToString(CultureInfo.InvariantCulture); }
            set
            {
                long v;
                if (long.TryParse(value, out v)) Value = v;
            }
        }

        protected override void OnEnabledChanged(EventArgs e)
        {
            base.OnEnabledChanged(e);
            _edit.Enabled = Enabled;
            _edit.BackColor = Enabled ? Theme.Input : Color.FromArgb(0x11, 0x15, 0x1B);
            _edit.ForeColor = Enabled ? Theme.Text : Theme.Dim;
            Invalidate();
        }

        protected override void OnLayout(LayoutEventArgs e)
        {
            base.OnLayout(e);
            int h = _edit.PreferredHeight;
            _edit.SetBounds(8, (Height - h) / 2, Width - BtnWidth - 14, h);
        }

        private const int BtnWidth = 20;

        private void SetValue(long v, bool raise)
        {
            if (v < _min) v = _min;
            if (v > _max) v = _max;
            bool changed = v != _value;
            _value = v;
            SyncText();
            Invalidate();
            if (changed && raise && ValueChanged != null) ValueChanged(this, EventArgs.Empty);
        }

        private void SyncText()
        {
            if (_sync) return;
            _sync = true;
            _edit.Text = _value.ToString(CultureInfo.InvariantCulture);
            _sync = false;
        }

        private void OnEditChanged(object sender, EventArgs e)
        {
            if (_sync) return;
            string t = _edit.Text.Trim();
            if (t.Length == 0) return;
            long v;
            if (!long.TryParse(t, NumberStyles.Integer, CultureInfo.InvariantCulture, out v)) return;
            // 输入过程中只在合法区间内即时同步；越界值等失焦再夹回来，避免删字符时被强行改写
            if (v >= _min && v <= _max && v != _value)
            {
                _value = v;
                Invalidate();
                if (ValueChanged != null) ValueChanged(this, EventArgs.Empty);
            }
        }

        private void OnEditKeyPress(object sender, KeyPressEventArgs e)
        {
            if (!char.IsDigit(e.KeyChar) && !char.IsControl(e.KeyChar)) e.Handled = true;
        }

        private int HotAt(int x, int y)
        {
            if (x < Width - BtnWidth - 2) return 0;
            return y < Height / 2 ? 1 : 2;
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            int h = HotAt(e.X, e.Y);
            if (h != _hot) { _hot = h; Invalidate(); }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            if (_hot != 0) { _hot = 0; Invalidate(); }
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            int h = HotAt(e.X, e.Y);
            if (h == 1) SetValue(_value + _inc, true);
            else if (h == 2) SetValue(_value - _inc, true);
            else { _edit.Focus(); _edit.SelectAll(); }
        }

        protected override void OnMouseWheel(MouseEventArgs e)
        {
            base.OnMouseWheel(e);
            SetValue(_value + (e.Delta > 0 ? _inc : -_inc), true);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            using (GraphicsPath p = Geom.Round(new Rectangle(0, 0, Width - 1, Height - 1), 6))
            {
                using (SolidBrush b = new SolidBrush(Enabled ? Theme.Input : Color.FromArgb(0x11, 0x15, 0x1B)))
                    g.FillPath(b, p);
                using (Pen pen = new Pen(Enabled ? Theme.Line : Color.FromArgb(0x1C, 0x23, 0x2C)))
                    g.DrawPath(pen, p);
            }

            // 按钮区与编辑区分界的竖线
            int bx = Width - BtnWidth - 2;
            using (Pen sep = new Pen(Enabled ? Theme.Line : Color.FromArgb(0x1C, 0x23, 0x2C)))
                g.DrawLine(sep, bx - 1, 4, bx - 1, Height - 5);

            Rectangle up = new Rectangle(bx + 1, 3, BtnWidth - 3, Height / 2 - 4);
            Rectangle dn = new Rectangle(bx + 1, Height / 2 + 1, BtnWidth - 3, Height / 2 - 4);
            DrawArrow(g, up, true, _hot == 1);
            DrawArrow(g, dn, false, _hot == 2);
        }

        private void DrawArrow(Graphics g, Rectangle r, bool up, bool hot)
        {
            if (hot && Enabled)
            {
                using (GraphicsPath p = Geom.Round(r, 3))
                using (SolidBrush b = new SolidBrush(Color.FromArgb(0x25, 0x30, 0x3D)))
                    g.FillPath(b, p);
            }

            int cx = r.X + r.Width / 2;
            int cy = r.Y + r.Height / 2;
            Color c = !Enabled ? Color.FromArgb(0x3A, 0x42, 0x4E) : (hot ? Theme.Accent : Theme.Dim);
            Point[] pts = up
                ? new Point[] { new Point(cx - 3, cy + 2), new Point(cx + 3, cy + 2), new Point(cx, cy - 3) }
                : new Point[] { new Point(cx - 3, cy - 2), new Point(cx + 3, cy - 2), new Point(cx, cy + 3) };
            using (SolidBrush b = new SolidBrush(c))
                g.FillPolygon(b, pts);
        }
    }

    internal sealed class HeaderPanel : Panel
    {
        public string Title = "传颂之物 · 二人白皇";
        public string Subtitle = "全人物属性修改器  ·  CT 表地址 → 运行时可读写内存";
        public string StatusText = "未连接";
        public bool StatusOk = false;
        public int RightReserved = 146;

        public HeaderPanel()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer
                     | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Color.FromArgb(0x13, 0x18, 0x1F);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            using (SolidBrush bg = new SolidBrush(BackColor)) g.FillRectangle(bg, ClientRectangle);

            Rectangle bar = new Rectangle(18, 17, 4, 42);
            using (LinearGradientBrush lg = new LinearGradientBrush(bar, Theme.Accent, Theme.AccentDim, LinearGradientMode.Vertical))
                g.FillRectangle(lg, bar);

            using (SolidBrush tb = new SolidBrush(Theme.Text)) g.DrawString(Title, Theme.FTitle, tb, 32, 12);
            using (SolidBrush sb = new SolidBrush(Theme.Dim)) g.DrawString(Subtitle, Theme.FSub, sb, 34, 46);

            using (Pen line = new Pen(Color.FromArgb(0x22, 0x2B, 0x36)))
                g.DrawLine(line, 0, Height - 1, Width, Height - 1);

            int textW = (int)g.MeasureString(StatusText, Theme.FSub).Width;
            int pillW = textW + 36;
            int pillX = Width - RightReserved - pillW - 8;
            if (pillX < 320) pillX = 320;
            Rectangle pill = new Rectangle(pillX, 26, pillW, 26);

            using (GraphicsPath p = Geom.Round(pill, 13))
            {
                Color fill = StatusOk ? Color.FromArgb(0x14, 0x2C, 0x25) : Color.FromArgb(0x1A, 0x1F, 0x27);
                using (SolidBrush b = new SolidBrush(fill)) g.FillPath(b, p);
                using (Pen pen = new Pen(StatusOk ? Theme.AccentDim : Theme.Line)) g.DrawPath(pen, p);
            }

            using (SolidBrush dot = new SolidBrush(StatusOk ? Theme.Accent : Color.FromArgb(0x6B, 0x76, 0x86)))
                g.FillEllipse(dot, pill.X + 12, pill.Y + 10, 7, 7);

            using (SolidBrush st = new SolidBrush(StatusOk ? Theme.Text : Theme.Dim))
                g.DrawString(StatusText, Theme.FSub, st, pill.X + 25, pill.Y + 6);
        }
    }

    // ---------------------------------------------------------------- 主窗口
    internal sealed class MainForm : Form
    {
        private readonly GameLink _link = new GameLink();
        private readonly BackupStore _bk = new BackupStore();

        private HeaderPanel _header;
        private DataGridView _grid;
        private NumBox _numAtk, _numDef, _numHp, _numAgi, _numMov, _numJmp, _numPow, _numInterval;
        private MiniSwitch _swHp, _swAgi, _swMov, _swJmp, _swPow, _swGuard;
        private PillButton _btnRun, _btnRestore, _btnReconnect, _btnElevate, _btnPick;
        private Label _status;
        private RichTextBox _log;
        private ContextMenuStrip _menu;
        private Timer _timer;
        private ToolTip _tips;

        private bool _active;
        private long _writeCount;

        public MainForm()
        {
            BuildUi();
            _bk.Load();
            if (!_bk.IsEmpty)
                Log("[i] 已载入上次备份（" + _bk.U16.Count + " 个 2 字节字段 / " + _bk.U32.Count + " 个 4 字节字段），随时可还原。");

            _timer = new Timer();
            _timer.Interval = 400;
            _timer.Tick += OnTick;
            _timer.Start();

            // 启动即尝试连接：优先继承上一次的进程名
            Connect(false);

            RefreshGrid();
            UpdateUi();
        }

        // ------------------------------------------------------ 界面搭建
        private void BuildUi()
        {
            SuspendLayout();

            Text = "传颂之物 · 二人白皇 — 全人物属性修改器";
            ClientSize = new Size(1180, 910);
            MinimumSize = new Size(1060, 820);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Theme.Bg;
            ForeColor = Theme.Text;
            Font = Theme.FBody;
            Icon = BuildIcon();

            _tips = new ToolTip();

            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.ColumnCount = 1;
            root.RowCount = 4;
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 86f));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 156f));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 44f));
            root.BackColor = Theme.Bg;
            Controls.Add(root);

            // 页头
            _header = new HeaderPanel();
            _header.Dock = DockStyle.Fill;
            _header.Margin = new Padding(0);
            root.Controls.Add(_header, 0, 0);

            FlowLayoutPanel headerRight = new FlowLayoutPanel();
            headerRight.Dock = DockStyle.Right;
            headerRight.Width = 278;
            headerRight.FlowDirection = FlowDirection.LeftToRight;
            headerRight.WrapContents = false;
            headerRight.Padding = new Padding(8, 32, 16, 0);
            headerRight.BackColor = Color.FromArgb(0x1A, 0x20, 0x28);
            _header.Controls.Add(headerRight);
            _header.RightReserved = 282;

            _btnPick = new PillButton();
            _btnPick.Text = "选择进程";
            _btnPick.Size = new Size(118, 34);
            _btnPick.Outlined = true;
            _btnPick.Font = Theme.Make(9f, FontStyle.Bold);
            _btnPick.Margin = new Padding(0, 0, 10, 0);
            _btnPick.Click += delegate { PickProcess(); };
            _tips.SetToolTip(_btnPick, "像 CE 一样列出所有进程，手动选一个连上（会记住这次的选择）");
            headerRight.Controls.Add(_btnPick);

            _btnReconnect = new PillButton();
            _btnReconnect.Text = "自动连接";
            _btnReconnect.Size = new Size(118, 34);
            _btnReconnect.Outlined = true;
            _btnReconnect.Font = Theme.Make(9f, FontStyle.Bold);
            _btnReconnect.Click += delegate { Connect(true); };
            _tips.SetToolTip(_btnReconnect, "优先连上次用过的进程名，其次按游戏名匹配");
            headerRight.Controls.Add(_btnReconnect);

            // 主体
            TableLayoutPanel body = new TableLayoutPanel();
            body.Dock = DockStyle.Fill;
            body.ColumnCount = 2;
            body.RowCount = 1;
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            body.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 430f));
            body.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            body.Padding = new Padding(20, 18, 20, 10);
            body.BackColor = Theme.Bg;
            root.Controls.Add(body, 0, 1);

            // --- 左：人物实时读数
            CardPanel cardGrid = new CardPanel();
            cardGrid.Title = "人物实时读数（双击某行 = 只改该角色，右键 = 更多）";
            cardGrid.Dock = DockStyle.Fill;
            cardGrid.Margin = new Padding(0, 0, 18, 0);
            body.Controls.Add(cardGrid, 0, 0);

            _grid = BuildGrid();
            _grid.Location = new Point(14, 44);
            _grid.Size = new Size(cardGrid.Width - 28, cardGrid.Height - 52);
            _grid.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            _grid.CellDoubleClick += OnGridDoubleClick;
            cardGrid.Controls.Add(_grid);

            _menu = new ContextMenuStrip();
            _menu.BackColor = Theme.Card;
            _menu.ForeColor = Theme.Text;
            ToolStripMenuItem miApply = new ToolStripMenuItem("把该角色设为目标值");
            miApply.Click += delegate { SingleWrite(CurrentRowIndex()); };
            ToolStripMenuItem miRestore = new ToolStripMenuItem("还原该角色的原始值");
            miRestore.Click += delegate { SingleRestore(CurrentRowIndex()); };
            _menu.Items.Add(miApply);
            _menu.Items.Add(miRestore);
            _grid.ContextMenuStrip = _menu;

            // --- 右：控制面板
            TableLayoutPanel right = new TableLayoutPanel();
            right.Dock = DockStyle.Fill;
            right.ColumnCount = 1;
            right.RowCount = 4;
            right.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            right.RowStyles.Add(new RowStyle(SizeType.Absolute, 150f));
            right.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            right.RowStyles.Add(new RowStyle(SizeType.Absolute, 140f));
            right.RowStyles.Add(new RowStyle(SizeType.Absolute, 68f));
            right.Margin = new Padding(0);
            right.BackColor = Theme.Bg;
            body.Controls.Add(right, 1, 0);

            // 目标数值
            CardPanel cardCore = new CardPanel();
            cardCore.Title = "目标数值 · 一键应用";
            cardCore.Dock = DockStyle.Fill;
            cardCore.Margin = new Padding(0, 0, 0, 10);
            right.Controls.Add(cardCore, 0, 0);

            cardCore.Controls.Add(MkLabel("攻击力", 22, 58, 9.5f, Theme.Text, false));
            _numAtk = MkNum(96, 54, 112, 99, 1, 65535);
            cardCore.Controls.Add(_numAtk);
            cardCore.Controls.Add(MkLabel("2 字节", 220, 60, 8.5f, Theme.Dim, false));

            cardCore.Controls.Add(MkLabel("防御力", 22, 104, 9.5f, Theme.Text, false));
            _numDef = MkNum(96, 100, 112, 99, 1, 65535);
            cardCore.Controls.Add(_numDef);
            cardCore.Controls.Add(MkLabel("2 字节", 220, 106, 8.5f, Theme.Dim, false));

            Label all16 = MkLabel("共 16 人", 330, 66, 8.5f, Theme.Dim, false);
            cardCore.Controls.Add(all16);

            // 附加数值
            CardPanel cardExtra = new CardPanel();
            cardExtra.Title = "附加数值 · 可选";
            cardExtra.Dock = DockStyle.Fill;
            cardExtra.Margin = new Padding(0, 0, 0, 10);
            right.Controls.Add(cardExtra, 0, 1);

            _swHp = MkSwitch(cardExtra, 22, 52);
            cardExtra.Controls.Add(MkLabel("生命 / 血量", 78, 54, 9.5f, Theme.Text, false));
            _numHp = MkNum(258, 46, 112, 9999, 1, 65535);
            cardExtra.Controls.Add(_numHp);

            _swAgi = MkSwitch(cardExtra, 22, 86);
            cardExtra.Controls.Add(MkLabel("敏捷（4 字节）", 78, 88, 9.5f, Theme.Text, false));
            _numAgi = MkNum(258, 80, 112, 99, 1, 99999);
            cardExtra.Controls.Add(_numAgi);

            _swMov = MkSwitch(cardExtra, 22, 120);
            cardExtra.Controls.Add(MkLabel("移动", 78, 122, 9.5f, Theme.Text, false));
            _numMov = MkNum(258, 114, 112, 9, 1, 99);
            cardExtra.Controls.Add(_numMov);

            _swJmp = MkSwitch(cardExtra, 22, 154);
            cardExtra.Controls.Add(MkLabel("跳跃", 78, 156, 9.5f, Theme.Text, false));
            _numJmp = MkNum(258, 148, 112, 9, 1, 99);
            cardExtra.Controls.Add(_numJmp);

            _swPow = MkSwitch(cardExtra, 22, 188);
            cardExtra.Controls.Add(MkLabel("力气（20 人）", 78, 190, 9.5f, Theme.Text, false));
            _numPow = MkNum(258, 182, 112, 99, 1, 65535);
            cardExtra.Controls.Add(_numPow);

            _swHp.Toggled += delegate { SyncExtraEnabled(); };
            _swAgi.Toggled += delegate { SyncExtraEnabled(); };
            _swMov.Toggled += delegate { SyncExtraEnabled(); };
            _swJmp.Toggled += delegate { SyncExtraEnabled(); };
            _swPow.Toggled += delegate { SyncExtraEnabled(); };
            SyncExtraEnabled();

            // 循环守护
            CardPanel cardGuard = new CardPanel();
            cardGuard.Title = "循环守护";
            cardGuard.Dock = DockStyle.Fill;
            cardGuard.Margin = new Padding(0, 0, 0, 10);
            right.Controls.Add(cardGuard, 0, 2);

            _swGuard = MkSwitch(cardGuard, 22, 52);
            _swGuard.On = true;
            cardGuard.Controls.Add(MkLabel("游戏回写数值时自动纠正", 78, 56, 9f, Theme.Text, false));

            cardGuard.Controls.Add(MkLabel("间隔", 22, 98, 9f, Theme.Dim, false));
            _numInterval = MkNum(70, 94, 92, 400, 100, 5000);
            _numInterval.Increment = 50;
            cardGuard.Controls.Add(_numInterval);
            cardGuard.Controls.Add(MkLabel("毫秒", 176, 100, 9f, Theme.Dim, false));
            _swGuard.Toggled += delegate { _numInterval.Enabled = _swGuard.On; UpdateUi(); };

            // 按钮
            TableLayoutPanel btnRow = new TableLayoutPanel();
            btnRow.Dock = DockStyle.Fill;
            btnRow.ColumnCount = 2;
            btnRow.RowCount = 1;
            btnRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            btnRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 132f));
            btnRow.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
            btnRow.Margin = new Padding(0, 0, 0, 10);
            btnRow.BackColor = Theme.Bg;
            right.Controls.Add(btnRow, 0, 3);

            _btnRun = new PillButton();
            _btnRun.Text = "▶  应用";
            _btnRun.Dock = DockStyle.Fill;
            _btnRun.Margin = new Padding(0, 0, 8, 0);
            _btnRun.Click += delegate { OnRun(); };
            btnRow.Controls.Add(_btnRun, 0, 0);

            _btnRestore = new PillButton();
            _btnRestore.Text = "还原";
            _btnRestore.Outlined = true;
            _btnRestore.Dock = DockStyle.Fill;
            _btnRestore.Margin = new Padding(0);
            _btnRestore.Click += delegate { OnRestore(); };
            btnRow.Controls.Add(_btnRestore, 1, 0);

            // 日志
            CardPanel cardLog = new CardPanel();
            cardLog.Title = "运行日志";
            cardLog.Dock = DockStyle.Fill;
            cardLog.Margin = new Padding(20, 0, 20, 12);
            root.Controls.Add(cardLog, 0, 2);

            _log = new RichTextBox();
            _log.BorderStyle = BorderStyle.None;
            _log.BackColor = Color.FromArgb(0x11, 0x15, 0x1B);
            _log.ForeColor = Color.FromArgb(0xB9, 0xC4, 0xD2);
            _log.Font = Theme.Make(9f, FontStyle.Regular);
            _log.ReadOnly = true;
            _log.DetectUrls = false;
            _log.ScrollBars = RichTextBoxScrollBars.None;
            _log.Location = new Point(16, 44);
            _log.Size = new Size(cardLog.Width - 34, cardLog.Height - 56);
            _log.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            cardLog.Controls.Add(_log);

            // 页脚
            Panel footer = new Panel();
            footer.Dock = DockStyle.Fill;
            footer.Margin = new Padding(0);
            footer.BackColor = Color.FromArgb(0x11, 0x15, 0x1B);
            footer.Paint += delegate(object s, PaintEventArgs pe)
            {
                using (Pen p = new Pen(Color.FromArgb(0x20, 0x28, 0x33)))
                    pe.Graphics.DrawLine(p, 0, 0, footer.Width, 0);
            };
            root.Controls.Add(footer, 0, 3);

            _status = MkLabel("状态：未连接", 20, 13, 9f, Theme.Dim, false);
            _status.AutoSize = false;
            _status.AutoEllipsis = true;
            _status.Width = footer.Width - 184;
            _status.Height = 22;
            footer.Controls.Add(_status);
            footer.Resize += delegate { _status.Width = footer.Width - 184; };

            _btnElevate = new PillButton();
            _btnElevate.Text = "以管理员重启";
            _btnElevate.Size = new Size(132, 28);
            _btnElevate.Outlined = true;
            _btnElevate.Font = Theme.Make(8.5f, FontStyle.Bold);
            _btnElevate.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _btnElevate.Location = new Point(footer.Width - 152, 8);
            _btnElevate.Click += delegate { Elevate(); };
            footer.Controls.Add(_btnElevate);
            footer.Resize += delegate { _btnElevate.Location = new Point(footer.Width - 152, 8); };

            ResumeLayout(false);
        }

        private DataGridView BuildGrid()
        {
            DataGridView g = new DataGridView();
            g.Dock = DockStyle.None;
            g.BackgroundColor = Theme.Card;
            g.BorderStyle = BorderStyle.None;
            g.GridColor = Color.FromArgb(0x1E, 0x25, 0x30);
            g.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
            g.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None;
            g.RowHeadersVisible = false;
            g.AllowUserToAddRows = false;
            g.AllowUserToDeleteRows = false;
            g.AllowUserToResizeRows = false;
            g.AllowUserToResizeColumns = false;
            g.AllowUserToOrderColumns = false;
            g.ReadOnly = true;
            g.MultiSelect = false;
            g.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            g.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            g.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
            g.ColumnHeadersHeight = 34;
            g.RowTemplate.Height = 31;
            g.EnableHeadersVisualStyles = false;
            g.ScrollBars = ScrollBars.Vertical;

            DataGridViewCellStyle head = new DataGridViewCellStyle();
            head.BackColor = Color.FromArgb(0x1B, 0x22, 0x2C);
            head.ForeColor = Theme.Dim;
            head.SelectionBackColor = Color.FromArgb(0x1B, 0x22, 0x2C);
            head.Font = Theme.FSub;
            head.Alignment = DataGridViewContentAlignment.MiddleLeft;
            head.Padding = new Padding(9, 0, 0, 0);
            g.ColumnHeadersDefaultCellStyle = head;

            DataGridViewCellStyle cell = new DataGridViewCellStyle();
            cell.BackColor = Theme.Card;
            cell.ForeColor = Theme.Text;
            cell.SelectionBackColor = Color.FromArgb(0x1B, 0x3A, 0x31);
            cell.SelectionForeColor = Theme.Text;
            cell.Font = Theme.FBody;
            cell.Padding = new Padding(9, 0, 0, 0);
            g.DefaultCellStyle = cell;

            DataGridViewCellStyle alt = new DataGridViewCellStyle();
            alt.BackColor = Color.FromArgb(0x18, 0x1E, 0x26);
            g.AlternatingRowsDefaultCellStyle = alt;

            AddColumn(g, "name", "角色", 21, DataGridViewContentAlignment.MiddleLeft);
            AddColumn(g, "atk", "攻击", 12, DataGridViewContentAlignment.MiddleCenter);
            AddColumn(g, "def", "防御", 12, DataGridViewContentAlignment.MiddleCenter);
            AddColumn(g, "hp", "生命", 15, DataGridViewContentAlignment.MiddleCenter);
            AddColumn(g, "agi", "敏捷", 18, DataGridViewContentAlignment.MiddleCenter);
            AddColumn(g, "st", "状态", 22, DataGridViewContentAlignment.MiddleCenter);

            g.Rows.Clear();
            for (int i = 0; i < Table.Chars.Length; i++)
            {
                int idx = g.Rows.Add();
                g.Rows[idx].Cells[0].Value = Table.Chars[i].Name;
                g.Rows[idx].Cells[1].Value = "—";
                g.Rows[idx].Cells[2].Value = "—";
                g.Rows[idx].Cells[3].Value = "—";
                g.Rows[idx].Cells[4].Value = "—";
                g.Rows[idx].Cells[5].Value = "";
            }
            return g;
        }

        private static void AddColumn(DataGridView g, string name, string header, int fillWeight,
            DataGridViewContentAlignment align)
        {
            DataGridViewTextBoxColumn c = new DataGridViewTextBoxColumn();
            c.Name = name;
            c.HeaderText = header;
            c.FillWeight = fillWeight;
            c.SortMode = DataGridViewColumnSortMode.NotSortable;
            c.DefaultCellStyle.Alignment = align;
            c.ReadOnly = true;
            g.Columns.Add(c);
        }

        private static Label MkLabel(string text, int x, int y, float size, Color color, bool bold)
        {
            Label l = new Label();
            l.Text = text;
            l.AutoSize = true;
            l.Location = new Point(x, y);
            l.ForeColor = color;
            l.BackColor = Color.Transparent;
            l.Font = Theme.Make(size, bold ? FontStyle.Bold : FontStyle.Regular);
            return l;
        }

        private static NumBox MkNum(int x, int y, int w, long val, long min, long max)
        {
            NumBox n = new NumBox();
            n.Font = Theme.FNum;
            n.Minimum = min;
            n.Maximum = max;
            n.Value = val;
            n.Location = new Point(x, y);
            n.Size = new Size(w, 30);
            return n;
        }

        private static MiniSwitch MkSwitch(Control parent, int x, int y)
        {
            MiniSwitch s = new MiniSwitch();
            s.Location = new Point(x, y);
            s.BackColor = parent.BackColor;
            parent.Controls.Add(s);
            return s;
        }

        private static Icon BuildIcon()
        {
            Bitmap bmp = new Bitmap(32, 32);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(Color.FromArgb(0x13, 0x18, 0x1F));
                using (SolidBrush br = new SolidBrush(Theme.Accent)) g.FillEllipse(br, 1, 1, 30, 30);
                using (SolidBrush t = new SolidBrush(Color.FromArgb(0x08, 0x14, 0x10)))
                {
                    StringFormat sf = new StringFormat();
                    sf.Alignment = StringAlignment.Center;
                    sf.LineAlignment = StringAlignment.Center;
                    g.DrawString("99", Theme.Make(12f, FontStyle.Bold), t, new RectangleF(1, 1, 30, 30), sf);
                    sf.Dispose();
                }
            }
            return Icon.FromHandle(bmp.GetHicon());
        }

        // ------------------------------------------------------ 连接 / 状态
        private bool EnsureAttached()
        {
            if (_link.IsAttached) return true;
            return Connect(false);
        }

        // 仅供自动化验证：环境变量 UTA_TEST_BASE 可覆盖模块基址（跑假进程截图用）
        private void ApplyTestBaseOverride()
        {
            string tb = Environment.GetEnvironmentVariable("UTA_TEST_BASE");
            if (string.IsNullOrEmpty(tb)) return;
            try
            {
                long b = Convert.ToInt64(tb.Replace("0x", "").Replace("0X", ""), 16);
                if (b != 0 && b != _link.ModuleBase)
                {
                    _link.ModuleBase = b;
                    Log("[i] 测试基址覆盖为 0x" + b.ToString("X") + "（UTA_TEST_BASE）");
                }
            }
            catch { }
        }

        private bool Connect(bool verbose)
        {
            string err;
            if (_link.AttachAuto(out err))
            {
                ApplyTestBaseOverride();
                Log("[ok] 已连接 " + (verbose ? _link.ProcessPath : _link.ProcessName)
                    + "  PID " + _link.Pid + "  基址 0x" + _link.ModuleBase.ToString("X"));
                RefreshGrid();
                UpdateUi();
                return true;
            }
            if (verbose) Log("[!] " + err);
            RefreshGrid();
            UpdateUi();
            return false;
        }

        // CE 式进程选择：列出全部进程，手动连一个，并记住这次的选择
        private void PickProcess()
        {
            using (ProcessPickerForm dlg = new ProcessPickerForm(_link.IsAttached ? _link.Pid : Config.LastPid))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK || dlg.Picked == null) return;

                string err;
                if (_link.AttachPid(dlg.Picked.Pid, dlg.Picked.ExePath, out err))
                {
                    ApplyTestBaseOverride();
                    Log("[ok] 已连接 " + dlg.Picked.Name + ".exe  PID " + _link.Pid
                        + "  基址 0x" + _link.ModuleBase.ToString("X") + "（已记住，下次自动连它）");
                    RefreshGrid();
                    UpdateUi();
                }
                else
                {
                    Log("[!] 连接失败：" + err);
                    UpdateUi();
                }
            }
        }

        private void SyncExtraEnabled()
        {
            _numHp.Enabled = _swHp.On;
            _numAgi.Enabled = _swAgi.On;
            _numMov.Enabled = _swMov.On;
            _numJmp.Enabled = _swJmp.On;
            _numPow.Enabled = _swPow.On;
            _numHp.ForeColor = _swHp.On ? Theme.Text : Theme.Dim;
            _numAgi.ForeColor = _swAgi.On ? Theme.Text : Theme.Dim;
            _numMov.ForeColor = _swMov.On ? Theme.Text : Theme.Dim;
            _numJmp.ForeColor = _swJmp.On ? Theme.Text : Theme.Dim;
            _numPow.ForeColor = _swPow.On ? Theme.Text : Theme.Dim;
        }

        private void UpdateUi()
        {
            bool on = _link.IsAttached;
            _header.StatusText = on
                ? ("已连接 · PID " + _link.Pid + " · 基址 0x" + _link.ModuleBase.ToString("X"))
                : "未连接";
            _header.StatusOk = on;
            _header.Invalidate();

            if (_active)
                _btnRun.Text = "■  停止并还原";
            else
                _btnRun.Text = _swGuard.On ? "▶  应用 + 守护" : "▶  应用一次";

            _btnRestore.Enabled = !_bk.IsEmpty;
            _btnRun.Fill = _active ? Theme.Danger : Theme.Accent;

            string guard = _active
                ? ("守护中 " + _numInterval.Value + " ms")
                : (_swGuard.On ? "守护待命" : "守护关闭");
            _status.Text = "状态：" + (on ? ("已连接 " + _link.ProcessName + ".exe") : "未连接")
                + (_link.IsAttached ? ("   PID " + _link.Pid + "   基址 0x" + _link.ModuleBase.ToString("X")) : "")
                + "   ·   " + guard
                + "   ·   累计写入 " + _writeCount + " 次"
                + "   ·   目标 攻击 " + _numAtk.Value + " / 防御 " + _numDef.Value;
            _status.ForeColor = on ? Theme.Dim : Color.FromArgb(0xA8, 0x84, 0x50);
        }

        private void Log(string msg)
        {
            if (_log == null) return;
            _log.AppendText(DateTime.Now.ToString("HH:mm:ss") + "  " + msg + Environment.NewLine);
            _log.SelectionStart = _log.TextLength;
            _log.ScrollToCaret();
        }

        // ------------------------------------------------------ 读写逻辑
        private bool Backup16(long abs)
        {
            if (_bk.U16.ContainsKey(abs)) return true;
            ushort v;
            if (!_link.ReadU16(abs, out v)) return false;
            _bk.U16[abs] = v;
            return true;
        }

        private bool Backup32(long abs)
        {
            if (_bk.U32.ContainsKey(abs)) return true;
            uint v;
            if (!_link.ReadU32(abs, out v)) return false;
            _bk.U32[abs] = v;
            return true;
        }

        private void SaveOriginals()
        {
            foreach (CharInfo c in Table.Chars)
            {
                Backup16(c.AtkAbs);
                Backup16(c.DefAbs);
                if (_swHp.On) Backup16(c.HpAbs);
                if (_swAgi.On) Backup32(c.AgiAbs);
                if (_swMov.On) Backup16(c.MovAbs);
                if (_swJmp.On) Backup16(c.JmpAbs);
            }
            if (_swPow.On)
                foreach (PowerInfo p in Table.Powers) Backup16(p.Abs);
            _bk.Save();
        }

        // 返回成功写入的字段数
        private int ApplyOnce(bool onlyIfDifferent)
        {
            int n = 0;
            ushort atk = (ushort)_numAtk.Value;
            ushort def = (ushort)_numDef.Value;

            foreach (CharInfo c in Table.Chars)
            {
                if (Write16(c.AtkAbs, atk, onlyIfDifferent)) n++;
                if (Write16(c.DefAbs, def, onlyIfDifferent)) n++;

                if (_swHp.On && Write16(c.HpAbs, (ushort)_numHp.Value, onlyIfDifferent)) n++;
                if (_swAgi.On && Write32(c.AgiAbs, (uint)_numAgi.Value, onlyIfDifferent)) n++;
                if (_swMov.On && Write16(c.MovAbs, (ushort)_numMov.Value, onlyIfDifferent)) n++;
                if (_swJmp.On && Write16(c.JmpAbs, (ushort)_numJmp.Value, onlyIfDifferent)) n++;
            }

            if (_swPow.On)
            {
                ushort pow = (ushort)_numPow.Value;
                foreach (PowerInfo p in Table.Powers)
                    if (Write16(p.Abs, pow, onlyIfDifferent)) n++;
            }
            return n;
        }

        private bool Write16(long abs, ushort value, bool onlyIfDifferent)
        {
            if (onlyIfDifferent)
            {
                ushort cur;
                if (_link.ReadU16(abs, out cur) && cur == value) return false;
            }
            return _link.WriteU16(abs, value);
        }

        private bool Write32(long abs, uint value, bool onlyIfDifferent)
        {
            if (onlyIfDifferent)
            {
                uint cur;
                if (_link.ReadU32(abs, out cur) && cur == value) return false;
            }
            return _link.WriteU32(abs, value);
        }

        private int RestoreAll()
        {
            int n = 0;
            foreach (KeyValuePair<long, ushort> kv in _bk.U16)
                if (_link.WriteU16(kv.Key, kv.Value)) n++;
            foreach (KeyValuePair<long, uint> kv in _bk.U32)
                if (_link.WriteU32(kv.Key, kv.Value)) n++;
            return n;
        }

        // ------------------------------------------------------ 交互
        private void OnRun()
        {
            if (_active)
            {
                _active = false;
                int r = RestoreAll();
                Log("[ok] 守护已停止，已还原 " + r + " 个字段。");
                RefreshGrid();
                UpdateUi();
                return;
            }

            if (!EnsureAttached()) return;
            if (_bk.IsEmpty) SaveOriginals();

            int n = ApplyOnce(false);
            _writeCount += n;

            if (_swGuard.On)
            {
                _active = true;
                _timer.Interval = (int)_numInterval.Value;
                Log("[ok] 已写入 " + n + " 个字段，守护开启（" + _numInterval.Value + " ms）：攻击 "
                    + _numAtk.Value + " / 防御 " + _numDef.Value + ExtraText());
            }
            else
            {
                Log("[ok] 已单次写入 " + n + " 个字段：攻击 " + _numAtk.Value + " / 防御 " + _numDef.Value + ExtraText());
            }

            RefreshGrid();
            UpdateUi();
        }

        private string ExtraText()
        {
            StringBuilder sb = new StringBuilder();
            if (_swHp.On) sb.Append(" / 生命 ").Append(_numHp.Value);
            if (_swAgi.On) sb.Append(" / 敏捷 ").Append(_numAgi.Value);
            if (_swMov.On) sb.Append(" / 移动 ").Append(_numMov.Value);
            if (_swJmp.On) sb.Append(" / 跳跃 ").Append(_numJmp.Value);
            if (_swPow.On) sb.Append(" / 力气 ").Append(_numPow.Value);
            return sb.ToString();
        }

        private void OnRestore()
        {
            if (_bk.IsEmpty)
            {
                Log("[!] 还没有备份，先应用一次再还原。");
                return;
            }
            if (!EnsureAttached()) return;

            _active = false;
            int n = RestoreAll();
            Log("[ok] 已还原 " + n + " 个字段到原始数值。");
            RefreshGrid();
            UpdateUi();
        }

        private int CurrentRowIndex()
        {
            if (_grid.CurrentRow == null) return -1;
            return _grid.CurrentRow.Index;
        }

        private void SingleWrite(int i)
        {
            if (i < 0 || i >= Table.Chars.Length) return;
            if (!EnsureAttached()) return;
            SaveOriginals();
            CharInfo c = Table.Chars[i];
            bool a = _link.WriteU16(c.AtkAbs, (ushort)_numAtk.Value);
            bool d = _link.WriteU16(c.DefAbs, (ushort)_numDef.Value);
            Log(a && d
                ? ("[ok] " + c.Name + " → 攻击 " + _numAtk.Value + " / 防御 " + _numDef.Value)
                : ("[!] " + c.Name + " 写入失败"));
            RefreshGrid();
        }

        private void SingleRestore(int i)
        {
            if (i < 0 || i >= Table.Chars.Length) return;
            if (!EnsureAttached()) return;
            CharInfo c = Table.Chars[i];
            ushort a, d;
            if (_bk.U16.TryGetValue(c.AtkAbs, out a) && _bk.U16.TryGetValue(c.DefAbs, out d))
            {
                _link.WriteU16(c.AtkAbs, a);
                _link.WriteU16(c.DefAbs, d);
                Log("[ok] " + c.Name + " 已还原为 攻击 " + a + " / 防御 " + d);
            }
            else
            {
                Log("[!] " + c.Name + " 没有备份记录。");
            }
            RefreshGrid();
        }

        private void OnGridDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex >= 0) SingleWrite(e.RowIndex);
        }

        private void OnTick(object sender, EventArgs e)
        {
            if (_link.IsAttached && !_link.IsAlive())
            {
                _link.Detach();
                Log("[i] 游戏进程已退出" + (_active ? "，等待重新启动后自动重连…" : "。"));
            }

            if (_active)
            {
                if (!_link.IsAttached)
                {
                    string err;
                    if (_link.AttachAuto(out err))
                    {
                        Log("[i] 自动重连成功 PID " + _link.Pid + "，基址 0x" + _link.ModuleBase.ToString("X") + "，重新备份原始值。");
                        _bk.Clear();
                        SaveOriginals();
                    }
                }
                else
                {
                    _writeCount += ApplyOnce(true);
                }
            }

            RefreshGrid();
            UpdateUi();
        }

        private void RefreshGrid()
        {
            bool on = _link.IsAttached;
            ushort tAtk = (ushort)Math.Min(_numAtk.Value, 65535L);
            ushort tDef = (ushort)Math.Min(_numDef.Value, 65535L);

            for (int i = 0; i < Table.Chars.Length && i < _grid.Rows.Count; i++)
            {
                CharInfo c = Table.Chars[i];
                DataGridViewRow row = _grid.Rows[i];

                if (!on)
                {
                    row.Cells[1].Value = "—";
                    row.Cells[2].Value = "—";
                    row.Cells[3].Value = "—";
                    row.Cells[4].Value = "—";
                    row.Cells[5].Value = "";
                    continue;
                }

                ushort atk, def, hp;
                uint agi;
                bool okA = _link.ReadU16(c.AtkAbs, out atk);
                bool okD = _link.ReadU16(c.DefAbs, out def);
                bool okH = _link.ReadU16(c.HpAbs, out hp);
                bool okG = _link.ReadU32(c.AgiAbs, out agi);

                row.Cells[1].Value = okA ? atk.ToString() : "?";
                row.Cells[2].Value = okD ? def.ToString() : "?";
                row.Cells[3].Value = okH ? hp.ToString() : "?";
                row.Cells[4].Value = okG ? agi.ToString() : "?";

                bool hit = okA && okD && atk == tAtk && def == tDef;
                if (hit)
                {
                    row.Cells[5].Value = "✔ 生效";
                    row.Cells[5].Style.ForeColor = Theme.Accent;
                }
                else if (!okA || !okD)
                {
                    row.Cells[5].Value = "失败";
                    row.Cells[5].Style.ForeColor = Theme.Dim;
                }
                else
                {
                    row.Cells[5].Value = "原始";
                    row.Cells[5].Style.ForeColor = Theme.Dim;
                }
            }
        }

        private void Elevate()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = Application.ExecutablePath;
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                Process.Start(psi);
                Close();
            }
            catch (Exception ex)
            {
                Log("[!] 提权失败：" + ex.Message);
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (_active)
            {
                RestoreAll();
            }
            _bk.Save();
            if (_timer != null) _timer.Stop();
            base.OnFormClosing(e);
        }
    }

    // ---------------------------------------------------------------- 自检
    internal static class SelfTest
    {
        public static int Run(StringBuilder log)
        {
            int pass = 0;
            int fail = 0;

            log.AppendLine("== 二人白皇 属性修改器 self test ==");

            IntPtr mem = Native.VirtualAlloc(IntPtr.Zero, (IntPtr)Table.RegionSize,
                Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_READWRITE);
            if (mem == IntPtr.Zero)
            {
                log.AppendLine("VirtualAlloc FAILED: " + Marshal.GetLastWin32Error());
                log.AppendLine("RESULT: FAIL");
                return 1;
            }

            long fakeModule = mem.ToInt64() - (Table.RegionAbs - Table.ImageBase);
            log.AppendLine("test region  : 0x" + mem.ToInt64().ToString("X"));
            log.AppendLine("fake module  : 0x" + fakeModule.ToString("X"));

            GameLink link = new GameLink();
            string err;
            if (!link.AttachSelfForTest(fakeModule, out err))
            {
                log.AppendLine("attach FAILED: " + err);
                log.AppendLine("RESULT: FAIL");
                Native.VirtualFree(mem, IntPtr.Zero, Native.MEM_RELEASE);
                return 1;
            }

            // 1) 每个角色 6 个字段的读写往返
            for (int i = 0; i < Table.Chars.Length; i++)
            {
                CharInfo c = Table.Chars[i];
                pass += Check(log, link, c.Name + ".攻击", c.AtkAbs, (ushort)(100 + i));
                pass += Check(log, link, c.Name + ".防御", c.DefAbs, (ushort)(200 + i));
                pass += Check(log, link, c.Name + ".生命", c.HpAbs, (ushort)(300 + i));
                pass += CheckU32(log, link, c.Name + ".敏捷", c.AgiAbs, (uint)(1000 + i));
                pass += Check(log, link, c.Name + ".移动", c.MovAbs, (ushort)(10 + i));
                pass += Check(log, link, c.Name + ".跳跃", c.JmpAbs, (ushort)(20 + i));
            }

            // 2) 力气 20 条
            for (int i = 0; i < Table.Powers.Length; i++)
                pass += Check(log, link, "力气:" + Table.Powers[i].Name, Table.Powers[i].Abs, (ushort)(500 + i));

            // 3) 边界值
            pass += Check(log, link, "边界 0", Table.Chars[0].AtkAbs, 0);
            pass += Check(log, link, "边界 65535", Table.Chars[0].AtkAbs, 65535);
            pass += CheckU32(log, link, "边界 0xFFFFFFFF", Table.Chars[0].AgiAbs, 0xFFFFFFFFu);

            // 4) 未映射地址必须失败
            ushort dummy;
            bool mapped = link.ReadU16(0x7FFFFFF0000L, out dummy);
            if (mapped)
            {
                log.AppendLine("FAIL  未映射地址应当读取失败，但读到了值 " + dummy);
                fail++;
            }
            else
            {
                log.AppendLine("PASS  未映射地址读取正确失败");
                pass++;
            }

            // 5) 地址表一致性（布局偏移 + 与 CT 表核对过的关键地址）
            fail += CheckTable(log, ref pass);

            link.Dispose();
            Native.VirtualFree(mem, IntPtr.Zero, Native.MEM_RELEASE);

            log.AppendLine("----");
            log.AppendLine("pass = " + pass + "   fail = " + fail);
            log.AppendLine(fail == 0 ? "RESULT: PASS" : "RESULT: FAIL");
            return fail == 0 ? 0 : 1;
        }

        private static int Check(StringBuilder log, GameLink link, string name, long abs, ushort value)
        {
            bool w = link.WriteU16(abs, value);
            ushort back;
            bool r = link.ReadU16(abs, out back);
            bool ok = w && r && back == value;
            if (!ok) log.AppendLine("FAIL  " + name + " 期望 " + value + " 实际 " + (r ? back.ToString() : "读失败"));
            return ok ? 1 : 0;
        }

        private static int CheckU32(StringBuilder log, GameLink link, string name, long abs, uint value)
        {
            bool w = link.WriteU32(abs, value);
            uint back;
            bool r = link.ReadU32(abs, out back);
            bool ok = w && r && back == value;
            if (!ok) log.AppendLine("FAIL  " + name + " 期望 " + value + " 实际 " + (r ? back.ToString() : "读失败"));
            return ok ? 1 : 0;
        }

        // 返回失败数量；成功计入 pass
        private static int CheckTable(StringBuilder log, ref int pass)
        {
            int fail = 0;

            // 生命/攻击/防御/敏捷/移动/跳跃 的固定偏移
            for (int i = 0; i < Table.Chars.Length; i++)
            {
                CharInfo c = Table.Chars[i];
                bool ok = (c.AtkAbs == c.HpAbs + 4) && (c.DefAbs == c.HpAbs + 6)
                          && (c.AgiAbs == c.HpAbs + 8) && (c.MovAbs == c.HpAbs + 0xC)
                          && (c.JmpAbs == c.HpAbs + 0xE);
                if (!ok)
                {
                    log.AppendLine("FAIL  " + c.Name + " 属性块偏移异常");
                    fail++;
                }
                else pass++;
            }

            // 与 CT 表抽检
            fail += Expect(log, ref pass, "奥修特尔（哈克）.攻击", Table.Chars[0].AtkAbs, 0x00B06744L);
            fail += Expect(log, ref pass, "久远.攻击", Table.Chars[1].AtkAbs, 0x00B069ECL);
            fail += Expect(log, ref pass, "久远.经验", Table.Chars[1].ExpAbs, 0x00B069DEL);
            fail += Expect(log, ref pass, "奇羽.跳跃", Table.Chars[7].JmpAbs, 0x00B07C8EL);
            fail += Expect(log, ref pass, "宗近.攻击", Table.Chars[11].AtkAbs, 0x00B08724L);
            fail += Expect(log, ref pass, "环.经验", Table.Chars[13].ExpAbs, 0x00B09C56L);
            fail += Expect(log, ref pass, "莎莎拉.防御", Table.Chars[14].DefAbs, 0x00B09F0EL);
            fail += Expect(log, ref pass, "神哈克.血量", Table.Chars[15].HpAbs, 0x00B0DEC8L);
            fail += Expect(log, ref pass, "哈克神.力气", Table.Powers[19].Abs, 0x00B0DF20L);
            return fail;
        }

        private static int Expect(StringBuilder log, ref int pass, string name, long actual, long expect)
        {
            if (actual == expect)
            {
                pass++;
                return 0;
            }
            log.AppendLine("FAIL  " + name + " 应为 0x" + expect.ToString("X") + " 实际 0x" + actual.ToString("X"));
            return 1;
        }
    }

    // ---------------------------------------------------------------- 命令行
    internal static class Cli
    {
        public static int Run(string[] args)
        {
            StringBuilder log = new StringBuilder();

            bool console = Native.AttachConsole(-1);
            if (console)
            {
                StreamWriter w = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false));
                w.AutoFlush = true;
                Console.SetOut(w);
            }

            int code = Exec(args, log);

            Console.Write(log.ToString());
            try
            {
                File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cli-out.txt"),
                    log.ToString(), new UTF8Encoding(false));
            }
            catch
            {
            }
            return code;
        }

        private static int Exec(string[] args, StringBuilder log)
        {
            string cmd = args[0].ToLowerInvariant();

            if (cmd == "--selftest")
            {
                return SelfTest.Run(log);
            }

            if (cmd == "--list")
            {
                PrintTable(log);
                return 0;
            }

            using (GameLink link = new GameLink())
            {
                // 解析参数
                int pid = 0;
                string proc = null;
                long baseOverride = 0;
                List<string> rest = new List<string>();
                for (int i = 1; i < args.Length; i++)
                {
                    string a = args[i];
                    if (a == "--pid" && i + 1 < args.Length) { int.TryParse(args[++i], out pid); }
                    else if (a == "--proc" && i + 1 < args.Length) { proc = args[++i]; }
                    else if (a == "--base" && i + 1 < args.Length)
                    {
                        string hex = args[++i];
                        if (hex.StartsWith("0x") || hex.StartsWith("0X")) hex = hex.Substring(2);
                        long.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out baseOverride);
                    }
                    else rest.Add(a);
                }

                Config.Load();

                // 命令行也能看到进程列表（GUI 里有「选择进程」窗口）
                if (cmd == "--ps")
                {
                    log.AppendLine("PID    位数  内存MB  读写  疑似  进程名                        窗口标题");
                    List<ProcEntry> all = ProcScan.List(false, false);
                    foreach (ProcEntry pe in all)
                    {
                        string t = pe.Title ?? "";
                        if (t.Length > 30) t = t.Substring(0, 30);
                        log.AppendLine(string.Format("{0,-6} {1,-5} {2,7}  {3}  {4}  {5,-26}  {6}",
                            pe.Pid, pe.Is32 ? "32" : "64", pe.MemMB,
                            pe.CanRead ? "✔" : "✖", pe.Likely ? "★" : " ", pe.Name, t));
                    }
                    log.AppendLine("total        : " + all.Count + " 个进程");
                    log.AppendLine("last-process : " + (Config.LastProcess.Length == 0 ? "(无)" : Config.LastProcess));
                    return 0;
                }

                string err;
                bool attached;
                if (pid != 0)
                {
                    attached = link.AttachPid(pid, null, out err);
                }
                else if (proc != null)
                {
                    string want = proc.Replace(".exe", "");
                    ProcEntry hit = null;
                    foreach (ProcEntry e in ProcScan.List(false, false))
                    {
                        if (string.Equals(e.Name.Replace(".exe", ""), want, StringComparison.OrdinalIgnoreCase))
                        {
                            hit = e;
                            break;
                        }
                    }
                    if (hit == null)
                    {
                        log.AppendLine("[!] 没找到进程: " + proc);
                        return 2;
                    }
                    attached = link.AttachPid(hit.Pid, hit.ExePath, out err);
                }
                else if (baseOverride != 0)
                {
                    // 纯离线：把已分配内存当成模块基址（自检 / 假进程校验）
                    attached = link.AttachSelfForTest(baseOverride, out err);
                }
                else
                {
                    attached = link.AttachAuto(out err);
                }

                if (!attached)
                {
                    log.AppendLine("[!] " + err);
                    return 2;
                }

                // 连上真进程后仍可覆盖基址，用于假进程内存校验
                if (baseOverride != 0 && link.ModuleBase != baseOverride)
                {
                    link.ModuleBase = baseOverride;
                    log.AppendLine("base    : 已覆盖为 0x" + baseOverride.ToString("X") + "（测试用）");
                }

                log.AppendLine("process : " + link.ProcessName + "  PID " + link.Pid);
                log.AppendLine("module  : 0x" + link.ModuleBase.ToString("X"));

                if (cmd == "--apply")
                {
                    ushort atk = 99, def = 99;
                    if (rest.Count > 0) ushort.TryParse(rest[0], out atk);
                    if (rest.Count > 1) ushort.TryParse(rest[1], out def);

                    BackupStore bk = new BackupStore();
                    bk.Load();
                    foreach (CharInfo c in Table.Chars)
                    {
                        if (!bk.U16.ContainsKey(c.AtkAbs)) { ushort v; if (link.ReadU16(c.AtkAbs, out v)) bk.U16[c.AtkAbs] = v; }
                        if (!bk.U16.ContainsKey(c.DefAbs)) { ushort v; if (link.ReadU16(c.DefAbs, out v)) bk.U16[c.DefAbs] = v; }
                    }
                    bk.Save();

                    int n = 0;
                    foreach (CharInfo c in Table.Chars)
                    {
                        if (link.WriteU16(c.AtkAbs, atk)) n++;
                        if (link.WriteU16(c.DefAbs, def)) n++;
                    }
                    log.AppendLine("applied : 攻击 " + atk + " / 防御 " + def + "   字段 " + n + "/" + (Table.Chars.Length * 2));
                    PrintRows(log, link);
                    return n == Table.Chars.Length * 2 ? 0 : 1;
                }

                if (cmd == "--off")
                {
                    BackupStore bk = new BackupStore();
                    bk.Load();
                    if (bk.IsEmpty)
                    {
                        log.AppendLine("[!] 没有备份文件: " + BackupStore.FilePath);
                        return 2;
                    }
                    int n = 0;
                    foreach (KeyValuePair<long, ushort> kv in bk.U16)
                        if (link.WriteU16(kv.Key, kv.Value)) n++;
                    foreach (KeyValuePair<long, uint> kv in bk.U32)
                        if (link.WriteU32(kv.Key, kv.Value)) n++;
                    log.AppendLine("restored: " + n + " 个字段");
                    PrintRows(log, link);
                    return 0;
                }

                if (cmd == "--guard")
                {
                    int secs = 20;
                    ushort gatk = 99, gdef = 99;
                    if (rest.Count > 0) int.TryParse(rest[0], out secs);
                    if (rest.Count > 1) ushort.TryParse(rest[1], out gatk);
                    if (rest.Count > 2) ushort.TryParse(rest[2], out gdef);

                    BackupStore gb = new BackupStore();
                    gb.Load();
                    foreach (CharInfo c in Table.Chars)
                    {
                        ushort v;
                        if (!gb.U16.ContainsKey(c.AtkAbs) && link.ReadU16(c.AtkAbs, out v)) gb.U16[c.AtkAbs] = v;
                        if (!gb.U16.ContainsKey(c.DefAbs) && link.ReadU16(c.DefAbs, out v)) gb.U16[c.DefAbs] = v;
                    }
                    gb.Save();

                    int writes = 0;
                    DateTime stop = DateTime.Now.AddSeconds(secs);
                    while (DateTime.Now < stop)
                    {
                        foreach (CharInfo c in Table.Chars)
                        {
                            ushort cur;
                            if (!link.ReadU16(c.AtkAbs, out cur) || cur != gatk)
                            {
                                if (link.WriteU16(c.AtkAbs, gatk)) writes++;
                            }
                            if (!link.ReadU16(c.DefAbs, out cur) || cur != gdef)
                            {
                                if (link.WriteU16(c.DefAbs, gdef)) writes++;
                            }
                        }
                        System.Threading.Thread.Sleep(200);
                    }
                    log.AppendLine("guard   : " + secs + " 秒内纠正写入 " + writes + " 次（攻击 " + gatk + " / 防御 " + gdef + "）");
                    PrintRows(log, link);
                    return 0;
                }

                if (cmd == "--dump")
                {
                    PrintRows(log, link);
                    return 0;
                }

                log.AppendLine("usage:");
                log.AppendLine("  --apply [atk] [def]   写入攻击/防御（默认 99/99）");
                log.AppendLine("  --off                 还原备份");
                log.AppendLine("  --dump                打印当前读数");
                log.AppendLine("  --list                打印地址表");
                log.AppendLine("  --ps                  列出所有进程（含位数/内存）");
                log.AppendLine("  --selftest            自检");
                log.AppendLine("  --pid N / --proc NAME 指定进程");
                log.AppendLine("  --base 0x...          指定模块基址（假进程测试用）");
                return 1;
            }
        }

        private static void PrintTable(StringBuilder log)
        {
            log.AppendLine("== 二人白皇 属性地址表（模块基址 0x400000）==");
            for (int i = 0; i < Table.Chars.Length; i++)
            {
                CharInfo c = Table.Chars[i];
                log.AppendLine(string.Format("{0,-16} 生命 0x{1:X}  攻击 0x{2:X}  防御 0x{3:X}  敏捷 0x{4:X}  移动 0x{5:X}  跳跃 0x{6:X}{7}",
                    c.Name, c.HpAbs, c.AtkAbs, c.DefAbs, c.AgiAbs, c.MovAbs, c.JmpAbs,
                    c.HasExp ? ("  经验 0x" + c.ExpAbs.ToString("X")) : ""));
            }
            log.AppendLine("-- 力气 20 条 --");
            for (int i = 0; i < Table.Powers.Length; i++)
                log.AppendLine(string.Format("{0,-16} 0x{1:X}", Table.Powers[i].Name, Table.Powers[i].Abs));
            log.AppendLine("角色数 " + Table.Chars.Length + "，力气条数 " + Table.Powers.Length);
        }

        private static void PrintRows(StringBuilder log, GameLink link)
        {
            log.AppendLine("name\tatk\tdef\thp\tagi");
            foreach (CharInfo c in Table.Chars)
            {
                ushort atk, def, hp;
                uint agi;
                bool a = link.ReadU16(c.AtkAbs, out atk);
                bool d = link.ReadU16(c.DefAbs, out def);
                bool h = link.ReadU16(c.HpAbs, out hp);
                bool g = link.ReadU32(c.AgiAbs, out agi);
                log.AppendLine(c.Name + "\t" + (a ? atk.ToString() : "?") + "\t" + (d ? def.ToString() : "?")
                    + "\t" + (h ? hp.ToString() : "?") + "\t" + (g ? agi.ToString() : "?"));
            }
        }
    }

    // ---------------------------------------------------------------- 入口
    internal static class Program
    {
        // 出异常时不弹那个看不懂的 .NET 崩溃框，而是落一份可读日志 + 简短提示
        internal static void LogCrash(Exception ex)
        {
            try
            {
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "错误日志.txt");
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("时间: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                sb.AppendLine("程序: " + AppDomain.CurrentDomain.FriendlyName);
                sb.AppendLine(ex == null ? "(未知异常)" : ex.ToString());
                File.AppendAllText(path, sb.ToString() + Environment.NewLine, new UTF8Encoding(false));
            }
            catch
            {
            }
            MessageBox.Show("程序遇到一个内部错误，已记录到「错误日志.txt」。\n\n"
                + (ex == null ? "" : ex.GetType().Name + ": " + ex.Message),
                "出错了", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        [STAThread]
        private static int Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += delegate(object s, System.Threading.ThreadExceptionEventArgs e) { LogCrash(e.Exception); };
            AppDomain.CurrentDomain.UnhandledException += delegate(object s, UnhandledExceptionEventArgs e) { LogCrash(e.ExceptionObject as Exception); };
            Config.Load();

            // --picker：只弹进程选择窗口（试看/截图用）
            if (args.Length > 0 && args[0] == "--picker")
            {
                ProcessPickerForm pf = new ProcessPickerForm(Config.LastPid);
                Application.Run(pf);
                return 0;
            }

            if (args.Length > 0 && args[0].StartsWith("--", StringComparison.Ordinal))
            {
                return Cli.Run(args);
            }

            Application.Run(new MainForm());
            return 0;
        }
    }
}
