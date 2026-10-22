// 测试替身：模拟「二人白皇」进程的内存布局，用于验证跨进程读写与循环守护。
// 分配一块 0x8000 的内存覆盖 0xB06000 ~ 0xB0E000，按 CT 表的绝对地址写初值，
// 并且每 2 秒把攻击/防御「刷回」初值，模拟游戏自己回写数值的行为。
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

internal static class FakeNative
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);
}

internal static class FakeGame
{
    // 与 Program.cs 里的 Table.RegionAbs / ImageBase 保持一致
    private const long RegionAbs = 0xB06000L;
    private const long ImageBase = 0x400000L;
    private const int RegionSize = 0x8000;

    // 16 个角色的「生命 / 血量」绝对地址
    private static readonly long[] HpAbs = new long[]
    {
        0x00B06740L, 0x00B069E8L, 0x00B06F38L, 0x00B071E0L,
        0x00B07488L, 0x00B07730L, 0x00B079D8L, 0x00B07C80L,
        0x00B07F28L, 0x00B081D0L, 0x00B08478L, 0x00B08720L,
        0x00B089C8L, 0x00B09C60L, 0x00B09F08L, 0x00B0DEC8L,
    };

    private static readonly string[] Names = new string[]
    {
        "奥修特尔", "久远", "露露提耶", "乌璐鲁萨拉拉", "鵟", "扇", "猫音", "奇羽",
        "阿图依", "杏树", "亚库托瓦尔特", "宗近", "福米璐璐", "环", "莎莎拉", "神哈克",
    };

    // 20 条「力气」
    private static readonly long[] PowAbs = new long[]
    {
        0x00B06A40L, 0x00B06798L, 0x00B06CE8L, 0x00B06F90L, 0x00B07238L,
        0x00B074E0L, 0x00B07788L, 0x00B07A30L, 0x00B07CD8L, 0x00B07F80L,
        0x00B08228L, 0x00B084D0L, 0x00B08778L, 0x00B08A20L, 0x00B08CC8L,
        0x00B08F70L, 0x00B09218L, 0x00B09CB8L, 0x00B09F60L, 0x00B0DF20L,
    };

    private static long _mem;

    private static IntPtr At(long abs)
    {
        return new IntPtr(_mem + (abs - RegionAbs));
    }

    private static void Seed()
    {
        for (int i = 0; i < HpAbs.Length; i++)
        {
            long hp = HpAbs[i];
            Marshal.WriteInt16(At(hp), (short)(1000 + i));
            Marshal.WriteInt16(At(hp + 4), (short)7);   // 攻击
            Marshal.WriteInt16(At(hp + 6), (short)3);   // 防御
            Marshal.WriteInt32(At(hp + 8), 40 + i);     // 敏捷
            Marshal.WriteInt16(At(hp + 0xC), (short)5); // 移动
            Marshal.WriteInt16(At(hp + 0xE), (short)5); // 跳跃
        }
        for (int i = 0; i < PowAbs.Length; i++)
            Marshal.WriteInt16(At(PowAbs[i]), (short)(10 + i));
    }

    // 模拟游戏按成长表回写数值
    private static void GameRewrite()
    {
        for (int i = 0; i < HpAbs.Length; i++)
        {
            long hp = HpAbs[i];
            Marshal.WriteInt16(At(hp + 4), (short)7);
            Marshal.WriteInt16(At(hp + 6), (short)3);
        }
    }

    private static void Dump(string dir)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < HpAbs.Length; i++)
        {
            long hp = HpAbs[i];
            sb.AppendFormat("{0}:hp={1},atk={2},def={3},agi={4} ",
                Names[i],
                Marshal.ReadInt16(At(hp)),
                Marshal.ReadInt16(At(hp + 4)),
                Marshal.ReadInt16(At(hp + 6)),
                Marshal.ReadInt32(At(hp + 8)));
        }
        sb.AppendLine();
        for (int i = 0; i < PowAbs.Length; i++)
            sb.AppendFormat("pow{0}={1} ", i, Marshal.ReadInt16(At(PowAbs[i])));
        sb.AppendLine();
        File.WriteAllText(Path.Combine(dir, "fakegame-state.txt"), sb.ToString(), new UTF8Encoding(false));
    }

    private static void Main(string[] args)
    {
        string dir = AppDomain.CurrentDomain.BaseDirectory;

        IntPtr mem = FakeNative.VirtualAlloc(IntPtr.Zero, (IntPtr)RegionSize, 0x3000, 0x04);
        _mem = mem.ToInt64();

        long fakeBase = _mem - (RegionAbs - ImageBase);
        StringBuilder init = new StringBuilder();
        init.AppendLine("alloc=0x" + _mem.ToString("X"));
        init.AppendLine("base=0x" + fakeBase.ToString("X"));
        init.AppendLine("module=0x" + Process.GetCurrentProcess().MainModule.BaseAddress.ToInt64().ToString("X"));
        File.WriteAllText(Path.Combine(dir, "fakegame-init.txt"), init.ToString(), new UTF8Encoding(false));

        if (mem == IntPtr.Zero) return;

        Seed();

        int seconds = 90;
        if (args.Length > 0) int.TryParse(args[0], out seconds);

        DateTime end = DateTime.Now.AddSeconds(seconds);
        DateTime nextRewrite = DateTime.Now.AddSeconds(2);
        while (DateTime.Now < end)
        {
            if (DateTime.Now >= nextRewrite)
            {
                GameRewrite();
                nextRewrite = DateTime.Now.AddSeconds(2);
            }
            Dump(dir);
            Thread.Sleep(250);
        }
    }
}
