// 截图小工具：Shot.exe <输出png> [标题关键字]
// 先 SetProcessDPIAware 再取窗口矩形，避免 DPI 虚拟化导致截歪；优先 PrintWindow。
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Text;

internal static class Shot
{
    [DllImport("user32.dll")] private static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] private static extern int GetWindowTextLength(IntPtr h);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] private static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
    private delegate bool EnumProc(IntPtr h, IntPtr l);
    private struct RECT { public int L, T, R, B; }

    private static string _want;
    private static IntPtr _found;

    private static bool Cb(IntPtr h, IntPtr l)
    {
        if (!IsWindowVisible(h)) return true;
        int len = GetWindowTextLength(h);
        if (len <= 0) return true;
        StringBuilder sb = new StringBuilder(len + 2);
        GetWindowText(h, sb, sb.Capacity);
        string t = sb.ToString();
        if (t.IndexOf(_want, StringComparison.OrdinalIgnoreCase) >= 0)
        {
            _found = h;
            return false;
        }
        return true;
    }

    private static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("用法: Shot.exe <输出png> [标题关键字]");
            return 2;
        }
        string outPath = args[0];
        _want = args.Length > 1 ? args[1] : "";

        SetProcessDPIAware();
        EnumWindows(Cb, IntPtr.Zero);
        if (_found == IntPtr.Zero)
        {
            Console.WriteLine("没找到窗口: " + _want);
            return 1;
        }

        RECT r;
        GetWindowRect(_found, out r);
        int w = r.R - r.L;
        int h = r.B - r.T;
        if (w <= 0 || h <= 0)
        {
            Console.WriteLine("窗口尺寸异常");
            return 1;
        }

        using (Bitmap bmp = new Bitmap(w, h))
        {
            using (Graphics g = Graphics.FromImage(bmp))
            {
                IntPtr hdc = g.GetHdc();
                bool ok = PrintWindow(_found, hdc, 2); // PW_RENDERFULLCONTENT
                g.ReleaseHdc(hdc);
                if (!ok) g.CopyFromScreen(r.L, r.T, 0, 0, bmp.Size);
            }
            bmp.Save(outPath, ImageFormat.Png);
        }
        Console.WriteLine("saved " + outPath + "  " + w + "x" + h);
        return 0;
    }
}
