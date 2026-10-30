using System.Text;

namespace GostCsharp;

/// <summary>
/// Conformance self-test (run with "--selftest"): Appendix A byte for byte,
/// the reference and mode known answers, round trips, invalid parameters, padding.
/// </summary>
internal static class SelfTest
{
    static int failures;

    static void Check(bool ok, string what)
    {
        if (!ok)
        {
            failures++;
            Console.WriteLine("FAIL: " + what);
        }
    }

    public static int Run(string resources)
    {
        failures = 0;
        AppendixA(resources);
        ReferenceKat(resources);
        ModesKat(resources);
        RoundTrip();
        InvalidParameters();
        Padding();
        Console.WriteLine(failures == 0 ? "selftest: all checks passed" : $"selftest: {failures} failure(s)");
        return failures == 0 ? 0 : 1;
    }

    static void AppendixA(string resources)
    {
        string tmp = Path.GetTempFileName();
        try
        {
            PRNG.init(0);
            using (var src = File.OpenRead(Path.Combine(resources, "input.bin")))
            using (var f = new StreamWriter(tmp, false, new UTF8Encoding(false)))
                TestVectors.ShortTestVectors(f, src);
            string got = File.ReadAllText(tmp).TrimEnd('\n');
            string want = File.ReadAllText(Path.Combine(resources, "gold.txt")).TrimEnd('\n');
            Check(got == want, "Appendix A output differs from gold.txt");
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    static IEnumerable<string[]> Records(string resources, string name) =>
        File.ReadLines(Path.Combine(resources, name))
            .Where(l => l.Length > 0 && l[0] != '#')
            .Select(l => l.Split(' ', StringSplitOptions.RemoveEmptyEntries));

    static void ReferenceKat(string resources)
    {
        int n = 0;
        foreach (var f in Records(resources, "reference_kat.txt"))
        {
            byte[] key = Convert.FromHexString(f[2]), pt = Convert.FromHexString(f[3]), ct = Convert.FromHexString(f[4]);
            using var c = new QalqanCipher(key, pt.Length);
            var buf = new byte[pt.Length];
            c.EncryptBlock(pt, buf);
            Check(buf.AsSpan().SequenceEqual(ct), $"reference KAT encrypt {f[0]}/{f[1]}");
            c.DecryptBlock(ct, buf);
            Check(buf.AsSpan().SequenceEqual(pt), $"reference KAT decrypt {f[0]}/{f[1]}");
            n++;
        }
        Check(n == 84, $"expected 84 reference cases, found {n}");
    }

    static void ModesKat(string resources)
    {
        int n = 0;
        foreach (var f in Records(resources, "modes_kat.txt"))
        {
            byte[] key = Convert.FromHexString(f[3]), pt = Convert.FromHexString(f[5]), ct = Convert.FromHexString(f[6]);
            byte[] iv = f[4] == "-" ? [] : Convert.FromHexString(f[4]);
            using var c = new QalqanCipher(key, int.Parse(f[2]) / 8);
            var enc = new byte[pt.Length];
            var dec = (byte[])ct.Clone(); // decrypt in place
            switch (f[0])
            {
                case "ECB": Modes.EcbEncrypt(c, pt, enc); Modes.EcbDecrypt(c, dec, dec); break;
                case "CBC": Modes.CbcEncrypt(c, iv, pt, enc); Modes.CbcDecrypt(c, iv, dec, dec); break;
                case "CFB": Modes.CfbEncrypt(c, iv, pt, enc); Modes.CfbDecrypt(c, iv, dec, dec); break;
                case "OFB": Modes.Ofb(c, iv, pt, enc); Modes.Ofb(c, iv, dec, dec); break;
                case "CTR": Modes.Ctr(c, iv, pt, enc); Modes.Ctr(c, iv, dec, dec); break;
                default: Check(false, "unknown mode " + f[0]); continue;
            }
            Check(enc.AsSpan().SequenceEqual(ct), $"{f[0]} encrypt {f[1]}/{f[2]}");
            Check(dec.AsSpan().SequenceEqual(pt), $"{f[0]} decrypt {f[1]}/{f[2]}");
            n++;
        }
        Check(n == 54, $"expected 54 mode cases, found {n}");
    }

    static void RoundTrip()
    {
        var rng = new Random(7);
        foreach (int blen in new[] { 16, 32, 64 })
            for (int klen = Qalqan.MINKEYLEN; klen <= Qalqan.MAXKEYLEN; klen += Qalqan.KEYLENSTEP)
                for (int t = 0; t < 50; t++)
                {
                    var key = new byte[klen];
                    var pt = new byte[blen];
                    rng.NextBytes(key);
                    rng.NextBytes(pt);
                    using var c = new QalqanCipher(key, blen);
                    Check(c.Rounds == 16 + (klen * 8 - 256) / 128, "round count");
                    var buf = (byte[])pt.Clone();
                    c.EncryptBlock(buf, buf);
                    c.DecryptBlock(buf, buf);
                    Check(buf.AsSpan().SequenceEqual(pt), $"round trip key {klen * 8}, block {blen * 8}");
                }
    }

    static void InvalidParameters()
    {
        foreach (int klen in new[] { 0, 16, 31, 40, 144 })
            Check(Throws(() => new QalqanCipher(new byte[klen], 16)), $"{klen}-byte key accepted");
        foreach (int blen in new[] { 0, 8, 24, 48, 128 })
            Check(Throws(() => new QalqanCipher(new byte[32], blen)), $"{blen}-byte block accepted");
        using var c = new QalqanCipher(new byte[32], 16);
        Check(Throws(() => Modes.CbcEncrypt(c, new byte[15], new byte[16], new byte[16])), "short IV accepted");
        Check(Throws(() => Modes.EcbEncrypt(c, new byte[17], new byte[17])), "partial ECB block accepted");
    }

    static void Padding()
    {
        foreach (int bs in new[] { 16, 32, 64 })
        {
            for (int n = 0; n <= 2 * bs; n++)
            {
                var data = Enumerable.Repeat((byte)0x80, n).ToArray();
                var p = Modes.PadMethod2(data, bs);
                var u = Modes.UnpadMethod2(p, bs);
                Check(p.Length % bs == 0 && u != null && u.AsSpan().SequenceEqual(data), $"padding n={n}");
            }
            Check(Modes.UnpadMethod2(new byte[bs], bs) == null, "missing padding marker accepted");
        }
    }

    static bool Throws(Action a)
    {
        try { a(); return false; }
        catch (ArgumentException) { return true; }
    }
}
