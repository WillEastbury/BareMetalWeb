using System.IO;
using System.IO.Pipelines;
using System.Text;
using BareMetalWeb.Rendering;
using Xunit;

namespace BareMetalWeb.Rendering.Tests;

public class SimdCopyTests
{
    [Fact]
    public void CopyFragment_SmallFragment_CopiesCorrectly()
    {
        byte[] src = "Hello"u8.ToArray();
        byte[] dst = new byte[src.Length];
        SimdCopy.CopyFragment(src, dst);
        Assert.Equal(src, dst);
    }

    [Fact]
    public void CopyFragment_EmptyFragment_Succeeds()
    {
        SimdCopy.CopyFragment(ReadOnlySpan<byte>.Empty, Span<byte>.Empty);
    }

    [Fact]
    public void CopyFragment_Exactly16Bytes_UsesVectorPath()
    {
        byte[] src = "0123456789ABCDEF"u8.ToArray();
        byte[] dst = new byte[16];
        SimdCopy.CopyFragment(src, dst);
        Assert.Equal(src, dst);
    }

    [Fact]
    public void CopyFragment_32Bytes_TwoVectorIterations()
    {
        byte[] src = "0123456789ABCDEF0123456789ABCDEF"u8.ToArray();
        byte[] dst = new byte[32];
        SimdCopy.CopyFragment(src, dst);
        Assert.Equal(src, dst);
    }

    [Fact]
    public void CopyFragment_WithTailBytes_CopiesAll()
    {
        // 20 bytes = 1 vector (16) + 4 tail bytes
        byte[] src = Encoding.UTF8.GetBytes("01234567890123456789");
        byte[] dst = new byte[20];
        SimdCopy.CopyFragment(src, dst);
        Assert.Equal(src, dst);
    }

    [Fact]
    public void CopyFragment_LargeFragment_256Bytes()
    {
        byte[] src = new byte[256];
        for (int i = 0; i < 256; i++) src[i] = (byte)(i & 0xFF);
        byte[] dst = new byte[256];
        SimdCopy.CopyFragment(src, dst);
        Assert.Equal(src, dst);
    }

    [Fact]
    public void CopyFragment_1ByteFragment_FallbackPath()
    {
        byte[] src = { 0x42 };
        byte[] dst = new byte[1];
        SimdCopy.CopyFragment(src, dst);
        Assert.Equal(0x42, dst[0]);
    }

    [Fact]
    public void CopyFragment_15ByteFragment_FallbackPath()
    {
        byte[] src = "fifteen_bytes!!"u8.ToArray();
        Assert.Equal(15, src.Length);
        byte[] dst = new byte[15];
        SimdCopy.CopyFragment(src, dst);
        Assert.Equal(src, dst);
    }

    [Fact]
    public void CopyFragment_17Bytes_OneVectorPlusTail()
    {
        byte[] src = Encoding.UTF8.GetBytes("01234567890123456");
        Assert.Equal(17, src.Length);
        byte[] dst = new byte[17];
        SimdCopy.CopyFragment(src, dst);
        Assert.Equal(src, dst);
    }

    [Fact]
    public void CopyFragment_HtmlFragment_TypicalSize()
    {
        // Typical HTML fragment: 40-80 bytes
        byte[] src = Encoding.UTF8.GetBytes("<div class=\"container-fluid p-3\"><h2>");
        byte[] dst = new byte[src.Length];
        SimdCopy.CopyFragment(src, dst);
        Assert.Equal(src, dst);
    }

    [Fact]
    public void CopyFragment_IntegratedWithPipeWriter_ProducesCorrectOutput()
    {
        // Verify SIMD copy works end-to-end with TemplatePlanExecutor
        var plan = TemplatePlanCompiler.Compile(
            "<div class=\"container\">{{title}}</div>");

        var ms = new MemoryStream();
        var writer = PipeWriter.Create(ms);
        TemplatePlanExecutor.Execute(writer, plan,
            new[] { "title" }, new[] { "Hello" },
            Array.Empty<string>(), Array.Empty<string>());
        writer.Complete();

        var output = Encoding.UTF8.GetString(ms.ToArray());
        Assert.Equal("<div class=\"container\">Hello</div>", output);
    }
}
