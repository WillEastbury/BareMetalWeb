using System.Buffers;

namespace BareMetalWeb.Interfaces;

public interface IHtmlFragmentStore
{
    string ReturnTemplateFragment(string templateKey);
    string ZeroAllocationReplaceCopy(string template, string[] keys, string[] values);
    byte[] ZeroAllocationReplaceCopyAndEncode(string template, string[] keys, string[] values);
    void ZeroAllocationReplaceCopyAndWrite(string template, IBufferWriter<byte> writer, string[] keys, string[] values);
}
