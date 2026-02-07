using System.Text;

namespace BareMetalWeb.Interfaces;

public interface IHtmlTemplate
{
    Encoding Encoding { get; }
    string ContentTypeHeader { get; }
    string Head { get; }
    string Body { get; }
    string Footer { get; }
    string Script { get; }
    
}
public interface IHtmlFragment
{
    string Content { get; }
}