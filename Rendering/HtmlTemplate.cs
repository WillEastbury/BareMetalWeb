using System.Text;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Rendering;

public class HtmlTemplate : IHtmlTemplate
{
    public Encoding encoding = Encoding.UTF8;
    public string Head {get;set;}
    public string Body {get;set;}
    public string Footer {get;set;}
    public string Script {get;set;}

    public HtmlTemplate(
        string head,
        string body,
        string footer,
        string script)
    {
        Head = head;
        Body = body;
        Footer = footer;
        Script = script;
    }

    private Encoding _encoding = Encoding.UTF8;

    public Encoding Encoding => _encoding;
    public string ContentTypeHeader => $"text/html; charset={_encoding.WebName}";
}
public class HtmlFragment : IHtmlFragment
{
    public string Content {get;set;}

    public HtmlFragment(string content)
    {
        Content = content;
    }
}