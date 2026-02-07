using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Interfaces;

public interface ITemplateStore
{
    IHtmlTemplate Get(string name);
    void ReloadAll();
}
