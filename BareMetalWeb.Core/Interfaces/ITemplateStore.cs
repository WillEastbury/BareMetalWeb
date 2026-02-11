using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Core.Interfaces;

public interface ITemplateStore
{
    IHtmlTemplate Get(string name);
    void ReloadAll();
}
