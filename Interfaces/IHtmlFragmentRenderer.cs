using System.Collections.Generic;
using BareMetalWeb.Rendering;

namespace BareMetalWeb.Interfaces;

public interface IHtmlFragmentRenderer
{
    byte[] RenderMenuOptions(List<MenuOption> options, bool rightAligned);
    byte[] RenderTable(string[] columnTitles, string[][] rows);
    byte[] RenderForm(FormDefinition definition);
    byte[] DocTypeAndHeadStart { get; }
    byte[] HeadEndAndBodyStart { get; }
    byte[] BodyEndAndHtmlEnd { get; }
    byte[] ScriptTagStart { get; }
    byte[] ScriptTagEnd { get; }
}
