using System.Collections.Generic;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Rendering.Models;
namespace BareMetalWeb.Rendering.Interfaces;

public interface IHtmlFragmentRenderer
{
    byte[] RenderMenuOptions(List<IMenuOption> options, bool rightAligned);
    byte[] RenderTable(string[] columnTitles, string[][] rows);
    byte[] RenderForm(FormDefinition definition);
    byte[] DocTypeAndHeadStart { get; }
    byte[] HeadEndAndBodyStart { get; }
    byte[] BodyEndAndHtmlEnd { get; }
    byte[] ScriptTagStart { get; }
    byte[] ScriptTagEnd { get; }
}
