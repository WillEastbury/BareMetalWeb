using System.IO.Pipelines;
using System.Threading.Tasks;
using BareMetalWeb.Rendering;
using BareMetalWeb.WebServer;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Interfaces;

public interface IHtmlRenderer
{
    // ValueTask RenderAsync(HttpResponse response, IHtmlTemplate template, string[] keys, string[] values,string[] appkeys, string[] appvalues);
    ValueTask<byte[]> RenderToBytesAsync(IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, BareMetalWebServer app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null);
    ValueTask RenderToStreamAsync(PipeWriter writer, IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, BareMetalWebServer app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null);
    ValueTask RenderPage(HttpContext context);
    ValueTask RenderPage(HttpContext context, PageInfo page, BareMetalWebServer app);
}
