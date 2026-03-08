using System.IO.Pipelines;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Core;
using Microsoft.AspNetCore.Http;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering.Models;
using BareMetalWeb.Rendering;

namespace BareMetalWeb.Core.Interfaces;

public interface IHtmlRenderer
{
    // ValueTask RenderAsync(HttpResponse response, IHtmlTemplate template, string[] keys, string[] values,string[] appkeys, string[] appvalues);
    ValueTask<ReadOnlyMemory<byte>> RenderToBytesAsync(IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null);
    ValueTask RenderToStreamAsync(PipeWriter writer, IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null);
    ValueTask RenderPage(BmwContext context);
    ValueTask RenderPage(BmwContext context, PageInfo page, IBareWebHost app);
}
