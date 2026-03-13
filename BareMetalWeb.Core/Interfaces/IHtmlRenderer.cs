using System.IO.Pipelines;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Models;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Core.Interfaces;

public interface IHtmlRenderer
{
    // ValueTask RenderAsync(HttpResponse response, IHtmlTemplate template, string[] keys, string[] values,string[] appkeys, string[] appvalues);
    ValueTask<ReadOnlyMemory<byte>> RenderToBytesAsync(IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null);
    ValueTask RenderToStreamAsync(PipeWriter writer, IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null);
    ValueTask RenderPage(BmwContext context);
    ValueTask RenderPage(BmwContext context, PageInfo page, IBareWebHost app);
}
