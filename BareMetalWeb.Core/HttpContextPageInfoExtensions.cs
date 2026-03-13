using System;
using System.Collections.Generic;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Models;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

public static class HttpContextPageInfoExtensions
{
    private const string PageMetaDataKey = "BareMetalWeb.PageMetaData";
    private const string PageContextKey = "BareMetalWeb.PageContext";
    private const string AppKey = "BareMetalWeb.App";

    public static void SetPageMetaData(this HttpContext context, PageMetaData metaData)
    {
        context.Items[PageMetaDataKey] = metaData;
    }

    public static void SetPageContext(this HttpContext context, PageContext pageContext)
    {
        context.Items[PageContextKey] = pageContext;
    }

    public static void SetPageInfo(this HttpContext context, PageInfo pageInfo)
    {
        context.SetPageMetaData(pageInfo.PageMetaData);
        context.SetPageContext(pageInfo.PageContext);
    }

    public static PageMetaData? GetPageMetaData(this HttpContext context)
    {
        return context.Items.TryGetValue(PageMetaDataKey, out var value) ? value as PageMetaData : null;
    }

    public static PageContext? GetPageContext(this HttpContext context)
    {
        return context.Items.TryGetValue(PageContextKey, out var value) ? value as PageContext : null;
    }

    public static PageInfo? GetPageInfo(this HttpContext context)
    {
        var meta = context.GetPageMetaData();
        var pageContext = context.GetPageContext();
        return meta != null && pageContext != null ? new PageInfo(meta, pageContext) : null;
    }

    public static void SetApp(this HttpContext context, IBareWebHost app)
    {
        context.Items[AppKey] = app;
    }

    public static IBareWebHost? GetApp(this HttpContext context)
    {
        return context.Items.TryGetValue(AppKey, out var value) ? value as IBareWebHost : null;
    }

    public static void SetStringValue(this HttpContext context, string key, string value)
    {
        var current = EnsurePageContext(context);
        var keys = new List<string>(current.PageMetaDataKeys);
        var values = new List<string>(current.PageMetaDataValues);

        int index = -1;
        for (int i = 0; i < keys.Count; i++)
        {
            if (string.Equals(keys[i], key, StringComparison.Ordinal))
            {
                index = i;
                break;
            }
        }
        if (index >= 0)
        {
            values[index] = value;
        }
        else
        {
            keys.Add(key);
            values.Add(value);
        }

        context.SetPageContext(current with
        {
            PageMetaDataKeys = keys.ToArray(),
            PageMetaDataValues = values.ToArray()
        });
    }

    public static void AddStringValue(this HttpContext context, string key, string value)
    {
        var current = EnsurePageContext(context);
        var keys = new List<string>(current.PageMetaDataKeys);
        var values = new List<string>(current.PageMetaDataValues);

        keys.Add(key);
        values.Add(value);

        context.SetPageContext(current with
        {
            PageMetaDataKeys = keys.ToArray(),
            PageMetaDataValues = values.ToArray()
        });
    }

    public static void RemoveStringValue(this HttpContext context, string key)
    {
        var current = EnsurePageContext(context);
        var keys = new List<string>();
        var values = new List<string>();

        for (int i = 0; i < current.PageMetaDataKeys.Length; i++)
        {
            if (string.Equals(current.PageMetaDataKeys[i], key, StringComparison.Ordinal))
                continue;
            keys.Add(current.PageMetaDataKeys[i]);
            values.Add(current.PageMetaDataValues[i]);
        }

        context.SetPageContext(current with
        {
            PageMetaDataKeys = keys.ToArray(),
            PageMetaDataValues = values.ToArray()
        });
    }

    public static void SetLoop(this HttpContext context, TemplateLoop loop)
    {
        var current = EnsurePageContext(context);
        var loops = current.TemplateLoops != null ? new List<TemplateLoop>(current.TemplateLoops) : new List<TemplateLoop>();

        int index = -1;
        for (int i = 0; i < loops.Count; i++)
        {
            if (string.Equals(loops[i].Key, loop.Key, StringComparison.Ordinal))
            {
                index = i;
                break;
            }
        }
        if (index >= 0)
        {
            loops[index] = loop;
        }
        else
        {
            loops.Add(loop);
        }

        context.SetPageContext(current with
        {
            TemplateLoops = loops.ToArray()
        });
    }

    public static void SetLoop(this HttpContext context, string loopKey, IReadOnlyList<IReadOnlyDictionary<string, string>> items)
        => context.SetLoop(new TemplateLoop(loopKey, items));

    public static void SetLoopValues(this HttpContext context, string loopKey, string valueKey, IReadOnlyList<string> values)
    {
        var items = new List<IReadOnlyDictionary<string, string>>(values.Count);
        for (int i = 0; i < values.Count; i++)
        {
            items.Add(new Dictionary<string, string> { [valueKey] = values[i] });
        }

        context.SetLoop(loopKey, items);
    }

    public static void AddLoopItem(this HttpContext context, string loopKey, IReadOnlyDictionary<string, string> item)
    {
        var current = EnsurePageContext(context);
        var loops = current.TemplateLoops != null ? new List<TemplateLoop>(current.TemplateLoops) : new List<TemplateLoop>();

        int index = -1;
        for (int i = 0; i < loops.Count; i++)
        {
            if (string.Equals(loops[i].Key, loopKey, StringComparison.Ordinal))
            {
                index = i;
                break;
            }
        }
        if (index >= 0)
        {
            var items = new List<IReadOnlyDictionary<string, string>>(loops[index].Items);
            items.Add(item);
            loops[index] = loops[index] with { Items = items };
        }
        else
        {
            loops.Add(new TemplateLoop(loopKey, new[] { item }));
        }

        context.SetPageContext(current with
        {
            TemplateLoops = loops.ToArray()
        });
    }

    public static void AddTable(this HttpContext context, string[] columnTitles, string[][] rows)
    {
        var current = EnsurePageContext(context);
        context.SetPageContext(current with
        {
            TableColumnTitles = columnTitles,
            TableData = rows
        });
    }

    public static void AddTableColumnTitle(this HttpContext context, string title)
    {
        var current = EnsurePageContext(context);
        var titles = current.TableColumnTitles != null ? new List<string>(current.TableColumnTitles) : new List<string>();
        titles.Add(title);

        context.SetPageContext(current with
        {
            TableColumnTitles = titles.ToArray()
        });
    }

    public static void AddTableHeader(this HttpContext context, string[] titles)
    {
        var current = EnsurePageContext(context);
        context.SetPageContext(current with
        {
            TableColumnTitles = titles
        });
    }

    public static void AddTableRow(this HttpContext context, string[] row)
    {
        var current = EnsurePageContext(context);
        var rows = current.TableData != null ? new List<string[]>(current.TableData) : new List<string[]>();
        rows.Add(row);

        context.SetPageContext(current with
        {
            TableData = rows.ToArray()
        });
    }

    public static void AddFormDefinition(this HttpContext context, FormDefinition formDefinition)
    {
        var current = EnsurePageContext(context);
        context.SetPageContext(current with
        {
            FormDefinition = formDefinition
        });
    }

    // ── BmwContext overloads (operate on BmwContext fields directly) ────

    public static void SetPageMetaData(this BmwContext context, PageMetaData metaData)
        => context.PageMetaData = metaData;

    public static void SetPageContext(this BmwContext context, PageContext pageContext)
        => context.PageContext = pageContext;

    public static void SetPageInfo(this BmwContext context, PageInfo pageInfo)
    {
        context.PageMetaData = pageInfo.PageMetaData;
        context.PageContext = pageInfo.PageContext;
    }

    public static PageMetaData? GetPageMetaData(this BmwContext context)
        => context.PageMetaData;

    public static PageContext? GetPageContext(this BmwContext context)
        => context.PageContext;

    public static PageInfo? GetPageInfo(this BmwContext context)
        => context.PageInfo;

    public static void SetApp(this BmwContext context, IBareWebHost app)
    {
        // App is set during BmwContext construction — this is a no-op compatibility shim.
    }

    public static IBareWebHost? GetApp(this BmwContext context)
        => context.App;

    public static void SetStringValue(this BmwContext context, string key, string value)
    {
        var current = EnsureBmwPageContext(context);
        var keys = new List<string>(current.PageMetaDataKeys);
        var values = new List<string>(current.PageMetaDataValues);

        int index = -1;
        for (int i = 0; i < keys.Count; i++)
        {
            if (string.Equals(keys[i], key, StringComparison.Ordinal))
            {
                index = i;
                break;
            }
        }
        if (index >= 0)
        {
            values[index] = value;
        }
        else
        {
            keys.Add(key);
            values.Add(value);
        }

        context.PageContext = current with
        {
            PageMetaDataKeys = keys.ToArray(),
            PageMetaDataValues = values.ToArray()
        };
    }

    public static void AddStringValue(this BmwContext context, string key, string value)
    {
        var current = EnsureBmwPageContext(context);
        var keys = new List<string>(current.PageMetaDataKeys);
        var values = new List<string>(current.PageMetaDataValues);

        keys.Add(key);
        values.Add(value);

        context.PageContext = current with
        {
            PageMetaDataKeys = keys.ToArray(),
            PageMetaDataValues = values.ToArray()
        };
    }

    public static void RemoveStringValue(this BmwContext context, string key)
    {
        var current = EnsureBmwPageContext(context);
        var keys = new List<string>();
        var values = new List<string>();

        for (int i = 0; i < current.PageMetaDataKeys.Length; i++)
        {
            if (string.Equals(current.PageMetaDataKeys[i], key, StringComparison.Ordinal))
                continue;
            keys.Add(current.PageMetaDataKeys[i]);
            values.Add(current.PageMetaDataValues[i]);
        }

        context.PageContext = current with
        {
            PageMetaDataKeys = keys.ToArray(),
            PageMetaDataValues = values.ToArray()
        };
    }

    public static void SetLoop(this BmwContext context, TemplateLoop loop)
    {
        var current = EnsureBmwPageContext(context);
        var loops = current.TemplateLoops != null ? new List<TemplateLoop>(current.TemplateLoops) : new List<TemplateLoop>();

        int index = -1;
        for (int i = 0; i < loops.Count; i++)
        {
            if (string.Equals(loops[i].Key, loop.Key, StringComparison.Ordinal))
            {
                index = i;
                break;
            }
        }
        if (index >= 0)
            loops[index] = loop;
        else
            loops.Add(loop);

        context.PageContext = current with { TemplateLoops = loops.ToArray() };
    }

    public static void SetLoop(this BmwContext context, string loopKey, IReadOnlyList<IReadOnlyDictionary<string, string>> items)
        => context.SetLoop(new TemplateLoop(loopKey, items));

    public static void SetLoopValues(this BmwContext context, string loopKey, string valueKey, IReadOnlyList<string> values)
    {
        var items = new List<IReadOnlyDictionary<string, string>>(values.Count);
        for (int i = 0; i < values.Count; i++)
            items.Add(new Dictionary<string, string> { [valueKey] = values[i] });
        context.SetLoop(loopKey, items);
    }

    public static void AddLoopItem(this BmwContext context, string loopKey, IReadOnlyDictionary<string, string> item)
    {
        var current = EnsureBmwPageContext(context);
        var loops = current.TemplateLoops != null ? new List<TemplateLoop>(current.TemplateLoops) : new List<TemplateLoop>();

        int index = -1;
        for (int i = 0; i < loops.Count; i++)
        {
            if (string.Equals(loops[i].Key, loopKey, StringComparison.Ordinal))
            {
                index = i;
                break;
            }
        }
        if (index >= 0)
        {
            var items = new List<IReadOnlyDictionary<string, string>>(loops[index].Items);
            items.Add(item);
            loops[index] = loops[index] with { Items = items };
        }
        else
        {
            loops.Add(new TemplateLoop(loopKey, new[] { item }));
        }

        context.PageContext = current with { TemplateLoops = loops.ToArray() };
    }

    public static void AddTable(this BmwContext context, string[] columnTitles, string[][] rows)
    {
        var current = EnsureBmwPageContext(context);
        context.PageContext = current with
        {
            TableColumnTitles = columnTitles,
            TableData = rows
        };
    }

    public static void AddTableColumnTitle(this BmwContext context, string title)
    {
        var current = EnsureBmwPageContext(context);
        var titles = current.TableColumnTitles != null ? new List<string>(current.TableColumnTitles) : new List<string>();
        titles.Add(title);
        context.PageContext = current with { TableColumnTitles = titles.ToArray() };
    }

    public static void AddTableHeader(this BmwContext context, string[] titles)
    {
        var current = EnsureBmwPageContext(context);
        context.PageContext = current with { TableColumnTitles = titles };
    }

    public static void AddTableRow(this BmwContext context, string[] row)
    {
        var current = EnsureBmwPageContext(context);
        var rows = current.TableData != null ? new List<string[]>(current.TableData) : new List<string[]>();
        rows.Add(row);
        context.PageContext = current with { TableData = rows.ToArray() };
    }

    public static void AddFormDefinition(this BmwContext context, FormDefinition formDefinition)
    {
        var current = EnsureBmwPageContext(context);
        context.PageContext = current with { FormDefinition = formDefinition };
    }

    private static PageContext EnsureBmwPageContext(BmwContext context)
    {
        var pageContext = context.PageContext;
        if (pageContext != null)
            return pageContext;

        var nonce = context.GetCspNonce();
        var newContext = new PageContext(
            new[] { "csp_nonce" },
            new[] { nonce }
        );
        context.PageContext = newContext;
        return newContext;
    }

    private static PageContext EnsurePageContext(HttpContext context)
    {
        var pageContext = context.GetPageContext();
        if (pageContext != null)
            return pageContext;

        // Get or generate CSP nonce
        var nonce = context.GetCspNonce();
        
        // Create new context with nonce pre-populated
        var newContext = new PageContext(
            new[] { "csp_nonce" }, 
            new[] { nonce }
        );
        context.SetPageContext(newContext);
        
        return newContext;
    }
}
