using System;
using System.Buffers;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Net;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering.Models;
using BareMetalWeb.Rendering.Interfaces;
// Contains standardised static HTML fragments used across the application for templating
namespace BareMetalWeb.Rendering;

public sealed class HtmlFragmentRenderer : IHtmlFragmentRenderer
{
    private readonly IHtmlFragmentStore _fragmentStore;

    public byte[] DocTypeAndHeadStart { get; }
    public byte[] HeadEndAndBodyStart { get; }
    public byte[] BodyEndAndHtmlEnd { get; }
    public byte[] ScriptTagStart { get; }
    public byte[] ScriptTagEnd { get; }

    private readonly byte[] TableStart;
    private readonly byte[] TableHeadStart;
    private readonly byte[] TableHeadEnd;
    private readonly byte[] TableBodyStart;
    private readonly byte[] TableRowStart;
    private readonly byte[] TableRowEnd;
    private readonly byte[] TableBodyEnd;
    private readonly byte[] TableEnd;
    private readonly byte[] FormStart;
    private readonly byte[] FormEnd;
    private readonly byte[] FormGroupStart;
    private readonly byte[] FormGroupEnd;
    private readonly byte[] MoneyGroupStart;
    private readonly byte[] MoneyGroupMid;
    private readonly byte[] MoneyGroupEnd;
    private readonly byte[] LookupGroupStart;
    private readonly byte[] LookupGroupEnd;
    private readonly byte[] InputPassword;
    private readonly byte[] InputTextArea;
    private readonly byte[] InputFile;
    private readonly byte[] Button;
    private readonly byte[] InputCheckbox;
    private readonly byte[] FormLink;
    private readonly byte[] InputHidden;

    public HtmlFragmentRenderer(IHtmlFragmentStore fragmentStore)
    {
        _fragmentStore = fragmentStore;
        DocTypeAndHeadStart = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("DocTypeAndHeadStart"));
        HeadEndAndBodyStart = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("HeadEndAndBodyStart"));
        BodyEndAndHtmlEnd = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("BodyEndAndHtmlEnd"));
        ScriptTagStart = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("ScriptTagStart"));
        ScriptTagEnd = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("ScriptTagEnd"));
        TableStart = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("TableStart"));
        TableHeadStart = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("TableHeadStart"));
        TableHeadEnd = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("TableHeadEnd"));
        TableBodyStart = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("TableBodyStart"));
        TableRowStart = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("TableRowStart"));
        TableRowEnd = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("TableRowEnd"));
        TableBodyEnd = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("TableBodyEnd"));
        TableEnd = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("TableEnd"));
        FormStart = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("FormStart"));
        FormEnd = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("FormEnd"));
        FormGroupStart = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("FormGroupStart"));
        FormGroupEnd = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("FormGroupEnd"));
        MoneyGroupStart = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("MoneyGroupStart"));
        MoneyGroupMid = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("MoneyGroupMid"));
        MoneyGroupEnd = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("MoneyGroupEnd"));
        LookupGroupStart = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("LookupGroupStart"));
        LookupGroupEnd = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("LookupGroupEnd"));
        InputPassword = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("InputPassword"));
        InputTextArea = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("InputTextArea"));
        InputFile = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("InputFile"));
        Button = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("Button"));
        InputCheckbox = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("InputCheckbox"));
        FormLink = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("FormLink"));
        InputHidden = Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("InputHidden"));
    }

    private byte[] MenuOptionTemplate(string href, string label, string cssClass) {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("MenuOption"),
                new[] { "{{href}}", "{{label}}", "{{class}}" },
                new[] { href, label, cssClass }
            );
    }
    private byte[] TableHeadCellTemplate(string value)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("TableHeadCell"),
                new[] { "{{value}}" },
                new[] { value }
            );
    }
    private byte[] TableCellTemplate(string value, string label)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("TableCell"),
                new[] { "{{value}}", "{{label}}" },
                new[] { value, label }
            );
    }
    private byte[] FormLabelTemplate(string id, string label)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("FormLabel"),
                new[] { "{{id}}", "{{label}}" },
                new[] { id, label }
            );
    }
    private byte[] InputTextTemplate(string id, string name, string value, string placeholder, string required,
        string minlength = "", string maxlength = "", string pattern = "", string invalidClass = "", string validationFeedback = "")
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputText"),
                new[] { "{{id}}", "{{name}}", "{{value}}", "{{placeholder}}", "{{required}}", "{{minlength}}", "{{maxlength}}", "{{pattern}}", "{{invalidClass}}", "{{validationFeedback}}" },
                new[] { id, name, value, placeholder, required, minlength, maxlength, pattern, invalidClass, validationFeedback }
            );
    }
    private byte[] InputReadOnlyTemplate(string id, string name, string value, string placeholder)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputReadOnly"),
                new[] { "{{id}}", "{{name}}", "{{value}}", "{{placeholder}}" },
                new[] { id, name, value, placeholder }
            );
    }
    private byte[] InputComputedTemplate(string id, string name, string value, string placeholder, string strategy)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputComputed"),
                new[] { "{{id}}", "{{name}}", "{{value}}", "{{placeholder}}", "{{strategy}}" },
                new[] { id, name, value, placeholder, strategy }
            );
    }

    private byte[] InputCalculatedTemplate(string id, string name, string value, string placeholder, string expression, string rawExpression, string format)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputCalculated"),
                new[] { "{{id}}", "{{name}}", "{{value}}", "{{placeholder}}", "{{expression}}", "{{rawexpression}}", "{{format}}" },
                new[] { id, name, value, placeholder, WebUtility.HtmlEncode(expression), WebUtility.HtmlEncode(rawExpression), format }
            );
    }
    private byte[] InputTextAreaTemplate(string id, string name, string value, string placeholder, string required,
        string minlength = "", string maxlength = "", string invalidClass = "", string validationFeedback = "")
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputTextArea"),
                new[] { "{{id}}", "{{name}}", "{{value}}", "{{placeholder}}", "{{required}}", "{{minlength}}", "{{maxlength}}", "{{invalidClass}}", "{{validationFeedback}}" },
                new[] { id, name, value, placeholder, required, minlength, maxlength, invalidClass, validationFeedback }
            );
    }
    private byte[] InputFileTemplate(string id, string name, string required, string accept, string maxFileSizeBytes, string existingFileName, string existingFileUrl)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputFile"),
                new[] { "{{id}}", "{{name}}", "{{required}}", "{{accept}}", "{{maxFileSizeBytes}}", "{{existingFileName}}", "{{existingFileUrl}}" },
                new[] { id, name, required, accept, maxFileSizeBytes, existingFileName, existingFileUrl }
            );
    }
    private byte[] InputDateTemplate(string id, string name, string value, string placeholder, string required)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputDate"),
                new[] { "{{id}}", "{{name}}", "{{value}}", "{{placeholder}}", "{{required}}" },
                new[] { id, name, value, placeholder, required }
            );
    }
    private byte[] InputTimeTemplate(string id, string name, string value, string placeholder, string required)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputTime"),
                new[] { "{{id}}", "{{name}}", "{{value}}", "{{placeholder}}", "{{required}}" },
                new[] { id, name, value, placeholder, required }
            );
    }
    private byte[] InputDateTimeTemplate(string id, string name, string value, string placeholder, string required)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputDateTime"),
                new[] { "{{id}}", "{{name}}", "{{value}}", "{{placeholder}}", "{{required}}" },
                new[] { id, name, value, placeholder, required }
            );
    }
    private byte[] InputNumberTemplate(string id, string name, string value, string placeholder, string required,
        string min = "", string max = "", string invalidClass = "", string validationFeedback = "")
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputNumber"),
                new[] { "{{id}}", "{{name}}", "{{value}}", "{{placeholder}}", "{{required}}", "{{min}}", "{{max}}", "{{invalidClass}}", "{{validationFeedback}}" },
                new[] { id, name, value, placeholder, required, min, max, invalidClass, validationFeedback }
            );
    }
    private byte[] InputOtpTemplate(string id, string name, string value, string placeholder, string required)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputOtp"),
                new[] { "{{id}}", "{{name}}", "{{value}}", "{{placeholder}}", "{{required}}" },
                new[] { id, name, value, placeholder, required }
            );
    }
    private byte[] InputDecimalTemplate(string id, string name, string value, string placeholder, string step, string required,
        string min = "", string max = "", string invalidClass = "", string validationFeedback = "")
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputDecimal"),
                new[] { "{{id}}", "{{name}}", "{{value}}", "{{placeholder}}", "{{step}}", "{{required}}", "{{min}}", "{{max}}", "{{invalidClass}}", "{{validationFeedback}}" },
                new[] { id, name, value, placeholder, step, required, min, max, invalidClass, validationFeedback }
            );
    }
    private byte[] InputEmailTemplate(string id, string name, string value, string placeholder, string pattern, string required,
        string invalidClass = "", string validationFeedback = "")
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputEmail"),
                new[] { "{{id}}", "{{name}}", "{{value}}", "{{placeholder}}", "{{pattern}}", "{{required}}", "{{invalidClass}}", "{{validationFeedback}}" },
                new[] { id, name, value, placeholder, pattern, required, invalidClass, validationFeedback }
            );
    }
    private byte[] InputPasswordTemplate(string id, string name, string value, string placeholder, string required)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputPassword"),
                new[] { "{{id}}", "{{name}}", "{{value}}", "{{placeholder}}", "{{required}}" },
                new[] { id, name, value, placeholder, required }
            );
    }
    private byte[] ButtonTemplate(string id, string name, string type, string cssClass, string label)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("Button"),
                new[] { "{{id}}", "{{name}}", "{{type}}", "{{class}}", "{{label}}" },
                new[] { id, name, type, cssClass, label }
            );
    }
    private byte[] FormLinkTemplate(string href, string label, string target, string cssClass)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("FormLink"),
                new[] { "{{href}}", "{{label}}", "{{target}}", "{{class}}" },
                new[] { href, label, target, cssClass }
            );
    }
    private byte[] InputHiddenTemplate(string id, string name, string value)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputHidden"),
                new[] { "{{id}}", "{{name}}", "{{value}}" },
                new[] { id, name, value }
            );
    }
    private byte[] InputImageTemplate(string id, string name, string required, string accept, string maxFileSizeBytes, string existingFileUrl)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputImage"),
                new[] { "{{id}}", "{{name}}", "{{required}}", "{{accept}}", "{{maxFileSizeBytes}}", "{{existingFileUrl}}" },
                new[] { id, name, required, accept, maxFileSizeBytes, existingFileUrl }
            );
    }
    private byte[] InputYesNoTemplate(string id, string name, string label, string required, string checkedValue)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("InputCheckbox"),
                new[] { "{{id}}", "{{name}}", "{{label}}", "{{required}}", "{{checked}}" },
                new[] { id, name, label, required, checkedValue }
            );
    }
    private byte[] SelectStartTemplate(string id, string name, string required)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("SelectStart"),
                new[] { "{{id}}", "{{name}}", "{{required}}" },
                new[] { id, name, required }
            );
    }
    private byte[] SelectOptionTemplate(string value, string label, string selected)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("SelectOption"),
                new[] { "{{value}}", "{{label}}", "{{selected}}" },
                new[] { value, label, selected }
            );
    }
    private byte[] SelectEndTemplate()
    {
        return Encoding.UTF8.GetBytes(_fragmentStore.ReturnTemplateFragment("SelectEnd"));
    }
    
    private byte[] LookupRefreshButtonTemplate(string fieldName)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("LookupRefreshButton"),
                new[] { "{{fieldName}}" },
                new[] { fieldName }
            );
    }
    
    private byte[] LookupAddButtonTemplate(string targetSlug, string targetType, string fieldName)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("LookupAddButton"),
                new[] { "{{targetSlug}}", "{{targetType}}", "{{fieldName}}" },
                new[] { targetSlug, targetType, fieldName }
            );
    }

    private byte[] LookupSearchButtonTemplate(string targetSlug, string targetType, string fieldName, string displayField, string valueField)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("LookupSearchButton"),
                new[] { "{{targetSlug}}", "{{targetType}}", "{{fieldName}}", "{{displayField}}", "{{valueField}}" },
                new[] { targetSlug, targetType, fieldName, displayField, valueField }
            );
    }

    private byte[] LookupSearchDisplayTemplate(string fieldName, string displayValue)
    {
        return _fragmentStore
            .ZeroAllocationReplaceCopyAndEncode(
                _fragmentStore.ReturnTemplateFragment("LookupSearchDisplay"),
                new[] { "{{fieldName}}", "{{displayValue}}" },
                new[] { fieldName, displayValue }
            );
    }
    public byte[] RenderMenuOptions(List<IMenuOption> options, bool rightAligned)
    {
        var buffer = new ArrayBufferWriter<byte>();

        var visibleOptions = options.Where(o => o.RightAligned == rightAligned).ToList();
        var renderedGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var option in visibleOptions)
        {
            if (string.IsNullOrWhiteSpace(option.Group))
            {
                var cssClass = option.HighlightAsButton
                    ? $"btn {(string.IsNullOrWhiteSpace(option.ColorClass) ? "btn-outline-light" : option.ColorClass)} btn-sm ms-2"
                    : string.IsNullOrWhiteSpace(option.ColorClass) ? "nav-link" : $"nav-link {option.ColorClass}";
                byte[] rendered = MenuOptionTemplate(option.Href, option.Label, cssClass);
                buffer.Write(rendered);
                continue;
            }

            if (renderedGroups.Contains(option.Group))
                continue;

            renderedGroups.Add(option.Group);
            var groupItems = visibleOptions
                .Where(o => string.Equals(o.Group, option.Group, StringComparison.OrdinalIgnoreCase))
                .ToList();

            var groupLabel = WebUtility.HtmlEncode(option.Group);
            var menuAlignmentClass = rightAligned ? "dropdown-menu dropdown-menu-end" : "dropdown-menu";
            var dropdownHtml = $"<li class=\"nav-item dropdown\"><a class=\"nav-link dropdown-toggle\" href=\"#\" role=\"button\" data-bs-toggle=\"dropdown\" aria-expanded=\"false\">{groupLabel}</a><ul class=\"{menuAlignmentClass}\">";

            foreach (var item in groupItems)
            {
                var itemLabel = WebUtility.HtmlEncode(item.Label);
                var itemHref = WebUtility.HtmlEncode(item.Href);
                dropdownHtml += $"<li><a class=\"dropdown-item\" href=\"{itemHref}\">{itemLabel}</a></li>";
            }

            dropdownHtml += "</ul></li>";
            buffer.Write(Encoding.UTF8.GetBytes(dropdownHtml));
        }

        return buffer.WrittenSpan.ToArray(); // Final allocation here only
    }
    public byte[] RenderTable(string[] columnTitles, string[][] rows)
    {
        var buffer = new ArrayBufferWriter<byte>();

        Write(buffer, TableStart);
        Write(buffer, TableHeadStart);

        foreach (var column in columnTitles)
        {
            Write(buffer, TableHeadCellTemplate(column));
        }

        Write(buffer, TableHeadEnd);
        Write(buffer, TableBodyStart);

        foreach (var row in rows)
        {
            Write(buffer, TableRowStart);
            for (int i = 0; i < row.Length; i++)
            {
                var label = i < columnTitles.Length ? columnTitles[i] : string.Empty;
                Write(buffer, TableCellTemplate(row[i], label));
            }
            Write(buffer, TableRowEnd);
        }

        Write(buffer, TableBodyEnd);
        Write(buffer, TableEnd);

        return buffer.WrittenSpan.ToArray();
    }
    public byte[] RenderForm(FormDefinition definition)
    {
        var buffer = new ArrayBufferWriter<byte>();

        var needsMultipart = definition.Fields.Any(f => f.FieldType == FormFieldType.Image || f.FieldType == FormFieldType.File);
        _fragmentStore.ZeroAllocationReplaceCopyAndWrite(
            _fragmentStore.ReturnTemplateFragment("FormStart"),
            buffer,
            new[] { "{{method}}", "{{action}}", "{{enctype}}" },
            new[]
            {
                definition.Method,
                definition.Action,
                needsMultipart ? "multipart/form-data" : "application/x-www-form-urlencoded"
            });

        foreach (var field in definition.Fields)
        {
            if (field.FieldType == FormFieldType.Hidden)
            {
                Write(buffer, RenderField(field));
                continue;
            }

            Write(buffer, FormGroupStart);
            if (!string.IsNullOrWhiteSpace(field.Label) && field.FieldType != FormFieldType.YesNo)
            {
                Write(buffer, FormLabelTemplate(field.Name, field.Label));
            }
            Write(buffer, RenderField(field));
            Write(buffer, FormGroupEnd);
        }

        _fragmentStore.ZeroAllocationReplaceCopyAndWrite(
            _fragmentStore.ReturnTemplateFragment("FormEnd"),
            buffer,
            new[] { "{{submitLabel}}" },
            new[] { definition.SubmitLabel }
        );

        return buffer.WrittenSpan.ToArray();
    }

    private byte[] RenderField(FormField field)
    {
        var required = field.Required ? "required" : string.Empty;
        var placeholder = Encode(field.Placeholder);
        var value = Encode(field.Value);
        var selectedValue = field.SelectedValue ?? string.Empty;
        var name = Encode(field.Name);
        var label = Encode(field.Label);
        var emailPattern = Encode(field.EmailPattern ?? ".+@.+\\..+");

        // Validation HTML5 attributes
        var minlength = field.MinLength.HasValue ? $"minlength=\"{field.MinLength.Value}\"" : string.Empty;
        var maxlength = field.MaxLength.HasValue ? $"maxlength=\"{field.MaxLength.Value}\"" : string.Empty;
        var min = field.RangeMin.HasValue ? $"min=\"{field.RangeMin.Value}\"" : string.Empty;
        var max = field.RangeMax.HasValue ? $"max=\"{field.RangeMax.Value}\"" : string.Empty;
        var pattern = !string.IsNullOrEmpty(field.Pattern) ? $"pattern=\"{Encode(field.Pattern)}\"" : string.Empty;
        var invalidClass = !string.IsNullOrEmpty(field.ValidationError) ? "is-invalid" : string.Empty;
        var validationFeedback = !string.IsNullOrEmpty(field.ValidationError)
            ? $"<div class=\"invalid-feedback\">{Encode(field.ValidationError)}</div>"
            : string.Empty;

        switch (field.FieldType)
        {
            case FormFieldType.String:
                return InputTextTemplate(name, name, value, placeholder, required, minlength, maxlength, pattern, invalidClass, validationFeedback);
            case FormFieldType.CustomHtml:
                return Encoding.UTF8.GetBytes(field.Html ?? string.Empty);
            case FormFieldType.Enum:
                return RenderLookupSelect(field, required, selectedValue);
            case FormFieldType.DateOnly:
                return InputDateTemplate(name, name, value, placeholder, required);
            case FormFieldType.TimeOnly:
                return InputTimeTemplate(name, name, value, placeholder, required);
            case FormFieldType.DateTime:
                return InputDateTimeTemplate(name, name, value, placeholder, required);
            case FormFieldType.Integer:
                return InputNumberTemplate(name, name, value, placeholder, required, min, max, invalidClass, validationFeedback);
            case FormFieldType.Otp:
                return InputOtpTemplate(name, name, value, placeholder, required);
            case FormFieldType.Tags:
            case FormFieldType.TextArea:
                return InputTextAreaTemplate(name, name, value, placeholder, required, minlength, maxlength, invalidClass, validationFeedback);
            case FormFieldType.Decimal:
                return InputDecimalTemplate(name, name, value, placeholder, StepFromDp(field.DecimalPlaces), required, min, max, invalidClass, validationFeedback);
            case FormFieldType.Money:
                return RenderMoneyField(field, required);
            case FormFieldType.Image:
                return InputImageTemplate(
                    name,
                    name,
                    required,
                    Encode(field.Accept ?? "image/*"),
                    field.MaxFileSizeBytes?.ToString() ?? string.Empty,
                    Encode(field.ExistingFileUrl));
            case FormFieldType.File:
                return InputFileTemplate(
                    name,
                    name,
                    required,
                    Encode(field.Accept ?? string.Empty),
                    field.MaxFileSizeBytes?.ToString() ?? string.Empty,
                    Encode(field.ExistingFileName),
                    Encode(field.ExistingFileUrl));
            case FormFieldType.Password:
                return InputPasswordTemplate(name, name, value, placeholder, required);
            case FormFieldType.Email:
                return InputEmailTemplate(name, name, value, placeholder, emailPattern, required, invalidClass, validationFeedback);
            case FormFieldType.Country:
                return RenderCountrySelect(field, required, selectedValue);
            case FormFieldType.YesNo:
                return InputYesNoTemplate(name, name, label, required, selectedValue == "true" ? "checked" : string.Empty);
            case FormFieldType.LookupList:
                return RenderLookupSelect(field, required, selectedValue);
            case FormFieldType.Button:
                return ButtonTemplate(
                    name,
                    name,
                    field.ButtonType ?? "button",
                    field.ButtonStyle ?? "btn-secondary",
                    Encode(field.ButtonText ?? field.Label));
            case FormFieldType.Link:
                return FormLinkTemplate(
                    Encode(field.LinkUrl ?? "#"),
                    Encode(field.LinkText ?? field.Label),
                    Encode(field.LinkTarget ?? "_self"),
                    Encode(field.LinkClass ?? "link-primary"));
            case FormFieldType.Hidden:
                return InputHiddenTemplate(name, name, value);
            case FormFieldType.ReadOnly:
                // Check if this is a calculated field and render with expression
                if (field.IsCalculated && !string.IsNullOrEmpty(field.CalculatedExpression))
                {
                    // The CalculatedExpression from FormField is already the JavaScript expression
                    var jsExpression = field.CalculatedExpression;
                    var format = field.DisplayFormat ?? string.Empty;
                    // Also pass raw expression for tooltip (we'll use the same for now)
                    return InputCalculatedTemplate(name, name, value, placeholder, jsExpression, jsExpression, format);
                }
                // Check if this is a computed field and render with indicator
                if (field.IsComputed && !string.IsNullOrEmpty(field.ComputedStrategy))
                {
                    return InputComputedTemplate(name, name, value, placeholder, field.ComputedStrategy);
                }
                return InputReadOnlyTemplate(name, name, value, placeholder);
            default:
                return InputTextTemplate(name, name, value, placeholder, required);
        }
    }

    private byte[] RenderMoneyField(FormField field, string required)
    {
        var buffer = new ArrayBufferWriter<byte>();
        Write(buffer, MoneyGroupStart);
        var amountValue = Encode(field.Value);
        var amountPlaceholder = Encode(field.Placeholder);
        var amountId = Encode(field.Name + "_amount");
        var amountName = Encode(field.Name);
        Write(buffer, InputDecimalTemplate(amountId, amountName, amountValue, amountPlaceholder, StepFromDp(field.DecimalPlaces), required));
        Write(buffer, MoneyGroupMid);

        var currencyOptions = field.CurrencyOptions ?? FormOptions.GetCurrencyOptions();
        var currencyName = Encode(field.Name + "_currency");
        Write(buffer, SelectStartTemplate(currencyName, currencyName, required));
        foreach (var currency in currencyOptions)
        {
            var selected = string.Equals(currency, field.SelectedValue, StringComparison.OrdinalIgnoreCase) ? "selected" : string.Empty;
            Write(buffer, SelectOptionTemplate(Encode(currency), Encode(currency), selected));
        }
        Write(buffer, SelectEndTemplate());
        Write(buffer, MoneyGroupEnd);
        return buffer.WrittenSpan.ToArray();
    }

    private byte[] RenderCountrySelect(FormField field, string required, string selectedValue)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var options = field.CountryOptions ?? FormOptions.GetCountryOptions();
        var name = Encode(field.Name);
        Write(buffer, SelectStartTemplate(name, name, required));
        foreach (var option in options)
        {
            var selected = string.Equals(option.Key, selectedValue, StringComparison.OrdinalIgnoreCase) ? "selected" : string.Empty;
            Write(buffer, SelectOptionTemplate(Encode(option.Key), Encode(option.Value), selected));
        }
        Write(buffer, SelectEndTemplate());
        return buffer.WrittenSpan.ToArray();
    }

    private byte[] RenderLookupSelect(FormField field, string required, string selectedValue)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var name = Encode(field.Name);
        
        // Check if we have lookup metadata (not for enum fields)
        var hasLookupMetadata = !string.IsNullOrEmpty(field.LookupTargetSlug);

        // High-cardinality: render hidden value input + display text + search button instead of full dropdown
        if (field.IsHighCardinality && hasLookupMetadata)
        {
            Write(buffer, LookupGroupStart);
            // Hidden input carries the actual ID value
            Write(buffer, Encoding.UTF8.GetBytes(
                $"<input type=\"hidden\" id=\"{name}\" name=\"{name}\" value=\"{Encode(selectedValue)}\" />"));
            // Readonly text input shows the human-readable display value
            Write(buffer, LookupSearchDisplayTemplate(name, Encode(field.LookupDisplayValue ?? string.Empty)));
            // Search button — value field name converted to camelCase to match JSON API response keys
            var rawValueField = field.LookupValueField ?? "id";
            var camelValueField = rawValueField.Length > 0
                ? char.ToLowerInvariant(rawValueField[0]) + rawValueField[1..]
                : "id";
            Write(buffer, LookupSearchButtonTemplate(
                Encode(field.LookupTargetSlug ?? string.Empty),
                Encode(field.LookupTargetType ?? string.Empty),
                name,
                Encode(field.LookupSearchField ?? string.Empty),
                Encode(camelValueField)
            ));
            // Add button
            Write(buffer, LookupAddButtonTemplate(
                Encode(field.LookupTargetSlug ?? string.Empty),
                Encode(field.LookupTargetType ?? string.Empty),
                name
            ));
            Write(buffer, LookupGroupEnd);
            return buffer.WrittenSpan.ToArray();
        }

        var options = field.LookupOptions ?? Array.Empty<KeyValuePair<string, string>>();
        
        // If we have lookup metadata, wrap in input-group for buttons
        if (hasLookupMetadata)
        {
            Write(buffer, LookupGroupStart);
        }
        
        Write(buffer, SelectStartTemplate(name, name, required));
        foreach (var option in options)
        {
            var selected = string.Equals(option.Key, selectedValue, StringComparison.OrdinalIgnoreCase) ? "selected" : string.Empty;
            Write(buffer, SelectOptionTemplate(Encode(option.Key), Encode(option.Value), selected));
        }
        Write(buffer, SelectEndTemplate());
        
        // Add refresh and add buttons if we have lookup metadata
        if (hasLookupMetadata)
        {
            Write(buffer, LookupRefreshButtonTemplate(name));
            if (!string.IsNullOrEmpty(field.LookupTargetSlug))
            {
                Write(buffer, LookupAddButtonTemplate(
                    Encode(field.LookupTargetSlug ?? string.Empty),
                    Encode(field.LookupTargetType ?? string.Empty),
                    name
                ));
            }
            Write(buffer, LookupGroupEnd);
        }
        
        return buffer.WrittenSpan.ToArray();
    }

    private static string Encode(string? value)
    {
        return WebUtility.HtmlEncode(value ?? string.Empty);
    }

    private static string StepFromDp(int decimalPlaces)
    {
        if (decimalPlaces <= 0)
            return "1";

        var step = Math.Pow(10, -decimalPlaces);
        return step.ToString($"0.{new string('0', decimalPlaces)}", System.Globalization.CultureInfo.InvariantCulture);
    }
    private static void Write(IBufferWriter<byte> writer, byte[] data)
    {
        var span = writer.GetSpan(data.Length);
        data.CopyTo(span);
        writer.Advance(data.Length);
    }
}
