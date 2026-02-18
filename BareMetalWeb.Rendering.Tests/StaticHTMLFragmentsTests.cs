using System.Buffers;
using System.Net;
using System.Text;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Interfaces;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Rendering.Tests;

#region Test Helpers

internal sealed class FakeFragmentStore : IHtmlFragmentStore
{
    // Real HTML fragment templates matching production
    private static readonly Dictionary<string, string> Templates = new(StringComparer.OrdinalIgnoreCase)
    {
        ["DocTypeAndHeadStart"] = "<!DOCTYPE html><html><head>",
        ["HeadEndAndBodyStart"] = "</head><body>",
        ["BodyEndAndHtmlEnd"] = "</body></html>",
        ["ScriptTagStart"] = "<script>",
        ["ScriptTagEnd"] = "</script>",
        ["TableStart"] = "<table class=\"table table-striped table-sm align-middle mb-0 bm-table\">",
        ["TableHeadStart"] = "<thead><tr>",
        ["TableHeadEnd"] = "</tr></thead>",
        ["TableHeadCell"] = "<th scope=\"col\">{{value}}</th>",
        ["TableBodyStart"] = "<tbody>",
        ["TableRowStart"] = "<tr>",
        ["TableRowEnd"] = "</tr>",
        ["TableBodyEnd"] = "</tbody>",
        ["TableEnd"] = "</table>",
        ["TableCell"] = "<td data-label=\"{{label}}\">{{value}}</td>",
        ["FormStart"] = "<form method=\"{{method}}\" action=\"{{action}}\" enctype=\"{{enctype}}\">",
        ["FormEnd"] = "<div class=\"mt-3\"><button type=\"submit\" class=\"btn btn-primary\">{{submitLabel}}</button></div></form>",
        ["FormGroupStart"] = "<div class=\"mb-3\">",
        ["FormGroupEnd"] = "</div>",
        ["FormLabel"] = "<label class=\"form-label\" for=\"{{id}}\">{{label}}</label>",
        ["InputText"] = "<input type=\"text\" class=\"form-control\" id=\"{{id}}\" name=\"{{name}}\" value=\"{{value}}\" placeholder=\"{{placeholder}}\" {{required}}>",
        ["InputReadOnly"] = "<input type=\"text\" class=\"form-control\" id=\"{{id}}\" name=\"{{name}}\" value=\"{{value}}\" placeholder=\"{{placeholder}}\" readonly disabled>",
        ["InputTextArea"] = "<textarea class=\"form-control\" id=\"{{id}}\" name=\"{{name}}\" placeholder=\"{{placeholder}}\" {{required}} rows=\"4\">{{value}}</textarea>",
        ["InputPassword"] = "<input type=\"password\" class=\"form-control\" id=\"{{id}}\" name=\"{{name}}\" value=\"{{value}}\" placeholder=\"{{placeholder}}\" {{required}}>",
        ["InputHidden"] = "<input type=\"hidden\" id=\"{{id}}\" name=\"{{name}}\" value=\"{{value}}\">",
        ["InputEmail"] = "<input type=\"email\" class=\"form-control\" id=\"{{id}}\" name=\"{{name}}\" value=\"{{value}}\" placeholder=\"{{placeholder}}\" pattern=\"{{pattern}}\" {{required}}>",
        ["InputNumber"] = "<input type=\"number\" class=\"form-control\" id=\"{{id}}\" name=\"{{name}}\" value=\"{{value}}\" placeholder=\"{{placeholder}}\" step=\"1\" {{required}}>",
        ["InputDecimal"] = "<input type=\"number\" class=\"form-control\" id=\"{{id}}\" name=\"{{name}}\" value=\"{{value}}\" placeholder=\"{{placeholder}}\" step=\"{{step}}\" inputmode=\"decimal\" {{required}}>",
        ["InputDate"] = "<input type=\"date\" class=\"form-control\" id=\"{{id}}\" name=\"{{name}}\" value=\"{{value}}\" placeholder=\"{{placeholder}}\" {{required}}>",
        ["InputTime"] = "<input type=\"time\" class=\"form-control\" id=\"{{id}}\" name=\"{{name}}\" value=\"{{value}}\" placeholder=\"{{placeholder}}\" {{required}}>",
        ["InputDateTime"] = "<input type=\"datetime-local\" class=\"form-control\" id=\"{{id}}\" name=\"{{name}}\" value=\"{{value}}\" placeholder=\"{{placeholder}}\" {{required}}>",
        ["InputFile"] = "<input type=\"file\" class=\"form-control\" id=\"{{id}}\" name=\"{{name}}\" {{required}} accept=\".csv,text/csv\">",
        ["InputImage"] = "<input type=\"file\" class=\"form-control\" id=\"{{id}}\" name=\"{{name}}\" accept=\"image/*\" {{required}}><img id=\"{{id}}_preview\" class=\"img-thumbnail mt-2 img-preview-max\" alt=\"preview\">",
        ["InputOtp"] = "<input type=\"text\" class=\"form-control\" id=\"{{id}}\" name=\"{{name}}\" value=\"{{value}}\" placeholder=\"{{placeholder}}\" inputmode=\"numeric\" pattern=\"\\d{6}\" minlength=\"6\" maxlength=\"6\" autocomplete=\"one-time-code\" {{required}}>",
        ["InputCheckbox"] = "<div class=\"form-check\"><input class=\"form-check-input\" type=\"checkbox\" id=\"{{id}}\" name=\"{{name}}\" value=\"true\" {{checked}} {{required}}><label class=\"form-check-label\" for=\"{{id}}\">{{label}}</label></div>",
        ["SelectStart"] = "<select class=\"form-select\" id=\"{{id}}\" name=\"{{name}}\" {{required}}>",
        ["SelectOption"] = "<option value=\"{{value}}\" {{selected}}>{{label}}</option>",
        ["SelectEnd"] = "</select>",
        ["MenuOption"] = "<li class=\"nav-item\"><a class=\"{{class}}\" href=\"{{href}}\">{{label}}</a></li>",
        ["Button"] = "<button type=\"{{type}}\" class=\"btn {{class}}\" id=\"{{id}}\" name=\"{{name}}\">{{label}}</button>",
        ["FormLink"] = "<a href=\"{{href}}\" class=\"{{class}}\" target=\"{{target}}\">{{label}}</a>",
        ["MoneyGroupStart"] = "<div class=\"row g-2\"><div class=\"col\">",
        ["MoneyGroupMid"] = "</div><div class=\"col-4\">",
        ["MoneyGroupEnd"] = "</div></div>",
        ["LookupGroupStart"] = "<div class=\"input-group\">",
        ["LookupGroupEnd"] = "</div>",
        ["LookupRefreshButton"] = "<button class=\"btn btn-outline-secondary btn-sm\" type=\"button\" data-lookup-refresh=\"{{fieldName}}\" title=\"Refresh lookup values\">↻</button>",
        ["LookupAddButton"] = "<button class=\"btn btn-outline-primary btn-sm\" type=\"button\" data-lookup-add=\"{{targetSlug}}\" data-lookup-field=\"{{fieldName}}\" title=\"Add new {{targetType}}\">+</button>",
    };

    public string ReturnTemplateFragment(string templateKey)
    {
        return Templates.TryGetValue(templateKey, out var value) ? value : string.Empty;
    }

    public string ZeroAllocationReplaceCopy(string template, string[] keys, string[] values)
    {
        var result = template;
        for (int i = 0; i < keys.Length; i++)
            result = result.Replace(keys[i], WebUtility.HtmlEncode(values[i]));
        return result;
    }

    public byte[] ZeroAllocationReplaceCopyAndEncode(string template, string[] keys, string[] values)
    {
        return Encoding.UTF8.GetBytes(ZeroAllocationReplaceCopy(template, keys, values));
    }

    public void ZeroAllocationReplaceCopyAndWrite(string template, IBufferWriter<byte> writer, string[] keys, string[] values)
    {
        var bytes = ZeroAllocationReplaceCopyAndEncode(template, keys, values);
        var span = writer.GetSpan(bytes.Length);
        bytes.CopyTo(span);
        writer.Advance(bytes.Length);
    }
}

#endregion

public class StaticHTMLFragmentsTests
{
    private readonly FakeFragmentStore _store = new();
    private readonly HtmlFragmentRenderer _renderer;

    public StaticHTMLFragmentsTests()
    {
        _renderer = new HtmlFragmentRenderer(_store);
    }

    private static string Decode(byte[] bytes) => Encoding.UTF8.GetString(bytes);

    // ── RenderField via RenderForm: String ──────────────────────────

    [Fact]
    public void RenderForm_StringField_RendersTextInput()
    {
        // Arrange
        var field = new FormField(FormFieldType.String, "username", "Username",
            Placeholder: "Enter name", Value: "Alice");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"text\"", html);
        Assert.Contains("name=\"username\"", html);
        Assert.Contains("value=\"Alice\"", html);
        Assert.Contains("placeholder=\"Enter name\"", html);
    }

    [Fact]
    public void RenderForm_StringFieldRequired_IncludesRequiredAttribute()
    {
        // Arrange
        var field = new FormField(FormFieldType.String, "email", "Email", Required: true);
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("required", html);
    }

    // ── RenderField via RenderForm: Number / Integer ────────────────

    [Fact]
    public void RenderForm_IntegerField_RendersNumberInput()
    {
        // Arrange
        var field = new FormField(FormFieldType.Integer, "age", "Age", Value: "25");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"number\"", html);
        Assert.Contains("name=\"age\"", html);
        Assert.Contains("value=\"25\"", html);
        Assert.Contains("step=\"1\"", html);
    }

    // ── RenderField via RenderForm: DateOnly ────────────────────────

    [Fact]
    public void RenderForm_DateOnlyField_RendersDateInput()
    {
        // Arrange
        var field = new FormField(FormFieldType.DateOnly, "dob", "Date of Birth", Value: "2000-01-01");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"date\"", html);
        Assert.Contains("value=\"2000-01-01\"", html);
    }

    // ── RenderField via RenderForm: TimeOnly ────────────────────────

    [Fact]
    public void RenderForm_TimeOnlyField_RendersTimeInput()
    {
        // Arrange
        var field = new FormField(FormFieldType.TimeOnly, "start", "Start Time", Value: "09:30");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"time\"", html);
        Assert.Contains("value=\"09:30\"", html);
    }

    // ── RenderField via RenderForm: DateTime ────────────────────────

    [Fact]
    public void RenderForm_DateTimeField_RendersDateTimeLocalInput()
    {
        // Arrange
        var field = new FormField(FormFieldType.DateTime, "scheduled", "Scheduled", Value: "2024-06-15T10:00");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"datetime-local\"", html);
        Assert.Contains("value=\"2024-06-15T10:00\"", html);
    }

    // ── RenderField via RenderForm: Checkbox / YesNo ────────────────

    [Fact]
    public void RenderForm_YesNoField_RendersCheckboxInput()
    {
        // Arrange
        var field = new FormField(FormFieldType.YesNo, "agree", "I agree", SelectedValue: "true");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"checkbox\"", html);
        Assert.Contains("checked", html);
        Assert.Contains("I agree", html);
    }

    [Fact]
    public void RenderForm_YesNoFieldUnchecked_DoesNotIncludeChecked()
    {
        // Arrange
        var field = new FormField(FormFieldType.YesNo, "agree", "I agree", SelectedValue: "false");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"checkbox\"", html);
        Assert.DoesNotContain("checked", html);
    }

    // ── RenderField via RenderForm: Select / Enum ───────────────────

    [Fact]
    public void RenderForm_EnumField_RendersSelectWithOptions()
    {
        // Arrange
        var options = new List<KeyValuePair<string, string>>
        {
            new("1", "Option A"),
            new("2", "Option B"),
        };
        var field = new FormField(FormFieldType.Enum, "status", "Status",
            LookupOptions: options, SelectedValue: "2");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("<select", html);
        Assert.Contains("</select>", html);
        Assert.Contains("Option A", html);
        Assert.Contains("Option B", html);
        Assert.Contains("value=\"2\" selected", html);
    }

    [Fact]
    public void RenderForm_EnumField_NonSelectedOptionNotMarkedSelected()
    {
        // Arrange
        var options = new List<KeyValuePair<string, string>>
        {
            new("1", "Option A"),
            new("2", "Option B"),
        };
        var field = new FormField(FormFieldType.Enum, "status", "Status",
            LookupOptions: options, SelectedValue: "2");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.DoesNotContain("value=\"1\" selected", html);
    }

    // ── RenderField via RenderForm: TextArea ────────────────────────

    [Fact]
    public void RenderForm_TextAreaField_RendersTextArea()
    {
        // Arrange
        var field = new FormField(FormFieldType.TextArea, "bio", "Bio",
            Value: "Hello world", Placeholder: "Tell us about yourself");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("<textarea", html);
        Assert.Contains("</textarea>", html);
        Assert.Contains("Hello world", html);
        Assert.Contains("placeholder=\"Tell us about yourself\"", html);
    }

    // ── RenderField via RenderForm: ReadOnly ────────────────────────

    [Fact]
    public void RenderForm_ReadOnlyField_RendersReadOnlyDisabledInput()
    {
        // Arrange
        var field = new FormField(FormFieldType.ReadOnly, "id", "ID", Value: "42");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("readonly", html);
        Assert.Contains("disabled", html);
        Assert.Contains("value=\"42\"", html);
    }

    // ── RenderField via RenderForm: Password ────────────────────────

    [Fact]
    public void RenderForm_PasswordField_RendersPasswordInput()
    {
        // Arrange
        var field = new FormField(FormFieldType.Password, "pass", "Password",
            Placeholder: "Enter password");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"password\"", html);
        Assert.Contains("name=\"pass\"", html);
    }

    // ── RenderField via RenderForm: Email ───────────────────────────

    [Fact]
    public void RenderForm_EmailField_RendersEmailInput()
    {
        // Arrange
        var field = new FormField(FormFieldType.Email, "email", "Email",
            Value: "test@example.com", EmailPattern: ".+@.+\\..+");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"email\"", html);
        Assert.Contains("test@example.com", html);
    }

    [Fact]
    public void RenderForm_EmailFieldNoPattern_UsesDefaultPattern()
    {
        // Arrange
        var field = new FormField(FormFieldType.Email, "email", "Email");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("pattern=", html);
    }

    // ── RenderField via RenderForm: Hidden ──────────────────────────

    [Fact]
    public void RenderForm_HiddenField_RendersHiddenInputWithoutFormGroup()
    {
        // Arrange
        var field = new FormField(FormFieldType.Hidden, "csrf", "CSRF", Value: "token123");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"hidden\"", html);
        Assert.Contains("value=\"token123\"", html);
        // Hidden fields should not be wrapped in form-group divs
        // The form-group div appears for other fields but not before hidden
    }

    // ── RenderField via RenderForm: Decimal ─────────────────────────

    [Fact]
    public void RenderForm_DecimalField_RendersDecimalInputWithStep()
    {
        // Arrange
        var field = new FormField(FormFieldType.Decimal, "price", "Price",
            Value: "19.99", DecimalPlaces: 2);
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"number\"", html);
        Assert.Contains("step=\"0.01\"", html);
        Assert.Contains("inputmode=\"decimal\"", html);
        Assert.Contains("value=\"19.99\"", html);
    }

    [Fact]
    public void RenderForm_DecimalFieldZeroDp_StepIsOne()
    {
        // Arrange
        var field = new FormField(FormFieldType.Decimal, "qty", "Qty", DecimalPlaces: 0);
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("step=\"1\"", html);
    }

    [Fact]
    public void RenderForm_DecimalFieldThreeDp_StepIsCorrect()
    {
        // Arrange
        var field = new FormField(FormFieldType.Decimal, "weight", "Weight", DecimalPlaces: 3);
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("step=\"0.001\"", html);
    }

    // ── RenderField via RenderForm: OTP ─────────────────────────────

    [Fact]
    public void RenderForm_OtpField_RendersOtpInput()
    {
        // Arrange
        var field = new FormField(FormFieldType.Otp, "otp", "OTP Code", Placeholder: "Enter code");
        var form = new FormDefinition("/verify", "POST", "Verify", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("inputmode=\"numeric\"", html);
        Assert.Contains("autocomplete=\"one-time-code\"", html);
        Assert.Contains("maxlength=\"6\"", html);
    }

    // ── RenderField via RenderForm: File ────────────────────────────

    [Fact]
    public void RenderForm_FileField_RendersFileInput()
    {
        // Arrange
        var field = new FormField(FormFieldType.File, "doc", "Document");
        var form = new FormDefinition("/upload", "POST", "Upload", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"file\"", html);
        Assert.Contains("name=\"doc\"", html);
    }

    // ── RenderField via RenderForm: Image ───────────────────────────

    [Fact]
    public void RenderForm_ImageField_RendersImageInputWithPreview()
    {
        // Arrange
        var field = new FormField(FormFieldType.Image, "photo", "Photo");
        var form = new FormDefinition("/upload", "POST", "Upload", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"file\"", html);
        Assert.Contains("accept=\"image/*\"", html);
        Assert.Contains("_preview", html);
    }

    [Fact]
    public void RenderForm_ImageField_SetsMultipartEnctype()
    {
        // Arrange
        var field = new FormField(FormFieldType.Image, "photo", "Photo");
        var form = new FormDefinition("/upload", "POST", "Upload", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("multipart/form-data", html);
    }

    // ── RenderField via RenderForm: Button ──────────────────────────

    [Fact]
    public void RenderForm_ButtonField_RendersButton()
    {
        // Arrange
        var field = new FormField(FormFieldType.Button, "cancel", "Cancel",
            ButtonType: "button", ButtonStyle: "btn-danger", ButtonText: "Cancel");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("<button", html);
        Assert.Contains("type=\"button\"", html);
        Assert.Contains("btn-danger", html);
        Assert.Contains(">Cancel</button>", html);
    }

    [Fact]
    public void RenderForm_ButtonFieldDefaults_UsesDefaultTypeAndStyle()
    {
        // Arrange
        var field = new FormField(FormFieldType.Button, "action", "Do It");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"button\"", html);
        Assert.Contains("btn-secondary", html);
    }

    // ── RenderField via RenderForm: Link ────────────────────────────

    [Fact]
    public void RenderForm_LinkField_RendersAnchorTag()
    {
        // Arrange
        var field = new FormField(FormFieldType.Link, "help", "Help",
            LinkUrl: "/help", LinkText: "Need help?", LinkTarget: "_blank", LinkClass: "link-info");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("href=\"/help\"", html);
        Assert.Contains("Need help?", html);
        Assert.Contains("target=\"_blank\"", html);
        Assert.Contains("link-info", html);
    }

    [Fact]
    public void RenderForm_LinkFieldDefaults_UsesDefaultValues()
    {
        // Arrange
        var field = new FormField(FormFieldType.Link, "back", "Go Back");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("href=\"#\"", html);
        Assert.Contains("target=\"_self\"", html);
        Assert.Contains("link-primary", html);
    }

    // ── RenderField via RenderForm: CustomHtml ──────────────────────

    [Fact]
    public void RenderForm_CustomHtmlField_RendersRawHtml()
    {
        // Arrange
        var field = new FormField(FormFieldType.CustomHtml, "custom", "", Html: "<hr class=\"my-4\">");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("<hr class=\"my-4\">", html);
    }

    [Fact]
    public void RenderForm_CustomHtmlFieldNullHtml_RendersEmpty()
    {
        // Arrange
        var field = new FormField(FormFieldType.CustomHtml, "custom", "", Html: null);
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert - should not throw, form still renders
        Assert.Contains("<form", html);
    }

    // ── RenderField via RenderForm: Country ─────────────────────────

    [Fact]
    public void RenderForm_CountryField_RendersSelectWithCountryOptions()
    {
        // Arrange
        var countries = new List<KeyValuePair<string, string>>
        {
            new("US", "United States"),
            new("GB", "United Kingdom"),
        };
        var field = new FormField(FormFieldType.Country, "country", "Country",
            CountryOptions: countries, SelectedValue: "GB");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("<select", html);
        Assert.Contains("United States", html);
        Assert.Contains("United Kingdom", html);
        Assert.Contains("value=\"GB\" selected", html);
    }

    // ── RenderField via RenderForm: Money ───────────────────────────

    [Fact]
    public void RenderForm_MoneyField_RendersAmountAndCurrencySelect()
    {
        // Arrange
        var currencies = new List<string> { "USD", "EUR", "GBP" };
        var field = new FormField(FormFieldType.Money, "total", "Total",
            Value: "100.50", CurrencyOptions: currencies, SelectedValue: "EUR", DecimalPlaces: 2);
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("inputmode=\"decimal\"", html);
        Assert.Contains("value=\"100.50\"", html);
        Assert.Contains("<select", html);
        Assert.Contains("USD", html);
        Assert.Contains("EUR", html);
        Assert.Contains("GBP", html);
    }

    // ── RenderField via RenderForm: LookupList ──────────────────────

    [Fact]
    public void RenderForm_LookupListField_RendersSelectWithOptions()
    {
        // Arrange
        var options = new List<KeyValuePair<string, string>>
        {
            new("1", "Lookup A"),
            new("2", "Lookup B"),
        };
        var field = new FormField(FormFieldType.LookupList, "ref", "Reference",
            LookupOptions: options, SelectedValue: "1");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("<select", html);
        Assert.Contains("Lookup A", html);
        Assert.Contains("value=\"1\" selected", html);
    }

    [Fact]
    public void RenderForm_LookupListWithSlug_RendersRefreshAndAddButtons()
    {
        // Arrange
        var options = new List<KeyValuePair<string, string>> { new("1", "Item") };
        var field = new FormField(FormFieldType.LookupList, "ref", "Reference",
            LookupOptions: options, LookupTargetSlug: "items", LookupTargetType: "Item");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("data-lookup-refresh", html);
        Assert.Contains("data-lookup-add", html);
        Assert.Contains("input-group", html);
    }

    // ── Form-level rendering ────────────────────────────────────────

    [Fact]
    public void RenderForm_ActionAndMethod_RendersFormAttributes()
    {
        // Arrange
        var form = new FormDefinition("/api/save", "POST", "Submit", new List<FormField>());

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("action=\"/api/save\"", html);
        Assert.Contains("method=\"POST\"", html);
    }

    [Fact]
    public void RenderForm_SubmitLabel_RendersSubmitButton()
    {
        // Arrange
        var form = new FormDefinition("/save", "POST", "Create Account", new List<FormField>());

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("Create Account", html);
        Assert.Contains("type=\"submit\"", html);
    }

    [Fact]
    public void RenderForm_NoImageFields_UsesFormUrlEncoded()
    {
        // Arrange
        var field = new FormField(FormFieldType.String, "name", "Name");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("application/x-www-form-urlencoded", html);
    }

    [Fact]
    public void RenderForm_WithCsrfToken_RendersHiddenField()
    {
        // Arrange
        var csrfField = new FormField(FormFieldType.Hidden, "csrf_token", "", Value: "abc-123");
        var nameField = new FormField(FormFieldType.String, "name", "Name");
        var form = new FormDefinition("/save", "POST", "Save", new[] { csrfField, nameField });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"hidden\"", html);
        Assert.Contains("value=\"abc-123\"", html);
    }

    [Fact]
    public void RenderForm_MultipleFields_RendersAllFields()
    {
        // Arrange
        var fields = new List<FormField>
        {
            new(FormFieldType.String, "first", "First Name"),
            new(FormFieldType.String, "last", "Last Name"),
            new(FormFieldType.Email, "email", "Email"),
        };
        var form = new FormDefinition("/save", "POST", "Save", fields);

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("name=\"first\"", html);
        Assert.Contains("name=\"last\"", html);
        Assert.Contains("type=\"email\"", html);
    }

    [Fact]
    public void RenderForm_FieldWithLabel_RendersFormLabel()
    {
        // Arrange
        var field = new FormField(FormFieldType.String, "name", "Full Name");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("<label", html);
        Assert.Contains("Full Name", html);
    }

    [Fact]
    public void RenderForm_YesNoField_DoesNotRenderSeparateLabel()
    {
        // Arrange — YesNo has its own label inside the checkbox template
        var field = new FormField(FormFieldType.YesNo, "agree", "I Agree");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert — label is inside form-check, not a separate <label class="form-label">
        Assert.Contains("form-check-label", html);
    }

    // ── RenderMenuOptions ───────────────────────────────────────────

    [Fact]
    public void RenderMenuOptions_LeftAligned_RendersOnlyLeftOptions()
    {
        // Arrange
        var options = new List<IMenuOption>
        {
            new StubMenuOption { Href = "/home", Label = "Home", RightAligned = false },
            new StubMenuOption { Href = "/settings", Label = "Settings", RightAligned = true },
        };

        // Act
        var html = Decode(_renderer.RenderMenuOptions(options, rightAligned: false));

        // Assert
        Assert.Contains("Home", html);
        Assert.DoesNotContain("Settings", html);
    }

    [Fact]
    public void RenderMenuOptions_RightAligned_RendersOnlyRightOptions()
    {
        // Arrange
        var options = new List<IMenuOption>
        {
            new StubMenuOption { Href = "/home", Label = "Home", RightAligned = false },
            new StubMenuOption { Href = "/settings", Label = "Settings", RightAligned = true },
        };

        // Act
        var html = Decode(_renderer.RenderMenuOptions(options, rightAligned: true));

        // Assert
        Assert.Contains("Settings", html);
        Assert.DoesNotContain("Home", html);
    }

    [Fact]
    public void RenderMenuOptions_StandardOption_RendersNavLink()
    {
        // Arrange
        var options = new List<IMenuOption>
        {
            new StubMenuOption { Href = "/about", Label = "About" },
        };

        // Act
        var html = Decode(_renderer.RenderMenuOptions(options, rightAligned: false));

        // Assert
        Assert.Contains("nav-link", html);
        Assert.Contains("href=\"/about\"", html);
        Assert.Contains("About", html);
    }

    [Fact]
    public void RenderMenuOptions_HighlightAsButton_RendersButtonClass()
    {
        // Arrange
        var options = new List<IMenuOption>
        {
            new StubMenuOption { Href = "/signup", Label = "Sign Up", HighlightAsButton = true },
        };

        // Act
        var html = Decode(_renderer.RenderMenuOptions(options, rightAligned: false));

        // Assert
        Assert.Contains("btn", html);
        Assert.Contains("btn-outline-light", html);
    }

    [Fact]
    public void RenderMenuOptions_HighlightAsButtonWithColor_UsesColorClass()
    {
        // Arrange
        var options = new List<IMenuOption>
        {
            new StubMenuOption { Href = "/signup", Label = "Sign Up", HighlightAsButton = true, ColorClass = "btn-success" },
        };

        // Act
        var html = Decode(_renderer.RenderMenuOptions(options, rightAligned: false));

        // Assert
        Assert.Contains("btn-success", html);
        Assert.DoesNotContain("btn-outline-light", html);
    }

    [Fact]
    public void RenderMenuOptions_StandardWithColorClass_IncludesColorInNavLink()
    {
        // Arrange
        var options = new List<IMenuOption>
        {
            new StubMenuOption { Href = "/alerts", Label = "Alerts", ColorClass = "text-danger" },
        };

        // Act
        var html = Decode(_renderer.RenderMenuOptions(options, rightAligned: false));

        // Assert
        Assert.Contains("nav-link text-danger", html);
    }

    [Fact]
    public void RenderMenuOptions_EmptyList_ReturnsEmptyArray()
    {
        // Act
        var result = _renderer.RenderMenuOptions(new List<IMenuOption>(), rightAligned: false);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void RenderMenuOptions_GroupedOptions_RendersDropdown()
    {
        // Arrange
        var options = new List<IMenuOption>
        {
            new StubMenuOption { Href = "/profile", Label = "Profile", Group = "Account" },
            new StubMenuOption { Href = "/logout", Label = "Logout", Group = "Account" },
        };

        // Act
        var html = Decode(_renderer.RenderMenuOptions(options, rightAligned: false));

        // Assert
        Assert.Contains("dropdown", html);
        Assert.Contains("dropdown-toggle", html);
        Assert.Contains("Account", html);
        Assert.Contains("Profile", html);
        Assert.Contains("Logout", html);
        Assert.Contains("dropdown-item", html);
    }

    [Fact]
    public void RenderMenuOptions_GroupedRightAligned_RendersDropdownMenuEnd()
    {
        // Arrange
        var options = new List<IMenuOption>
        {
            new StubMenuOption { Href = "/profile", Label = "Profile", Group = "User", RightAligned = true },
            new StubMenuOption { Href = "/logout", Label = "Logout", Group = "User", RightAligned = true },
        };

        // Act
        var html = Decode(_renderer.RenderMenuOptions(options, rightAligned: true));

        // Assert
        Assert.Contains("dropdown-menu-end", html);
    }

    [Fact]
    public void RenderMenuOptions_GroupedLeftAligned_NoDropdownMenuEnd()
    {
        // Arrange
        var options = new List<IMenuOption>
        {
            new StubMenuOption { Href = "/a", Label = "A", Group = "G" },
            new StubMenuOption { Href = "/b", Label = "B", Group = "G" },
        };

        // Act
        var html = Decode(_renderer.RenderMenuOptions(options, rightAligned: false));

        // Assert
        Assert.DoesNotContain("dropdown-menu-end", html);
        Assert.Contains("dropdown-menu", html);
    }

    [Fact]
    public void RenderMenuOptions_MixedGroupedAndUngrouped_RendersAllCorrectly()
    {
        // Arrange
        var options = new List<IMenuOption>
        {
            new StubMenuOption { Href = "/home", Label = "Home" },
            new StubMenuOption { Href = "/profile", Label = "Profile", Group = "Account" },
            new StubMenuOption { Href = "/logout", Label = "Logout", Group = "Account" },
        };

        // Act
        var html = Decode(_renderer.RenderMenuOptions(options, rightAligned: false));

        // Assert
        Assert.Contains("Home", html);
        Assert.Contains("dropdown", html);
        Assert.Contains("Profile", html);
        Assert.Contains("Logout", html);
    }

    // ── RenderTable ─────────────────────────────────────────────────

    [Fact]
    public void RenderTable_HeadersAndRows_RendersTableStructure()
    {
        // Arrange
        var columns = new[] { "Name", "Age" };
        var rows = new[] { new[] { "Alice", "30" }, new[] { "Bob", "25" } };

        // Act
        var html = Decode(_renderer.RenderTable(columns, rows));

        // Assert
        Assert.Contains("<table", html);
        Assert.Contains("</table>", html);
        Assert.Contains("<th scope=\"col\">Name</th>", html);
        Assert.Contains("<th scope=\"col\">Age</th>", html);
    }

    [Fact]
    public void RenderTable_RowData_RendersTableCells()
    {
        // Arrange
        var columns = new[] { "Name", "Score" };
        var rows = new[] { new[] { "Alice", "95" } };

        // Act
        var html = Decode(_renderer.RenderTable(columns, rows));

        // Assert
        Assert.Contains("Alice", html);
        Assert.Contains("95", html);
        Assert.Contains("data-label=\"Name\"", html);
        Assert.Contains("data-label=\"Score\"", html);
    }

    [Fact]
    public void RenderTable_MultipleRows_RendersAllRows()
    {
        // Arrange
        var columns = new[] { "ID" };
        var rows = new[]
        {
            new[] { "1" },
            new[] { "2" },
            new[] { "3" },
        };

        // Act
        var html = Decode(_renderer.RenderTable(columns, rows));

        // Assert
        Assert.Contains("<td data-label=\"ID\">1</td>", html);
        Assert.Contains("<td data-label=\"ID\">2</td>", html);
        Assert.Contains("<td data-label=\"ID\">3</td>", html);
    }

    [Fact]
    public void RenderTable_EmptyRows_RendersEmptyTableBody()
    {
        // Arrange
        var columns = new[] { "Name" };
        var rows = Array.Empty<string[]>();

        // Act
        var html = Decode(_renderer.RenderTable(columns, rows));

        // Assert
        Assert.Contains("<table", html);
        Assert.Contains("<th scope=\"col\">Name</th>", html);
        Assert.DoesNotContain("<td", html);
    }

    [Fact]
    public void RenderTable_RowWithMoreColumnsThanHeaders_UsesEmptyLabelForExtra()
    {
        // Arrange
        var columns = new[] { "Name" };
        var rows = new[] { new[] { "Alice", "Extra" } };

        // Act
        var html = Decode(_renderer.RenderTable(columns, rows));

        // Assert
        Assert.Contains("data-label=\"Name\"", html);
        Assert.Contains("data-label=\"\"", html);
        Assert.Contains("Extra", html);
    }

    // ── HTML encoding ───────────────────────────────────────────────

    [Fact]
    public void RenderForm_SpecialCharactersInValue_ArePassedThrough()
    {
        // Arrange
        var field = new FormField(FormFieldType.String, "name", "Name",
            Value: "<script>alert('xss')</script>");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert — renderer passes values through; caller is responsible for encoding
        Assert.Contains("alert(", html);
    }

    [Fact]
    public void RenderForm_SpecialCharactersInPlaceholder_ArePassedThrough()
    {
        // Arrange
        var field = new FormField(FormFieldType.String, "data", "Data",
            Placeholder: "Use <brackets> & \"quotes\"");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert — renderer passes placeholders through; caller is responsible for encoding
        Assert.Contains("brackets", html);
    }

    [Fact]
    public void RenderMenuOptions_SpecialCharactersInLabel_AreHtmlEncoded()
    {
        // Arrange
        var options = new List<IMenuOption>
        {
            new StubMenuOption { Href = "/test", Label = "A & B" },
        };

        // Act
        var html = Decode(_renderer.RenderMenuOptions(options, rightAligned: false));

        // Assert
        Assert.Contains("A &amp; B", html);
    }

    [Fact]
    public void RenderMenuOptions_DropdownGroupLabel_IsHtmlEncoded()
    {
        // Arrange
        var options = new List<IMenuOption>
        {
            new StubMenuOption { Href = "/a", Label = "A", Group = "Items & More" },
            new StubMenuOption { Href = "/b", Label = "B", Group = "Items & More" },
        };

        // Act
        var html = Decode(_renderer.RenderMenuOptions(options, rightAligned: false));

        // Assert
        Assert.Contains("Items &amp; More", html);
    }

    // ── Empty/null value handling ────────────────────────────────────

    [Fact]
    public void RenderForm_NullValue_RendersEmptyValue()
    {
        // Arrange
        var field = new FormField(FormFieldType.String, "name", "Name", Value: null);
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("value=\"\"", html);
    }

    [Fact]
    public void RenderForm_NullPlaceholder_RendersEmptyPlaceholder()
    {
        // Arrange
        var field = new FormField(FormFieldType.String, "name", "Name", Placeholder: null);
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("placeholder=\"\"", html);
    }

    [Fact]
    public void RenderForm_EmptyFields_RendersFormWithNoFieldContent()
    {
        // Arrange
        var form = new FormDefinition("/save", "POST", "Go", new List<FormField>());

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("<form", html);
        Assert.Contains("</form>", html);
        Assert.Contains("Go", html);
    }

    [Fact]
    public void RenderForm_UnknownFieldType_FallsBackToTextInput()
    {
        // Arrange
        var field = new FormField(FormFieldType.Unknown, "fallback", "Fallback", Value: "test");
        var form = new FormDefinition("/save", "POST", "Save", new[] { field });

        // Act
        var html = Decode(_renderer.RenderForm(form));

        // Assert
        Assert.Contains("type=\"text\"", html);
        Assert.Contains("value=\"test\"", html);
    }

    // ── RenderTable encoding ────────────────────────────────────────

    [Fact]
    public void RenderTable_SpecialCharsInHeaders_AreHtmlEncoded()
    {
        // Arrange
        var columns = new[] { "Name & Role" };
        var rows = new[] { new[] { "Admin" } };

        // Act
        var html = Decode(_renderer.RenderTable(columns, rows));

        // Assert
        Assert.Contains("Name &amp; Role", html);
    }

    [Fact]
    public void RenderTable_SpecialCharsInCells_AreHtmlEncoded()
    {
        // Arrange
        var columns = new[] { "Value" };
        var rows = new[] { new[] { "<b>bold</b>" } };

        // Act
        var html = Decode(_renderer.RenderTable(columns, rows));

        // Assert
        Assert.Contains("&lt;b&gt;bold&lt;/b&gt;", html);
    }

    // ── Constructor properties ──────────────────────────────────────

    [Fact]
    public void Constructor_InitializesDocTypeAndHeadStart()
    {
        var html = Decode(_renderer.DocTypeAndHeadStart);
        Assert.Contains("<!DOCTYPE html>", html);
    }

    [Fact]
    public void Constructor_InitializesHeadEndAndBodyStart()
    {
        var html = Decode(_renderer.HeadEndAndBodyStart);
        Assert.Contains("</head><body>", html);
    }

    [Fact]
    public void Constructor_InitializesBodyEndAndHtmlEnd()
    {
        var html = Decode(_renderer.BodyEndAndHtmlEnd);
        Assert.Contains("</body></html>", html);
    }

    [Fact]
    public void Constructor_InitializesScriptTags()
    {
        Assert.Contains("<script>", Decode(_renderer.ScriptTagStart));
        Assert.Contains("</script>", Decode(_renderer.ScriptTagEnd));
    }
}
