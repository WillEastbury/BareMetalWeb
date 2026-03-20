using System.Collections.Generic;
using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for Money field binding in ApplyValuesFromForm and ApplyValuesFromJson.
/// Regression tests for "Money type Doesn't bind second field (Currency)".
/// </summary>
[Collection("SharedState")]
public class MoneyFieldBindingTests
{
    [DataEntity("MoneyTestEntities")]
    private class MoneyTestEntity : BaseDataObject
    {
        private const int Ord_Name = BaseFieldCount + 0;
        private const int Ord_Price = BaseFieldCount + 1;
        internal new const int TotalFieldCount = BaseFieldCount + 2;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Name", Ord_Name),
            new FieldSlot("Price", Ord_Price),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public MoneyTestEntity() : base(TotalFieldCount) { }
        public MoneyTestEntity(string createdBy) : base(TotalFieldCount, createdBy) { }


        [DataField(Label = "Price", FieldType = FormFieldType.Money, Order = 1)]
        public decimal Price
        {
            get => (decimal)(_values[Ord_Price] ?? 0m);
            set => _values[Ord_Price] = value;
        }



        [DataField(Label = "Name", Order = 2)]
        public string Name
        {
            get => (string?)_values[Ord_Name] ?? string.Empty;
            set => _values[Ord_Name] = value;
        }
    }

    private static DataEntityMetadata GetMeta()
    {
        DataScaffold.RegisterEntity<MoneyTestEntity>();
        var meta = DataScaffold.GetEntityByType(typeof(MoneyTestEntity));
        Assert.NotNull(meta);
        return meta!;
    }

    // ── ApplyValuesFromForm ──────────────────────────────────────────────────

    [Fact]
    public void ApplyValuesFromForm_MoneyField_BindsAmountByFieldName()
    {
        // Arrange – submit amount using the plain field name (standard form after rendering fix)
        var meta = GetMeta();
        var instance = new MoneyTestEntity();
        var formValues = new Dictionary<string, string?>
        {
            ["Price"] = "123.45",
            ["Name"] = "Widget"
        };

        // Act
        var errors = DataScaffold.ApplyValuesFromForm(meta, instance, formValues, forCreate: true);

        // Assert
        Assert.Empty(errors);
        Assert.Equal(123.45m, instance.Price);
    }

    [Fact]
    public void ApplyValuesFromForm_MoneyField_BindsAmountViaAmountSuffix()
    {
        // Arrange – submit amount using the _amount suffix (backward-compat fallback)
        var meta = GetMeta();
        var instance = new MoneyTestEntity();
        var formValues = new Dictionary<string, string?>
        {
            ["Price_amount"] = "99.99",
            ["Price_currency"] = "EUR",
            ["Name"] = "Gadget"
        };

        // Act
        var errors = DataScaffold.ApplyValuesFromForm(meta, instance, formValues, forCreate: true);

        // Assert – amount must bind; currency is accepted but has no backing property
        Assert.Empty(errors);
        Assert.Equal(99.99m, instance.Price);
    }

    [Fact]
    public void ApplyValuesFromForm_MoneyField_RequiredAndMissing_ReturnsError()
    {
        // Arrange
        DataScaffold.RegisterEntity<MoneyRequiredEntity>();
        var meta = DataScaffold.GetEntityByType(typeof(MoneyRequiredEntity));
        Assert.NotNull(meta);
        var instance = new MoneyRequiredEntity();
        var formValues = new Dictionary<string, string?>
        {
            ["Name"] = "Test"
        };

        // Act
        var errors = DataScaffold.ApplyValuesFromForm(meta!, instance, formValues, forCreate: true);

        // Assert – should have a required error for the Money field
        Assert.Contains(errors, e => e.Contains("Price"));
    }

    // ── ApplyValuesFromJson ──────────────────────────────────────────────────

    [Fact]
    public void ApplyValuesFromJson_MoneyField_BindsAmountFromJsonObject()
    {
        // Arrange – VNext SPA submits { "Price": { "amount": 250.00, "currency": "GBP" } }
        var meta = GetMeta();
        var instance = new MoneyTestEntity();
        var json = JsonDocToDict(
            "{\"Price\":{\"amount\":250.00,\"currency\":\"GBP\"},\"Name\":\"Widget\"}");

        // Act
        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, json, forCreate: true, allowMissing: false);

        // Assert – amount extracted from object
        Assert.Empty(errors);
        Assert.Equal(250.00m, instance.Price);
    }

    [Fact]
    public void ApplyValuesFromJson_MoneyField_BindsAmountFromPlainDecimal()
    {
        // Arrange – plain decimal value (non-VNext or numeric field path)
        var meta = GetMeta();
        var instance = new MoneyTestEntity();
        var json = JsonDocToDict(
            "{\"Price\":75.50,\"Name\":\"Widget\"}");

        // Act
        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, json, forCreate: true, allowMissing: false);

        // Assert
        Assert.Empty(errors);
        Assert.Equal(75.50m, instance.Price);
    }

    [Fact]
    public void ApplyValuesFromJson_MoneyField_InvalidObjectWithoutAmount_ReturnsError()
    {
        // Arrange – object without "amount" property should fail gracefully
        var meta = GetMeta();
        var instance = new MoneyTestEntity();
        var json = JsonDocToDict(
            "{\"Price\":{\"value\":100},\"Name\":\"Widget\"}");

        // Act
        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, json, forCreate: true, allowMissing: false);

        // Assert – error reported for the invalid Money field
        Assert.Contains(errors, e => e.Contains("Price"));
    }

    [DataEntity("MoneyRequiredTestEntities")]
    private class MoneyRequiredEntity : BaseDataObject
    {
        private const int Ord_Name = BaseFieldCount + 0;
        private const int Ord_Price = BaseFieldCount + 1;
        internal new const int TotalFieldCount = BaseFieldCount + 2;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Name", Ord_Name),
            new FieldSlot("Price", Ord_Price),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public MoneyRequiredEntity() : base(TotalFieldCount) { }
        public MoneyRequiredEntity(string createdBy) : base(TotalFieldCount, createdBy) { }


        [DataField(Label = "Price", FieldType = FormFieldType.Money, Order = 1, Required = true)]
        public decimal Price
        {
            get => (decimal)(_values[Ord_Price] ?? 0m);
            set => _values[Ord_Price] = value;
        }



        [DataField(Label = "Name", Order = 2)]
        public string Name
        {
            get => (string?)_values[Ord_Name] ?? string.Empty;
            set => _values[Ord_Name] = value;
        }
    }

    private static Dictionary<string, JsonElement> JsonDocToDict(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var dict = new Dictionary<string, JsonElement>();
        foreach (var prop in doc.RootElement.EnumerateObject())
            dict[prop.Name] = prop.Value.Clone();
        return dict;
    }
}
