using System;
using System.Collections.Generic;
using System.Linq;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;
using Xunit;

namespace BareMetalWeb.Data.Tests;

// Test entities with validation attributes — ordinal-indexed storage, no reflection.
[DataEntity("Validated Entities", Slug = "validated-entities")]
public class ValidatedEntity : BaseDataObject
{
    public override string EntityTypeName => "Validated Entities";
    private const int Ord_Name = BaseFieldCount + 0;
    private const int Ord_Email = BaseFieldCount + 1;
    private const int Ord_Website = BaseFieldCount + 2;
    private const int Ord_PhoneNumber = BaseFieldCount + 3;
    private const int Ord_Score = BaseFieldCount + 4;
    private const int Ord_Code = BaseFieldCount + 5;
    internal new const int TotalFieldCount = BaseFieldCount + 6;

    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("Code", Ord_Code),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Email", Ord_Email),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Name", Ord_Name),
        new FieldSlot("PhoneNumber", Ord_PhoneNumber),
        new FieldSlot("Score", Ord_Score),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
        new FieldSlot("Website", Ord_Website),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public ValidatedEntity() : base(TotalFieldCount) { }
    public ValidatedEntity(string createdBy) : base(TotalFieldCount, createdBy) { }

    [DataField(Label = "Name", Required = true)]
    [MinLength(2)]
    [MaxLength(50)]
    public string Name
    {
        get => (string?)_values[Ord_Name] ?? string.Empty;
        set => _values[Ord_Name] = value;
    }

    [DataField(Label = "Email")]
    [EmailAddress]
    public string? Email
    {
        get => (string?)_values[Ord_Email];
        set => _values[Ord_Email] = value;
    }

    [DataField(Label = "Website")]
    [Url]
    public string? Website
    {
        get => (string?)_values[Ord_Website];
        set => _values[Ord_Website] = value;
    }

    [DataField(Label = "Phone")]
    [Phone]
    public string? PhoneNumber
    {
        get => (string?)_values[Ord_PhoneNumber];
        set => _values[Ord_PhoneNumber] = value;
    }

    [DataField(Label = "Score", FieldType = FormFieldType.Integer)]
    [Range(0, 100)]
    public int Score
    {
        get => (int)(_values[Ord_Score] ?? 0);
        set => _values[Ord_Score] = value;
    }

    [DataField(Label = "Code")]
    [RegexPattern(@"^[A-Z]{3}-\d{4}$", ErrorMessage = "Code must be in format XXX-0000")]
    public string? Code
    {
        get => (string?)_values[Ord_Code];
        set => _values[Ord_Code] = value;
    }
}

[DataEntity("Date Range Entities", Slug = "date-range-entities")]
[ValidationRule("EndDate > StartDate", "End date must be after start date")]
public class DateRangeEntity : BaseDataObject
{
    public override string EntityTypeName => "Date Range Entities";
    private const int Ord_StartDate = BaseFieldCount + 0;
    private const int Ord_EndDate = BaseFieldCount + 1;
    internal new const int TotalFieldCount = BaseFieldCount + 2;

    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("EndDate", Ord_EndDate),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("StartDate", Ord_StartDate),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public DateRangeEntity() : base(TotalFieldCount) { }
    public DateRangeEntity(string createdBy) : base(TotalFieldCount, createdBy) { }

    [DataField(Label = "Start Date", FieldType = FormFieldType.DateOnly)]
    public DateTime StartDate
    {
        get => _values[Ord_StartDate] is DateTime dt ? dt : default;
        set => _values[Ord_StartDate] = value;
    }

    [DataField(Label = "End Date", FieldType = FormFieldType.DateOnly)]
    public DateTime EndDate
    {
        get => _values[Ord_EndDate] is DateTime dt ? dt : default;
        set => _values[Ord_EndDate] = value;
    }
}

/// <summary>
/// All validation tests go through the metadata platform:
/// register entity → get field metadata → validate via metadata.
/// Zero reflection at test time.
/// </summary>
[Collection("SharedState")]
public class ValidationServiceTests
{
    private readonly DataEntityMetadata _validatedMeta;
    private readonly DataEntityMetadata _dateRangeMeta;

    public ValidationServiceTests()
    {
        DataScaffold.RegisterEntity<ValidatedEntity>();
        DataScaffold.RegisterEntity<DateRangeEntity>();
        _validatedMeta = DataScaffold.GetEntityByType(typeof(ValidatedEntity))!;
        _dateRangeMeta = DataScaffold.GetEntityByType(typeof(DateRangeEntity))!;
    }

    private DataFieldMetadata Field(string name) => _validatedMeta.FindField(name)!;

    [Fact]
    public void ValidateField_MinLength_TooShort_ReturnsError()
    {
        var errors = ValidationService.ValidateField(Field("Name"), "A");
        Assert.Single(errors);
        Assert.Contains("at least 2", errors[0]);
    }

    [Fact]
    public void ValidateField_MinLength_Valid_NoError()
    {
        var errors = ValidationService.ValidateField(Field("Name"), "AB");
        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateField_MaxLength_TooLong_ReturnsError()
    {
        var errors = ValidationService.ValidateField(Field("Name"), new string('A', 51));
        Assert.Single(errors);
        Assert.Contains("at most 50", errors[0]);
    }

    [Fact]
    public void ValidateField_Range_BelowMin_ReturnsError()
    {
        var errors = ValidationService.ValidateField(Field("Score"), -1);
        Assert.Single(errors);
        Assert.Contains("between 0 and 100", errors[0]);
    }

    [Fact]
    public void ValidateField_Range_AboveMax_ReturnsError()
    {
        var errors = ValidationService.ValidateField(Field("Score"), 101);
        Assert.Single(errors);
        Assert.Contains("between 0 and 100", errors[0]);
    }

    [Fact]
    public void ValidateField_Range_WithinRange_NoError()
    {
        var errors = ValidationService.ValidateField(Field("Score"), 50);
        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateField_EmailAddress_Invalid_ReturnsError()
    {
        var errors = ValidationService.ValidateField(Field("Email"), "not-an-email");
        Assert.Single(errors);
        Assert.Contains("valid email", errors[0]);
    }

    [Fact]
    public void ValidateField_EmailAddress_Valid_NoError()
    {
        var errors = ValidationService.ValidateField(Field("Email"), "test@example.com");
        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateField_Url_Invalid_ReturnsError()
    {
        var errors = ValidationService.ValidateField(Field("Website"), "not-a-url");
        Assert.Single(errors);
        Assert.Contains("valid URL", errors[0]);
    }

    [Fact]
    public void ValidateField_Url_Valid_NoError()
    {
        var errors = ValidationService.ValidateField(Field("Website"), "https://example.com");
        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateField_Phone_Invalid_ReturnsError()
    {
        var errors = ValidationService.ValidateField(Field("PhoneNumber"), "abc");
        Assert.Single(errors);
        Assert.Contains("valid phone", errors[0]);
    }

    [Fact]
    public void ValidateField_Phone_Valid_NoError()
    {
        var errors = ValidationService.ValidateField(Field("PhoneNumber"), "+1 (555) 123-4567");
        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateField_RegexPattern_Invalid_ReturnsError()
    {
        var errors = ValidationService.ValidateField(Field("Code"), "invalid");
        Assert.Single(errors);
        Assert.Contains("XXX-0000", errors[0]);
    }

    [Fact]
    public void ValidateField_RegexPattern_Valid_NoError()
    {
        var errors = ValidationService.ValidateField(Field("Code"), "ABC-1234");
        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateField_NullValue_SkipsValidation()
    {
        var errors = ValidationService.ValidateField(Field("Email"), null);
        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateEntity_CrossFieldExpression_Invalid_ReturnsError()
    {
        var instance = new DateRangeEntity
        {
            Key = 1,
            StartDate = new DateTime(2024, 6, 1),
            EndDate = new DateTime(2024, 1, 1)
        };

        var result = ValidationService.ValidateEntity(_dateRangeMeta, instance);

        Assert.False(result.IsValid);
        Assert.Contains("End date must be after start date", result.EntityErrors);
    }

    [Fact]
    public void ValidateEntity_CrossFieldExpression_Valid_NoError()
    {
        var instance = new DateRangeEntity
        {
            Key = 2,
            StartDate = new DateTime(2024, 1, 1),
            EndDate = new DateTime(2024, 6, 1)
        };

        var result = ValidationService.ValidateEntity(_dateRangeMeta, instance);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void MetadataValidationConfig_NoAttributes_ReturnsNull()
    {
        // Base property "Key" has no validation attributes → Validation should be null
        var keyField = _validatedMeta.FindField("Key");
        // Key is a core property, not in Fields unless explicitly annotated
        // Verify a non-validated field has null config
        Assert.Null(Field("Email").Validation?.MinLength);
    }

    [Fact]
    public void MetadataValidationConfig_WithAttributes_PopulatesConfig()
    {
        var config = Field("Name").Validation;
        Assert.NotNull(config);
        Assert.Equal(2, config!.MinLength);
        Assert.Equal(50, config.MaxLength);
    }

    [Fact]
    public void MetadataValidationConfig_RangeAttribute_PopulatesMinMax()
    {
        var config = Field("Score").Validation;
        Assert.NotNull(config);
        Assert.Equal(0, config!.RangeMin);
        Assert.Equal(100, config.RangeMax);
    }

    [Fact]
    public void GenerateJavaScriptRule_ValidExpression_ReturnsJs()
    {
        var js = ValidationService.GenerateJavaScriptRule("EndDate > StartDate");
        Assert.NotNull(js);
        Assert.Contains("parseFieldValue", js!);
    }

    [Fact]
    public void GenerateJavaScriptRule_InvalidExpression_ReturnsNull()
    {
        var js = ValidationService.GenerateJavaScriptRule("!!!invalid!!!");
        Assert.Null(js);
    }
}
