using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;
using Xunit;

namespace BareMetalWeb.Data.Tests;

// Test entities with validation attributes
[DataEntity("Validated Entities", Slug = "validated-entities")]
public class ValidatedEntity : BaseDataObject
{
    [DataField(Label = "Name", Required = true)]
    [MinLength(2)]
    [MaxLength(50)]
    public string Name { get; set; } = string.Empty;

    [DataField(Label = "Email")]
    [EmailAddress]
    public string? Email { get; set; }

    [DataField(Label = "Website")]
    [Url]
    public string? Website { get; set; }

    [DataField(Label = "Phone")]
    [Phone]
    public string? PhoneNumber { get; set; }

    [DataField(Label = "Score", FieldType = FormFieldType.Integer)]
    [Range(0, 100)]
    public int Score { get; set; }

    [DataField(Label = "Code")]
    [RegexPattern(@"^[A-Z]{3}-\d{4}$", ErrorMessage = "Code must be in format XXX-0000")]
    public string? Code { get; set; }
}

[DataEntity("Date Range Entities", Slug = "date-range-entities")]
[ValidationRule("EndDate > StartDate", "End date must be after start date")]
public class DateRangeEntity : BaseDataObject
{
    [DataField(Label = "Start Date", FieldType = FormFieldType.DateOnly)]
    public DateTime StartDate { get; set; }

    [DataField(Label = "End Date", FieldType = FormFieldType.DateOnly)]
    public DateTime EndDate { get; set; }
}

public class ValidationServiceTests
{
    [Fact]
    public void ValidateField_MinLength_TooShort_ReturnsError()
    {
        // Arrange
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.Name))!;
        var config = ValidationService.BuildValidationConfig(prop);
        var field = BuildField(prop, "Name", "Name", config);

        // Act
        var errors = ValidationService.ValidateField(field, "A");

        // Assert
        Assert.Single(errors);
        Assert.Contains("at least 2", errors[0]);
    }

    [Fact]
    public void ValidateField_MinLength_Valid_NoError()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.Name))!;
        var config = ValidationService.BuildValidationConfig(prop);
        var field = BuildField(prop, "Name", "Name", config);

        var errors = ValidationService.ValidateField(field, "AB");

        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateField_MaxLength_TooLong_ReturnsError()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.Name))!;
        var config = ValidationService.BuildValidationConfig(prop);
        var field = BuildField(prop, "Name", "Name", config);

        var errors = ValidationService.ValidateField(field, new string('A', 51));

        Assert.Single(errors);
        Assert.Contains("at most 50", errors[0]);
    }

    [Fact]
    public void ValidateField_Range_BelowMin_ReturnsError()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.Score))!;
        var config = ValidationService.BuildValidationConfig(prop);
        var field = BuildField(prop, "Score", "Score", config);

        var errors = ValidationService.ValidateField(field, -1);

        Assert.Single(errors);
        Assert.Contains("between 0 and 100", errors[0]);
    }

    [Fact]
    public void ValidateField_Range_AboveMax_ReturnsError()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.Score))!;
        var config = ValidationService.BuildValidationConfig(prop);
        var field = BuildField(prop, "Score", "Score", config);

        var errors = ValidationService.ValidateField(field, 101);

        Assert.Single(errors);
        Assert.Contains("between 0 and 100", errors[0]);
    }

    [Fact]
    public void ValidateField_Range_WithinRange_NoError()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.Score))!;
        var config = ValidationService.BuildValidationConfig(prop);
        var field = BuildField(prop, "Score", "Score", config);

        var errors = ValidationService.ValidateField(field, 50);

        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateField_EmailAddress_Invalid_ReturnsError()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.Email))!;
        var config = ValidationService.BuildValidationConfig(prop);
        var field = BuildField(prop, "Email", "Email", config);

        var errors = ValidationService.ValidateField(field, "not-an-email");

        Assert.Single(errors);
        Assert.Contains("valid email", errors[0]);
    }

    [Fact]
    public void ValidateField_EmailAddress_Valid_NoError()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.Email))!;
        var config = ValidationService.BuildValidationConfig(prop);
        var field = BuildField(prop, "Email", "Email", config);

        var errors = ValidationService.ValidateField(field, "test@example.com");

        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateField_Url_Invalid_ReturnsError()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.Website))!;
        var config = ValidationService.BuildValidationConfig(prop);
        var field = BuildField(prop, "Website", "Website", config);

        var errors = ValidationService.ValidateField(field, "not-a-url");

        Assert.Single(errors);
        Assert.Contains("valid URL", errors[0]);
    }

    [Fact]
    public void ValidateField_Url_Valid_NoError()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.Website))!;
        var config = ValidationService.BuildValidationConfig(prop);
        var field = BuildField(prop, "Website", "Website", config);

        var errors = ValidationService.ValidateField(field, "https://example.com");

        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateField_Phone_Invalid_ReturnsError()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.PhoneNumber))!;
        var config = ValidationService.BuildValidationConfig(prop);
        var field = BuildField(prop, "PhoneNumber", "Phone", config);

        var errors = ValidationService.ValidateField(field, "abc");

        Assert.Single(errors);
        Assert.Contains("valid phone", errors[0]);
    }

    [Fact]
    public void ValidateField_Phone_Valid_NoError()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.PhoneNumber))!;
        var config = ValidationService.BuildValidationConfig(prop);
        var field = BuildField(prop, "PhoneNumber", "Phone", config);

        var errors = ValidationService.ValidateField(field, "+1 (555) 123-4567");

        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateField_RegexPattern_Invalid_ReturnsError()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.Code))!;
        var config = ValidationService.BuildValidationConfig(prop);
        var field = BuildField(prop, "Code", "Code", config);

        var errors = ValidationService.ValidateField(field, "invalid");

        Assert.Single(errors);
        Assert.Contains("XXX-0000", errors[0]);
    }

    [Fact]
    public void ValidateField_RegexPattern_Valid_NoError()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.Code))!;
        var config = ValidationService.BuildValidationConfig(prop);
        var field = BuildField(prop, "Code", "Code", config);

        var errors = ValidationService.ValidateField(field, "ABC-1234");

        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateField_NullValue_SkipsValidation()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.Email))!;
        var config = ValidationService.BuildValidationConfig(prop);
        var field = BuildField(prop, "Email", "Email", config);

        var errors = ValidationService.ValidateField(field, null);

        Assert.Empty(errors);
    }

    [Fact]
    public void ValidateEntity_CrossFieldExpression_Invalid_ReturnsError()
    {
        // Arrange
        DataScaffold.RegisterEntity<DateRangeEntity>();
        var meta = DataScaffold.GetEntityByType(typeof(DateRangeEntity))!;
        var instance = new DateRangeEntity
        {
            Key = 1,
            StartDate = new DateTime(2024, 6, 1),
            EndDate = new DateTime(2024, 1, 1) // Before start
        };

        // Act
        var result = ValidationService.ValidateEntity(meta, instance);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains("End date must be after start date", result.EntityErrors);
    }

    [Fact]
    public void ValidateEntity_CrossFieldExpression_Valid_NoError()
    {
        // Arrange
        DataScaffold.RegisterEntity<DateRangeEntity>();
        var meta = DataScaffold.GetEntityByType(typeof(DateRangeEntity))!;
        var instance = new DateRangeEntity
        {
            Key = 2,
            StartDate = new DateTime(2024, 1, 1),
            EndDate = new DateTime(2024, 6, 1) // After start
        };

        // Act
        var result = ValidationService.ValidateEntity(meta, instance);

        // Assert
        Assert.True(result.IsValid);
    }

    [Fact]
    public void BuildValidationConfig_NoAttributes_ReturnsNull()
    {
        var prop = typeof(BaseDataObject).GetProperty(nameof(BaseDataObject.Key))!;
        var config = ValidationService.BuildValidationConfig(prop);
        Assert.Null(config);
    }

    [Fact]
    public void BuildValidationConfig_WithAttributes_PopulatesConfig()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.Name))!;
        var config = ValidationService.BuildValidationConfig(prop);

        Assert.NotNull(config);
        Assert.Equal(2, config!.MinLength);
        Assert.Equal(50, config.MaxLength);
    }

    [Fact]
    public void BuildValidationConfig_RangeAttribute_PopulatesMinMax()
    {
        var prop = typeof(ValidatedEntity).GetProperty(nameof(ValidatedEntity.Score))!;
        var config = ValidationService.BuildValidationConfig(prop);

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

    private static DataFieldMetadata BuildField(PropertyInfo prop, string name, string label, ValidationConfig? validation)
    {
        return new DataFieldMetadata(
            prop, name, label, FormFieldType.String, 0, false,
            true, true, true, true, false, null, null,
            IdGenerationStrategy.None, null, null, null, validation
        );
    }
}
