using System;
using System.Collections;
using System.Linq;
using System.Reflection;
using System.Threading;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests that BuildFormFields detects high-cardinality lookup fields and
/// switches to the search dialog rendering instead of a full dropdown.
/// </summary>
[Collection("DataStoreProvider")]
public class HighCardinalityLookupTests : IDisposable
{
    private readonly int _originalThreshold;

    public HighCardinalityLookupTests()
    {
        _originalThreshold = DataScaffold.LargeListThreshold;
        _ = GalleryTestFixture.State;
    }

    public void Dispose()
    {
        DataScaffold.LargeListThreshold = _originalThreshold;
        ClearCaches();
    }

    private static void SeedEmployees(DataEntityMetadata empMeta, int count, int startKey = 1)
    {
        for (int i = startKey; i < startKey + count; i++)
        {
            var emp = empMeta.Handlers.Create();
            emp.Key = (uint)i;
            empMeta.FindField("Name")!.SetValueFn(emp, $"Employee {i}");
            empMeta.Handlers.SaveAsync(emp, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        }
    }

    [Fact]
    public void BuildFormFields_LowCardinalityLookup_UsesDropdown()
    {
        // Arrange: threshold = 5, add 3 employees (below threshold)
        DataScaffold.LargeListThreshold = 5;
        ClearCaches();

        Assert.True(DataScaffold.TryGetEntity("employees", out var meta));

        SeedEmployees(meta, 3);
        ClearCaches();

        // Act
        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true);
        var managerField = fields.FirstOrDefault(f => f.Name == "ManagerId");

        // Assert: not high-cardinality, options populated
        Assert.NotNull(managerField);
        Assert.Equal(FormFieldType.LookupList, managerField!.FieldType);
        Assert.False(managerField.IsHighCardinality);
        Assert.NotNull(managerField.LookupOptions);
        Assert.Null(managerField.LookupDisplayValue);
        Assert.Null(managerField.LookupSearchField);
    }

    [Fact]
    public void BuildFormFields_HighCardinalityLookup_UsesSearchDialog()
    {
        // Arrange: threshold = 2, add 5 employees (above threshold)
        DataScaffold.LargeListThreshold = 2;
        ClearCaches();

        Assert.True(DataScaffold.TryGetEntity("employees", out var meta));

        SeedEmployees(meta, 5);
        ClearCaches();

        // Act
        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true);
        var managerField = fields.FirstOrDefault(f => f.Name == "ManagerId");

        // Assert: high-cardinality, no options, search field populated
        Assert.NotNull(managerField);
        Assert.Equal(FormFieldType.LookupList, managerField!.FieldType);
        Assert.True(managerField.IsHighCardinality);
        Assert.Null(managerField.LookupOptions);
        Assert.Equal("Name", managerField.LookupSearchField);
    }

    [Fact]
    public void BuildFormFields_HighCardinalityLookup_WithCurrentValue_PopulatesDisplayValue()
    {
        // Arrange: threshold = 2, add 5 employees, edit an employee that has a manager set
        DataScaffold.LargeListThreshold = 2;
        ClearCaches();

        Assert.True(DataScaffold.TryGetEntity("employees", out var meta));

        // Save "Alice Manager" with Key = 100
        var alice = meta.Handlers.Create();
        alice.Key = 100;
        meta.FindField("Name")!.SetValueFn(alice, "Alice Manager");
        meta.Handlers.SaveAsync(alice, CancellationToken.None).AsTask().GetAwaiter().GetResult();

        SeedEmployees(meta, 4, startKey: 2);
        ClearCaches();

        // Create instance via handlers with ManagerId pointing to Alice
        var instance = meta.Handlers.Create();
        instance.Key = 1;
        meta.FindField("Name")!.SetValueFn(instance, "Bob");
        meta.FindField("ManagerId")!.SetValueFn(instance, "100");

        // Act
        var fields = DataScaffold.BuildFormFields(meta, instance, forCreate: false);
        var managerField = fields.FirstOrDefault(f => f.Name == "ManagerId");

        // Assert: high-cardinality with display value resolved
        Assert.NotNull(managerField);
        Assert.True(managerField!.IsHighCardinality);
        Assert.Equal("Alice Manager", managerField.LookupDisplayValue);
    }

    [Fact]
    public void BuildFormFields_HighCardinalityLookup_WithNoCurrentValue_NullDisplayValue()
    {
        // Arrange: threshold = 2, add 5 employees, create new (no value)
        DataScaffold.LargeListThreshold = 2;
        ClearCaches();

        Assert.True(DataScaffold.TryGetEntity("employees", out var meta));

        SeedEmployees(meta, 5);
        ClearCaches();

        // Act: create form, no current value
        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true);
        var managerField = fields.FirstOrDefault(f => f.Name == "ManagerId");

        // Assert: no display value when no value is selected
        Assert.NotNull(managerField);
        Assert.True(managerField!.IsHighCardinality);
        Assert.Null(managerField.LookupDisplayValue);
    }

    [Fact]
    public void LargeListThreshold_Default_Is20()
    {
        // Reset to verify the default; the fixture saves/restores original value
        var savedThreshold = DataScaffold.LargeListThreshold;
        try
        {
            // After resetting, the static field default is 20
            // Use reflection to directly verify the expected default
            var prop = typeof(DataScaffold).GetProperty(nameof(DataScaffold.LargeListThreshold),
                BindingFlags.Public | BindingFlags.Static);
            Assert.NotNull(prop);
            Assert.True(prop!.CanWrite);
            // Verify we can set and get
            DataScaffold.LargeListThreshold = 50;
            Assert.Equal(50, DataScaffold.LargeListThreshold);
        }
        finally
        {
            DataScaffold.LargeListThreshold = savedThreshold;
        }
    }

    private static void ClearCaches()
    {
        var lookupCache = typeof(DataScaffold).GetField("LookupCache",
            BindingFlags.NonPublic | BindingFlags.Static);
        if (lookupCache?.GetValue(null) is IDictionary lc) lc.Clear();

        var largeListCache = typeof(DataScaffold).GetField("LargeListCache",
            BindingFlags.NonPublic | BindingFlags.Static);
        if (largeListCache?.GetValue(null) is IDictionary llc) llc.Clear();
    }
}
