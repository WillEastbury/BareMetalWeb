using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class EntitySchemaTests
{
    // ── Builder + parallel arrays ──────────────────────────────────────────

    [Fact]
    public void Builder_CreatesCorrectParallelArrays()
    {
        var schema = BuildCustomerSchema();

        Assert.Equal("Customer", schema.EntityName);
        Assert.Equal("customers", schema.Slug);
        Assert.Equal(4, schema.FieldCount);

        // Names
        Assert.Equal("Name", schema.Names[0]);
        Assert.Equal("Email", schema.Names[1]);
        Assert.Equal("Age", schema.Names[2]);
        Assert.Equal("Active", schema.Names[3]);

        // Types
        Assert.Equal(FieldType.StringUtf8, schema.Types[0]);
        Assert.Equal(FieldType.StringUtf8, schema.Types[1]);
        Assert.Equal(FieldType.Int32, schema.Types[2]);
        Assert.Equal(FieldType.Bool, schema.Types[3]);

        // CLR types
        Assert.Equal(typeof(string), schema.ClrTypes[0]);
        Assert.Equal(typeof(string), schema.ClrTypes[1]);
        Assert.Equal(typeof(int?), schema.ClrTypes[2]);
        Assert.Equal(typeof(bool), schema.ClrTypes[3]);
    }

    [Fact]
    public void Builder_PreservesFlags()
    {
        var schema = BuildCustomerSchema();

        // Name: required
        Assert.True(schema.IsRequired[0]);
        Assert.False(schema.IsNullable[0]);
        Assert.False(schema.IsIndexed[0]);

        // Email: required + indexed
        Assert.True(schema.IsRequired[1]);
        Assert.True(schema.IsIndexed[1]);

        // Age: nullable
        Assert.True(schema.IsNullable[2]);
        Assert.False(schema.IsRequired[2]);

        // Active: none
        Assert.False(schema.IsNullable[3]);
        Assert.False(schema.IsRequired[3]);
    }

    [Fact]
    public void Builder_MaxLengths()
    {
        var schema = BuildCustomerSchema();

        Assert.Equal(100, schema.MaxLengths[0]);
        Assert.Equal(255, schema.MaxLengths[1]);
        Assert.Equal(0, schema.MaxLengths[2]);
        Assert.Equal(0, schema.MaxLengths[3]);
    }

    // ── Name → ordinal lookup ──────────────────────────────────────────────

    [Fact]
    public void TryGetOrdinal_ExistingField_ReturnsTrue()
    {
        var schema = BuildCustomerSchema();

        Assert.True(schema.TryGetOrdinal("Name", out var ord));
        Assert.Equal(0, ord);

        Assert.True(schema.TryGetOrdinal("Active", out ord));
        Assert.Equal(3, ord);
    }

    [Fact]
    public void TryGetOrdinal_CaseInsensitive()
    {
        var schema = BuildCustomerSchema();

        Assert.True(schema.TryGetOrdinal("name", out var ord1));
        Assert.True(schema.TryGetOrdinal("NAME", out var ord2));
        Assert.True(schema.TryGetOrdinal("eMaIl", out var ord3));

        Assert.Equal(0, ord1);
        Assert.Equal(0, ord2);
        Assert.Equal(1, ord3);
    }

    [Fact]
    public void TryGetOrdinal_MissingField_ReturnsFalse()
    {
        var schema = BuildCustomerSchema();

        Assert.False(schema.TryGetOrdinal("DoesNotExist", out _));
    }

    // ── Accessors ──────────────────────────────────────────────────────────

    [Fact]
    public void NameAt_ReturnsCorrectName()
    {
        var schema = BuildCustomerSchema();
        Assert.Equal("Email", schema.NameAt(1));
    }

    [Fact]
    public void TypeAt_ReturnsCorrectType()
    {
        var schema = BuildCustomerSchema();
        Assert.Equal(FieldType.Int32, schema.TypeAt(2));
    }

    // ── Schema hash ────────────────────────────────────────────────────────

    [Fact]
    public void SchemaHash_DeterministicForSameFields()
    {
        var schema1 = BuildCustomerSchema();
        var schema2 = BuildCustomerSchema();

        Assert.Equal(schema1.SchemaHash, schema2.SchemaHash);
    }

    [Fact]
    public void SchemaHash_DiffersForDifferentFields()
    {
        var schema1 = BuildCustomerSchema();
        var schema2 = new EntitySchema.Builder("Customer", "customers")
            .AddField("Name", FieldType.StringUtf8, typeof(string))
            .AddField("Phone", FieldType.StringUtf8, typeof(string)) // different field
            .Build();

        Assert.NotEqual(schema1.SchemaHash, schema2.SchemaHash);
    }

    [Fact]
    public void SchemaHash_DiffersForDifferentTypes()
    {
        var schema1 = new EntitySchema.Builder("Test", "test")
            .AddField("Value", FieldType.Int32, typeof(int))
            .Build();
        var schema2 = new EntitySchema.Builder("Test", "test")
            .AddField("Value", FieldType.StringUtf8, typeof(string))
            .Build();

        Assert.NotEqual(schema1.SchemaHash, schema2.SchemaHash);
    }

    // ── CreateRecord ───────────────────────────────────────────────────────

    [Fact]
    public void CreateRecord_SizedCorrectly()
    {
        var schema = BuildCustomerSchema();
        var record = schema.CreateRecord();

        Assert.Equal(4, record.FieldCount);
        Assert.Equal("Customer", record.EntityTypeName);
    }

    // ── FieldPlanDescriptor builder ────────────────────────────────────────

    [Fact]
    public void BuildFieldPlanDescriptors_CorrectCount()
    {
        var schema = BuildCustomerSchema();
        var descriptors = schema.BuildFieldPlanDescriptors();

        // 8 base properties + 4 schema fields = 12
        Assert.Equal(12, descriptors.Length);
        // Base properties come first (__Key, __CreatedOnUtc, etc.)
        Assert.Equal("__Key", descriptors[0].Name);
        // Schema fields start at index 8
        Assert.Equal("Name", descriptors[8].Name);
        Assert.Equal("Email", descriptors[9].Name);
        Assert.Equal("Age", descriptors[10].Name);
        Assert.Equal("Active", descriptors[11].Name);
    }

    [Fact]
    public void BuildFieldPlanDescriptors_ClosuresReadWrite()
    {
        var schema = BuildCustomerSchema();
        var descriptors = schema.BuildFieldPlanDescriptors();
        var record = schema.CreateRecord();

        // Schema fields start at offset 8
        descriptors[8].Setter(record, "Alice");
        descriptors[9].Setter(record, "alice@example.com");
        descriptors[10].Setter(record, 30);
        descriptors[11].Setter(record, true);

        Assert.Equal("Alice", descriptors[8].Getter(record));
        Assert.Equal("alice@example.com", descriptors[9].Getter(record));
        Assert.Equal(30, descriptors[10].Getter(record));
        Assert.Equal(true, descriptors[11].Getter(record));

        // Verify ordinal path matches
        Assert.Equal("Alice", record.GetValue(0));
        Assert.Equal(30, record.GetValue(2));

        // Base property closures work too
        descriptors[0].Setter(record, 42u); // __Key
        Assert.Equal(42u, descriptors[0].Getter(record));
        Assert.Equal(42u, record.Key);
    }

    [Fact]
    public void BuildFieldPlanDescriptors_ClosuresAreIndependent()
    {
        var schema = BuildCustomerSchema();
        var descriptors = schema.BuildFieldPlanDescriptors();

        var rec1 = schema.CreateRecord();
        var rec2 = schema.CreateRecord();

        // Schema fields at offset 8
        descriptors[8].Setter(rec1, "Alice");
        descriptors[8].Setter(rec2, "Bob");

        Assert.Equal("Alice", descriptors[8].Getter(rec1));
        Assert.Equal("Bob", descriptors[8].Getter(rec2));
    }

    // ── Ordinal stability ──────────────────────────────────────────────────

    [Fact]
    public void OrdinalStability_FieldsGetSequentialOrdinals()
    {
        var schema = BuildCustomerSchema();

        // Ordinals are 0-based, sequential, matching insertion order
        Assert.True(schema.TryGetOrdinal("Name", out var o0));
        Assert.True(schema.TryGetOrdinal("Email", out var o1));
        Assert.True(schema.TryGetOrdinal("Age", out var o2));
        Assert.True(schema.TryGetOrdinal("Active", out var o3));

        Assert.Equal(0, o0);
        Assert.Equal(1, o1);
        Assert.Equal(2, o2);
        Assert.Equal(3, o3);
    }

    // ── Empty schema ───────────────────────────────────────────────────────

    [Fact]
    public void EmptySchema_IsValid()
    {
        var schema = new EntitySchema.Builder("Empty", "empty").Build();

        Assert.Equal(0, schema.FieldCount);
        Assert.Empty(schema.Names);
        Assert.False(schema.TryGetOrdinal("anything", out _));
    }

    [Fact]
    public void EmptySchema_CreateRecord_HasZeroFields()
    {
        var schema = new EntitySchema.Builder("Empty", "empty").Build();
        var record = schema.CreateRecord();
        Assert.Equal(0, record.FieldCount);
    }

    // ── Scanning parallel arrays ───────────────────────────────────────────

    [Fact]
    public void ParallelArrayScan_FindIndexedFields()
    {
        var schema = BuildCustomerSchema();
        var indexedFields = new List<string>();

        for (int i = 0; i < schema.FieldCount; i++)
        {
            if (schema.IsIndexed[i])
                indexedFields.Add(schema.Names[i]);
        }

        Assert.Single(indexedFields);
        Assert.Equal("Email", indexedFields[0]);
    }

    [Fact]
    public void ParallelArrayScan_FindRequiredFields()
    {
        var schema = BuildCustomerSchema();
        var required = new List<string>();

        for (int i = 0; i < schema.FieldCount; i++)
        {
            if (schema.IsRequired[i])
                required.Add(schema.Names[i]);
        }

        Assert.Equal(2, required.Count);
        Assert.Contains("Name", required);
        Assert.Contains("Email", required);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static EntitySchema BuildCustomerSchema()
    {
        return new EntitySchema.Builder("Customer", "customers")
            .AddField("Name", FieldType.StringUtf8, typeof(string), required: true, maxLength: 100)
            .AddField("Email", FieldType.StringUtf8, typeof(string), required: true, indexed: true, maxLength: 255)
            .AddField("Age", FieldType.Int32, typeof(int?), nullable: true)
            .AddField("Active", FieldType.Bool, typeof(bool))
            .Build();
    }
}
