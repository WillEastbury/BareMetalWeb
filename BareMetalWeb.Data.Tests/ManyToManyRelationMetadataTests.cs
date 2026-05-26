using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class ManyToManyRelationMetadataTests
{
    [Fact]
    public void BuildManyToManyMappingEntity_CreatesHiddenLookupMappingMetadata()
    {
        var source = Entity("Investigators", "investigators");
        var target = Entity("Capabilities", "capabilities");
        var relation = new ManyToManyRelationConfig(
            RelationName: "Investigator Capabilities",
            Source: source,
            Target: target,
            MappingSlug: "investigator-capabilities",
            SourceField: "InvestigatorId",
            TargetField: "CapabilityId",
            SourceDisplayField: "Name",
            TargetDisplayField: "Name");

        var mapping = DataScaffold.BuildManyToManyMappingEntity(relation);

        Assert.False(mapping.ShowOnNav);
        Assert.Equal("investigator-capabilities", mapping.Slug);
        Assert.Equal(source.Permissions, mapping.Permissions);
        Assert.Equal("InvestigatorId", mapping.ParentField?.Name);
        Assert.Equal(2, mapping.Fields.Count);
        Assert.All(mapping.Fields, f => Assert.Equal(FormFieldType.LookupList, f.FieldType));
        Assert.Equal("investigators", mapping.Fields[0].Lookup?.TargetSlug);
        Assert.Equal("capabilities", mapping.Fields[1].Lookup?.TargetSlug);
    }

    private static DataEntityMetadata Entity(string name, string slug)
    {
        var fields = new[]
        {
            new DataFieldMetadata(
                ClrType: typeof(string),
                Name: "Name",
                Label: "Name",
                FieldType: FormFieldType.String,
                Order: 1,
                Required: true,
                List: true,
                View: true,
                Edit: true,
                Create: true,
                ReadOnly: false,
                Placeholder: null,
                Lookup: null,
                IdGeneration: IdGenerationStrategy.None,
                Computed: null,
                Upload: null,
                Calculated: null,
                Validation: null)
        };
        return new DataEntityMetadata(
            Type: typeof(DataRecord),
            Name: name,
            Slug: slug,
            Permissions: $"{slug}.read",
            ShowOnNav: true,
            NavGroup: null,
            NavOrder: 0,
            IdGeneration: AutoIdStrategy.Sequential,
            ViewType: ViewType.Table,
            ParentField: null,
            Fields: fields,
            Handlers: DataScaffold.BuildStoreHandlers(name, () => new DataRecord(1)),
            Commands: Array.Empty<RemoteCommandMetadata>());
    }
}
