using System.Linq;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Runtime;
using Xunit;

namespace BareMetalWeb.Runtime.Tests;

/// <summary>Tests for <see cref="DomainEventSubscription"/> entity registration and metadata.</summary>
public class DomainEventSubscriptionTests
{
    // ── Slug ─────────────────────────────────────────────────────────────────

    [Fact]
    public void DomainEventSubscription_HasCorrectSlug()
    {
        DataScaffold.RegisterEntity<DomainEventSubscription>();
        var meta = DataScaffold.GetEntityByType(typeof(DomainEventSubscription))!;

        Assert.Equal("domain-event-subscriptions", meta.Slug);
    }

    // ── Field presence ───────────────────────────────────────────────────────

    [Theory]
    [InlineData("Name")]
    [InlineData("SourceEntity")]
    [InlineData("WatchField")]
    [InlineData("FromValue")]
    [InlineData("TriggerValue")]
    [InlineData("TargetAction")]
    [InlineData("TargetResolution")]
    [InlineData("Priority")]
    [InlineData("Enabled")]
    public void DomainEventSubscription_HasExpectedField(string fieldName)
    {
        var prop = typeof(DomainEventSubscription).GetProperty(fieldName);
        Assert.NotNull(prop);
    }

    // ── Default values ───────────────────────────────────────────────────────

    [Fact]
    public void DomainEventSubscription_DefaultTargetResolution_IsSelf()
    {
        var sub = new DomainEventSubscription();
        Assert.Equal("self", sub.TargetResolution);
    }

    [Fact]
    public void DomainEventSubscription_DefaultPriority_Is100()
    {
        var sub = new DomainEventSubscription();
        Assert.Equal(100, sub.Priority);
    }

    [Fact]
    public void DomainEventSubscription_DefaultEnabled_IsTrue()
    {
        var sub = new DomainEventSubscription();
        Assert.True(sub.Enabled);
    }

    // ── ToString ──────────────────────────────────────────────────────────────

    [Fact]
    public void DomainEventSubscription_ToString_ReturnsName()
    {
        var sub = new DomainEventSubscription { Name = "Large Order Approval" };
        Assert.Equal("Large Order Approval", sub.ToString());
    }

    // ── MetadataExtractor ─────────────────────────────────────────────────────

    [Fact]
    public void MetadataExtractor_BuildFromMetadata_ProducesEntityDef()
    {
        DataScaffold.RegisterEntity<DomainEventSubscription>();
        var meta = DataScaffold.GetEntityByType(typeof(DomainEventSubscription))!;
        var (entityDef, fields, indexes) = MetadataExtractor.BuildFromMetadata(meta);

        Assert.NotNull(entityDef);
        Assert.Equal("Workflow Rules", entityDef.Name);
        Assert.Equal("domain-event-subscriptions", entityDef.Slug);
        Assert.True(fields.Count >= 9, $"Expected at least 9 fields, got {fields.Count}");
    }

    [Fact]
    public void MetadataExtractor_DomainEventSubscription_NameFieldIsRequired()
    {
        DataScaffold.RegisterEntity<DomainEventSubscription>();
        var meta = DataScaffold.GetEntityByType(typeof(DomainEventSubscription))!;
        var (_, fields, _) = MetadataExtractor.BuildFromMetadata(meta);
        var nameField = fields.FirstOrDefault(f => f.Name == "Name");

        Assert.NotNull(nameField);
        Assert.True(nameField.Required, "Name field should be required");
    }

    [Fact]
    public void MetadataExtractor_DomainEventSubscription_SourceEntityFieldHasLookup()
    {
        DataScaffold.RegisterEntity<DomainEventSubscription>();
        DataScaffold.RegisterEntity<EntityDefinition>();
        var meta = DataScaffold.GetEntityByType(typeof(DomainEventSubscription))!;
        var (_, fields, _) = MetadataExtractor.BuildFromMetadata(meta);
        var sourceField = fields.FirstOrDefault(f => f.Name == "SourceEntity");

        Assert.NotNull(sourceField);
        Assert.True(sourceField.Required, "SourceEntity field should be required");
        // Should have a lookup pointing to EntityDefinition
        Assert.False(string.IsNullOrEmpty(sourceField.LookupEntitySlug),
            "SourceEntity should have a lookup entity slug");
    }

    // ── SamplePackage ─────────────────────────────────────────────────────────

    [Fact]
    public void SamplePackage_HasWorkflowRulesCollection()
    {
        var pkg = new SamplePackage();
        Assert.NotNull(pkg.WorkflowRules);
        Assert.Empty(pkg.WorkflowRules);
    }

    [Fact]
    public void SamplePackage_CanAddWorkflowRule()
    {
        var pkg = new SamplePackage();
        var rule = new DomainEventSubscription
        {
            Name = "Status change rule",
            SourceEntity = "order",
            WatchField = "Status",
            TriggerValue = "Approved",
            TargetAction = "SendApprovalEmail",
            TargetResolution = "self",
            Enabled = true
        };

        pkg.WorkflowRules.Add(rule);

        Assert.Single(pkg.WorkflowRules);
        Assert.Equal("Status change rule", pkg.WorkflowRules[0].Name);
        Assert.Equal("order", pkg.WorkflowRules[0].SourceEntity);
    }
}
