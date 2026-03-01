using System;
using System.Collections.Generic;
using System.Linq;
using BareMetalWeb.Runtime;
using Xunit;

namespace BareMetalWeb.Runtime.Tests;

/// <summary>Tests for <see cref="ActionExpander"/>.</summary>
public class ActionExpanderTests
{
    // ── Helpers ───────────────────────────────────────────────────────────────

    private static RuntimeActionModel MakeAction(
        string name,
        IReadOnlyList<ActionCommand> commands) =>
        new RuntimeActionModel(
            ActionId: "test-id",
            EntityId: "entity-id",
            Name: name,
            Label: name,
            Icon: null,
            Permission: null,
            EnabledWhen: null,
            Operations: Array.Empty<string>(),
            Commands: commands,
            Version: 1);

    private static IReadOnlyDictionary<string, object?> Ctx(params (string k, object? v)[] pairs)
    {
        var d = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in pairs)
            d[k] = v;
        return d;
    }

    // ── SetIf ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Expand_SetIf_TrueCondition_ProducesMutation()
    {
        var action = MakeAction("Resolve", new[]
        {
            // Use numeric comparison that is definitively true
            new SetIfCommand(Order: 1, Condition: "Status == 0", FieldId: "Resolved", ValueExpression: "true")
        });

        var ctx = Ctx(("Status", (object?)0m));
        var envelope = ActionExpander.Expand(action, "tickets", "42", ctx);

        Assert.NotEmpty(envelope.AggregateMutations);
        var mutation = envelope.AggregateMutations[0];
        Assert.Equal("tickets", mutation.AggregateType);
        Assert.Equal("42", mutation.AggregateId);
        Assert.Single(mutation.Changes);
        Assert.Equal("Resolved", mutation.Changes[0].FieldId);
        Assert.Equal(true, mutation.Changes[0].NewValue);
    }

    [Fact]
    public void Expand_SetIf_FalseCondition_ProducesNoMutation()
    {
        var action = MakeAction("Resolve", new[]
        {
            // Use numeric comparison that is definitively false
            new SetIfCommand(Order: 1, Condition: "1 == 2", FieldId: "IsResolved", ValueExpression: "true")
        });

        var ctx = Ctx();
        var envelope = ActionExpander.Expand(action, "tickets", "1", ctx);

        // The primary aggregate entry is always created; no field changes should be present
        Assert.All(envelope.AggregateMutations, m => Assert.Empty(m.Changes));
    }

    [Fact]
    public void Expand_SetIf_EmptyCondition_AlwaysApplies()
    {
        var action = MakeAction("Stamp", new[]
        {
            new SetIfCommand(Order: 1, Condition: "", FieldId: "Processed", ValueExpression: "true")
        });

        var envelope = ActionExpander.Expand(action, "orders", "7", Ctx());

        Assert.Single(envelope.AggregateMutations[0].Changes);
        Assert.Equal("Processed", envelope.AggregateMutations[0].Changes[0].FieldId);
    }

    // ── CalculateAndSetIf ─────────────────────────────────────────────────────

    [Fact]
    public void Expand_CalculateAndSetIf_MarksDerived()
    {
        var action = MakeAction("Compute", new[]
        {
            new CalculateAndSetIfCommand(Order: 1, Condition: "true", FieldId: "Total",
                ValueExpression: "Qty * Price")
        });

        var ctx = Ctx(("Qty", (object?)5m), ("Price", (object?)3m));
        var envelope = ActionExpander.Expand(action, "lines", "3", ctx);

        var change = envelope.AggregateMutations[0].Changes[0];
        Assert.Equal("Total", change.FieldId);
        Assert.Equal(15m, Convert.ToDecimal(change.NewValue));
        Assert.True(change.IsDerived);
    }

    // ── AssertIf ──────────────────────────────────────────────────────────────

    [Fact]
    public void Expand_AssertIf_Fires_WhenConditionTrue()
    {
        var action = MakeAction("Check", new[]
        {
            new AssertIfCommand(Order: 1, Condition: "Balance < 0",
                Code: "NEG_BALANCE", Severity: AssertSeverity.Error,
                Message: "Balance cannot be negative")
        });

        var ctx = Ctx(("Balance", (object?)-10m));
        var envelope = ActionExpander.Expand(action, "accounts", "5", ctx);

        Assert.Single(envelope.Assertions);
        var a = envelope.Assertions[0];
        Assert.True(a.Fired);
        Assert.Equal(AssertSeverity.Error, a.Severity);
        Assert.Equal("NEG_BALANCE", a.Code);
        Assert.False(envelope.IsValid);
        Assert.NotNull(envelope.FirstError);
    }

    [Fact]
    public void Expand_AssertIf_DoesNotFire_WhenConditionFalse()
    {
        var action = MakeAction("Check", new[]
        {
            new AssertIfCommand(Order: 1, Condition: "Balance < 0",
                Code: "NEG_BALANCE", Severity: AssertSeverity.Error,
                Message: "Balance cannot be negative")
        });

        var ctx = Ctx(("Balance", (object?)100m));
        var envelope = ActionExpander.Expand(action, "accounts", "5", ctx);

        Assert.Single(envelope.Assertions);
        Assert.False(envelope.Assertions[0].Fired);
        Assert.True(envelope.IsValid);
        Assert.Null(envelope.FirstError);
    }

    [Fact]
    public void Expand_AssertWarning_DoesNotInvalidateEnvelope()
    {
        var action = MakeAction("Warn", new[]
        {
            new AssertIfCommand(Order: 1, Condition: "1 == 1",
                Code: "WARN_01", Severity: AssertSeverity.Warning, Message: "Just a warning")
        });

        var envelope = ActionExpander.Expand(action, "x", "1", Ctx());

        Assert.True(envelope.Assertions[0].Fired);
        Assert.True(envelope.IsValid); // warnings don't block commit
    }

    // ── Command ordering ──────────────────────────────────────────────────────

    [Fact]
    public void Expand_Commands_ExecutedInOrderAscending()
    {
        // SetIf at order=2 depends on value set by order=1
        var action = MakeAction("Chain", new ActionCommand[]
        {
            new SetIfCommand(Order: 2, Condition: "Step1Done == true",
                FieldId: "Step2Done", ValueExpression: "true"),
            new SetIfCommand(Order: 1, Condition: "true",
                FieldId: "Step1Done", ValueExpression: "true")
        });

        var ctx = Ctx(("Step1Done", (object?)false));
        var envelope = ActionExpander.Expand(action, "items", "1", ctx);

        var changes = envelope.AggregateMutations[0].Changes;
        Assert.Equal(2, changes.Count);
        Assert.Contains(changes, c => c.FieldId == "Step1Done");
        Assert.Contains(changes, c => c.FieldId == "Step2Done");
    }

    // ── TransactionEnvelope properties ────────────────────────────────────────

    [Fact]
    public void Expand_TransactionId_IsUnique()
    {
        var action = MakeAction("Noop", Array.Empty<ActionCommand>());
        var e1 = ActionExpander.Expand(action, "x", "1", Ctx());
        var e2 = ActionExpander.Expand(action, "x", "1", Ctx());
        Assert.NotEqual(e1.TransactionId, e2.TransactionId);
    }

    [Fact]
    public void Expand_EmptyAction_ProducesEmptyMutationList()
    {
        var action = MakeAction("Noop", Array.Empty<ActionCommand>());
        var envelope = ActionExpander.Expand(action, "things", "99", Ctx());
        Assert.All(envelope.AggregateMutations, m => Assert.Empty(m.Changes));
        Assert.Empty(envelope.Assertions);
        Assert.True(envelope.IsValid);
    }
}
