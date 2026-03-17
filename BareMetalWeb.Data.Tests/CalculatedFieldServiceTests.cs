using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.ExpressionEngine;
using Xunit;

namespace BareMetalWeb.Data.Tests;

[DataEntity("Calculated Test", Slug = "calculatedtest")]
public class CalculatedTestEntity : BaseDataObject
{
    [DataField] public int Quantity { get; set; }
    [DataField] public decimal UnitPrice { get; set; }
    [DataField] public decimal DiscountPercent { get; set; }

    [DataField]
    [CalculatedField(Expression = "Quantity * UnitPrice")]
    public decimal Subtotal { get; set; }

    [DataField]
    [CalculatedField(Expression = "Subtotal * (1 - DiscountPercent / 100)")]
    public decimal LineTotal { get; set; }
}

[DataEntity("Circular Test", Slug = "circulartest")]
public class CircularTestEntity : BaseDataObject
{
    [DataField]
    [CalculatedField(Expression = "B + 1")]
    public decimal A { get; set; }

    [DataField]
    [CalculatedField(Expression = "A + 1")]
    public decimal B { get; set; }
}

[DataEntity("Independent Test", Slug = "independenttest")]
public class IndependentFieldsTestEntity : BaseDataObject
{
    [DataField] public decimal Price { get; set; }
    [DataField] public decimal Tax { get; set; }

    [DataField]
    [CalculatedField(Expression = "Price * 1.1")]
    public decimal PriceWithMarkup { get; set; }

    [DataField]
    [CalculatedField(Expression = "Price * Tax")]
    public decimal TaxAmount { get; set; }
}

public class CalculatedFieldServiceTests
{
    public CalculatedFieldServiceTests()
    {
        DataScaffold.RegisterEntity<CalculatedTestEntity>();
        DataScaffold.RegisterEntity<CircularTestEntity>();
        DataScaffold.RegisterEntity<IndependentFieldsTestEntity>();
    }

    [Fact]
    public void EvaluateCalculatedFields_SimpleCalculation_ComputesCorrectValue()
    {
        var entity = new CalculatedTestEntity
        {
            Quantity = 5,
            UnitPrice = 10.50m,
            DiscountPercent = 0
        };

        CalculatedFieldService.EvaluateCalculatedFields(entity);

        Assert.Equal(52.5m, entity.Subtotal);
        Assert.Equal(52.5m, entity.LineTotal);
    }

    [Fact]
    public void EvaluateCalculatedFields_WithDiscount_AppliesCorrectly()
    {
        var entity = new CalculatedTestEntity
        {
            Quantity = 10,
            UnitPrice = 20m,
            DiscountPercent = 10m
        };

        CalculatedFieldService.EvaluateCalculatedFields(entity);

        Assert.Equal(200m, entity.Subtotal);  // 10 * 20
        Assert.Equal(180m, entity.LineTotal);  // 200 * (1 - 10/100) = 200 * 0.9
    }

    [Fact]
    public void EvaluateCalculatedFields_DependencyChain_EvaluatesInCorrectOrder()
    {
        var entity = new CalculatedTestEntity
        {
            Quantity = 3,
            UnitPrice = 15m,
            DiscountPercent = 20m
        };

        CalculatedFieldService.EvaluateCalculatedFields(entity);

        // Subtotal depends on Quantity and UnitPrice
        Assert.Equal(45m, entity.Subtotal);
        // LineTotal depends on Subtotal (which was just calculated)
        Assert.Equal(36m, entity.LineTotal);  // 45 * (1 - 20/100) = 45 * 0.8
    }

    [Fact]
    public void ValidateNoCycles_WithCircularDependency_ThrowsException()
    {
        Assert.Throws<InvalidOperationException>(() =>
        {
            CalculatedFieldService.ValidateNoCycles(typeof(CircularTestEntity));
        });
    }

    [Fact]
    public void ValidateNoCycles_WithoutCircularDependency_DoesNotThrow()
    {
        var exception = Record.Exception(() =>
        {
            CalculatedFieldService.ValidateNoCycles(typeof(CalculatedTestEntity));
        });

        Assert.Null(exception);
    }

    [Fact]
    public void GetDependencies_ReturnsCorrectFieldNames()
    {
        var deps = CalculatedFieldService.GetDependencies(typeof(CalculatedTestEntity), "Subtotal");

        Assert.Contains("Quantity", deps);
        Assert.Contains("UnitPrice", deps);
        Assert.Equal(2, deps.Count);
    }

    [Fact]
    public void GetDependencies_ForDependentField_IncludesOnlyDirectDependencies()
    {
        var deps = CalculatedFieldService.GetDependencies(typeof(CalculatedTestEntity), "LineTotal");

        Assert.Contains("Subtotal", deps);
        Assert.Contains("DiscountPercent", deps);
        Assert.Equal(2, deps.Count);
    }

    [Fact]
    public void EvaluateCalculatedFields_IndependentFields_ComputesBoth()
    {
        var entity = new IndependentFieldsTestEntity
        {
            Price = 100m,
            Tax = 0.08m
        };

        CalculatedFieldService.EvaluateCalculatedFields(entity);

        Assert.Equal(110m, entity.PriceWithMarkup);  // 100 * 1.1
        Assert.Equal(8m, entity.TaxAmount);  // 100 * 0.08
    }

    [Fact]
    public void GenerateJavaScript_ProducesValidJavaScriptCode()
    {
        var js = CalculatedFieldService.GenerateJavaScript(typeof(CalculatedTestEntity));

        Assert.Contains("Subtotal", js);
        Assert.Contains("LineTotal", js);
        Assert.Contains("updateCalculatedField", js);
        Assert.Contains("parseFieldValue", js);
    }

    [Fact]
    public void GetCompiledExpression_CachesResults()
    {
        var expr1 = CalculatedFieldService.GetCompiledExpression("2 + 2");
        var expr2 = CalculatedFieldService.GetCompiledExpression("2 + 2");

        // Should return the same cached instance
        Assert.Same(expr1, expr2);
    }

    [Fact]
    public void EvaluateCalculatedFields_WithZeroValues_HandlesCorrectly()
    {
        var entity = new CalculatedTestEntity
        {
            Quantity = 0,
            UnitPrice = 0,
            DiscountPercent = 0
        };

        CalculatedFieldService.EvaluateCalculatedFields(entity);

        Assert.Equal(0m, entity.Subtotal);
        Assert.Equal(0m, entity.LineTotal);
    }

    [Fact]
    public void EvaluateCalculatedFields_WithDecimalPrecision_MaintainsPrecision()
    {
        var entity = new CalculatedTestEntity
        {
            Quantity = 3,
            UnitPrice = 10.333333m,
            DiscountPercent = 5.5m
        };

        CalculatedFieldService.EvaluateCalculatedFields(entity);

        Assert.Equal(30.999999m, entity.Subtotal);
        // 30.999999 * (1 - 5.5/100) = 30.999999 * 0.945
        Assert.Equal(29.294999055m, entity.LineTotal);
    }
}
