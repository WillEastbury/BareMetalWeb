using BareMetalWeb.Data.ExpressionEngine;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class ExpressionParserTests
{
    [Theory]
    [InlineData("5", 5)]
    [InlineData("3.14", 3.14)]
    [InlineData("-10", -10)]
    [InlineData("+42", 42)]
    public void Parse_SimpleLiteral_ReturnsCorrectValue(string expression, decimal expected)
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse(expression);
        var result = ast.Evaluate(new Dictionary<string, object?>());
        
        Assert.Equal(expected, Convert.ToDecimal(result));
    }

    [Theory]
    [InlineData("2 + 3", 5)]
    [InlineData("10 - 4", 6)]
    [InlineData("5 * 6", 30)]
    [InlineData("20 / 4", 5)]
    [InlineData("17 % 5", 2)]
    public void Parse_SimpleArithmetic_ReturnsCorrectValue(string expression, decimal expected)
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse(expression);
        var result = ast.Evaluate(new Dictionary<string, object?>());
        
        Assert.Equal(expected, Convert.ToDecimal(result));
    }

    [Theory]
    [InlineData("2 + 3 * 4", 14)]  // Multiplication before addition
    [InlineData("(2 + 3) * 4", 20)]  // Parentheses override precedence
    [InlineData("10 - 3 - 2", 5)]  // Left-to-right
    [InlineData("100 / 10 / 2", 5)]  // Left-to-right
    public void Parse_ComplexArithmetic_RespectsOperatorPrecedence(string expression, decimal expected)
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse(expression);
        var result = ast.Evaluate(new Dictionary<string, object?>());
        
        Assert.Equal(expected, Convert.ToDecimal(result));
    }

    [Fact]
    public void Parse_FieldReference_ReturnsFieldValue()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("Quantity");
        var context = new Dictionary<string, object?>
        {
            ["Quantity"] = 10
        };
        
        var result = ast.Evaluate(context);
        
        Assert.Equal(10, Convert.ToInt32(result));
    }

    [Fact]
    public void Parse_FieldsInExpression_EvaluatesCorrectly()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("Quantity * UnitPrice");
        var context = new Dictionary<string, object?>
        {
            ["Quantity"] = 5,
            ["UnitPrice"] = 10.50m
        };
        
        var result = ast.Evaluate(context);
        
        Assert.Equal(52.5m, Convert.ToDecimal(result));
    }

    [Fact]
    public void Parse_ComplexCalculation_WithMultipleFields()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("Subtotal * (1 - DiscountPercent / 100)");
        var context = new Dictionary<string, object?>
        {
            ["Subtotal"] = 100m,
            ["DiscountPercent"] = 10m
        };
        
        var result = ast.Evaluate(context);
        
        Assert.Equal(90m, Convert.ToDecimal(result));
    }

    [Theory]
    [InlineData("Round(3.14159, 2)", 3.14)]
    [InlineData("Round(3.5)", 4)]
    [InlineData("Round(3.14159, 0)", 3)]
    public void Parse_RoundFunction_ReturnsCorrectValue(string expression, decimal expected)
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse(expression);
        var result = ast.Evaluate(new Dictionary<string, object?>());
        
        Assert.Equal(expected, Convert.ToDecimal(result));
    }

    [Theory]
    [InlineData("Min(5, 10)", 5)]
    [InlineData("Min(20, 15)", 15)]
    [InlineData("Min(3, 7, 2, 9)", 2)]
    public void Parse_MinFunction_ReturnsMinimumValue(string expression, decimal expected)
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse(expression);
        var result = ast.Evaluate(new Dictionary<string, object?>());
        
        Assert.Equal(expected, Convert.ToDecimal(result));
    }

    [Theory]
    [InlineData("Max(5, 10)", 10)]
    [InlineData("Max(20, 15)", 20)]
    [InlineData("Max(3, 7, 2, 9)", 9)]
    public void Parse_MaxFunction_ReturnsMaximumValue(string expression, decimal expected)
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse(expression);
        var result = ast.Evaluate(new Dictionary<string, object?>());
        
        Assert.Equal(expected, Convert.ToDecimal(result));
    }

    [Theory]
    [InlineData("Abs(-5)", 5)]
    [InlineData("Abs(7)", 7)]
    [InlineData("Abs(0)", 0)]
    public void Parse_AbsFunction_ReturnsAbsoluteValue(string expression, decimal expected)
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse(expression);
        var result = ast.Evaluate(new Dictionary<string, object?>());
        
        Assert.Equal(expected, Convert.ToDecimal(result));
    }

    [Fact]
    public void Parse_IfFunction_TrueCondition_ReturnsTrueValue()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("If(10 > 5, 100, 200)");
        var result = ast.Evaluate(new Dictionary<string, object?>());
        
        Assert.Equal(100, Convert.ToInt32(result));
    }

    [Fact]
    public void Parse_IfFunction_FalseCondition_ReturnsFalseValue()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("If(3 > 5, 100, 200)");
        var result = ast.Evaluate(new Dictionary<string, object?>());
        
        Assert.Equal(200, Convert.ToInt32(result));
    }

    [Fact]
    public void Parse_StringConcatenation_CombinesStrings()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("'Hello' + ' ' + 'World'");
        var result = ast.Evaluate(new Dictionary<string, object?>());
        
        Assert.Equal("Hello World", result?.ToString());
    }

    [Fact]
    public void Parse_StringWithFields_ConcatenatesCorrectly()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("FirstName + ' ' + LastName");
        var context = new Dictionary<string, object?>
        {
            ["FirstName"] = "John",
            ["LastName"] = "Doe"
        };
        
        var result = ast.Evaluate(context);
        
        Assert.Equal("John Doe", result?.ToString());
    }

    [Fact]
    public void ToJavaScript_SimpleExpression_GeneratesValidJS()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("Quantity * UnitPrice");
        var js = ast.ToJavaScript();
        
        Assert.Contains("parseFieldValue('Quantity')", js);
        Assert.Contains("parseFieldValue('UnitPrice')", js);
        Assert.Contains("*", js);
    }

    [Fact]
    public void ToJavaScript_RoundFunction_GeneratesCorrectCall()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("Round(Subtotal, 2)");
        var js = ast.ToJavaScript();
        
        Assert.Contains("roundNumber", js);
        Assert.Contains("2", js);
    }

    [Fact]
    public void Parse_EmptyExpression_ThrowsException()
    {
        var parser = new ExpressionParser();
        
        Assert.Throws<ArgumentException>(() => parser.Parse(""));
    }

    [Fact]
    public void Parse_InvalidSyntax_ThrowsException()
    {
        var parser = new ExpressionParser();
        
        Assert.Throws<InvalidOperationException>(() => parser.Parse("5 +"));
    }
}
