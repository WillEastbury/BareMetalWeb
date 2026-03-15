using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Intelligence.Tests;

public class IntentClassifierTests
{
    // ── Null / empty ────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Classify_NullOrEmpty_ReturnsNull(string? input)
    {
        var result = IntentClassifier.Classify(input!);
        Assert.Null(result);
    }

    // ── Greetings ───────────────────────────────────────────────────────────

    [Theory]
    [InlineData("hello")]
    [InlineData("hi")]
    [InlineData("hey")]
    [InlineData("Hello there")]
    [InlineData("Hi, how are you")]
    [InlineData("good morning")]
    public void Classify_Greeting_ReturnsGreetingIntent(string input)
    {
        var result = IntentClassifier.Classify(input);
        Assert.NotNull(result);
        Assert.Equal("greeting", result!.Intent);
        Assert.True(result.Confidence >= 0.9f);
    }

    // ── Farewells ───────────────────────────────────────────────────────────

    [Theory]
    [InlineData("bye")]
    [InlineData("goodbye")]
    [InlineData("see you")]
    [InlineData("farewell")]
    public void Classify_Farewell_ReturnsFarewellIntent(string input)
    {
        var result = IntentClassifier.Classify(input);
        Assert.NotNull(result);
        Assert.Equal("farewell", result!.Intent);
    }

    // ── Help ────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("help")]
    [InlineData("?")]
    [InlineData("what can you do")]
    [InlineData("commands")]
    public void Classify_Help_ReturnsHelpIntent(string input)
    {
        var result = IntentClassifier.Classify(input);
        Assert.NotNull(result);
        Assert.Equal("help", result!.Intent);
    }

    // ── System / index status ───────────────────────────────────────────────

    [Theory]
    [InlineData("system status")]
    [InlineData("diagnostics")]
    [InlineData("memory usage")]
    public void Classify_SystemStatus_ReturnsSystemStatusIntent(string input)
    {
        var result = IntentClassifier.Classify(input);
        Assert.NotNull(result);
        Assert.Equal("system-status", result!.Intent);
    }

    [Theory]
    [InlineData("index status")]
    [InlineData("search index")]
    [InlineData("rebuild index")]
    public void Classify_IndexStatus_ReturnsIndexStatusIntent(string input)
    {
        var result = IntentClassifier.Classify(input);
        Assert.NotNull(result);
        Assert.Equal("index-status", result!.Intent);
    }

    // ── List entities ───────────────────────────────────────────────────────

    [Theory]
    [InlineData("list entities")]
    [InlineData("show entities")]
    [InlineData("list all entities")]
    [InlineData("all entities")]
    public void Classify_ListEntities_ReturnsListEntitiesIntent(string input)
    {
        var result = IntentClassifier.Classify(input);
        Assert.NotNull(result);
        Assert.Equal("list-entities", result!.Intent);
    }

    // ── Create todo ─────────────────────────────────────────────────────────

    [Theory]
    [InlineData("create a todo")]
    [InlineData("create todo")]
    [InlineData("add a todo")]
    [InlineData("new todo")]
    [InlineData("make a new todo")]
    public void Classify_CreateTodo_ReturnsCreateTodoIntent(string input)
    {
        var result = IntentClassifier.Classify(input);
        Assert.NotNull(result);
        Assert.Equal("create-todo", result!.Intent);
        Assert.Equal("/to-do/new", result.NavigateUrl);
    }

    [Fact]
    public void Classify_CreateTodoWithDescription_PrefillsTitle()
    {
        var result = IntentClassifier.Classify("create a todo for reminding me about beer");
        Assert.NotNull(result);
        Assert.Equal("create-todo", result!.Intent);
        Assert.Equal("/to-do/new", result.NavigateUrl);
        Assert.NotNull(result.PrefillFields);
        Assert.True(result.PrefillFields!.ContainsKey("Title"));
        Assert.Contains("beer", result.PrefillFields["Title"], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Classify_CreateTodoWithAbout_PrefillsTitle()
    {
        var result = IntentClassifier.Classify("create a todo about fixing the login page");
        Assert.NotNull(result);
        Assert.Equal("create-todo", result!.Intent);
        Assert.NotNull(result.PrefillFields);
        Assert.Contains("login page", result.PrefillFields!["Title"], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Classify_CreateTodoWithCalled_PrefillsTitle()
    {
        var result = IntentClassifier.Classify("add a todo called weekly standup");
        Assert.NotNull(result);
        Assert.Equal("create-todo", result!.Intent);
        Assert.Contains("weekly standup", result.PrefillFields!["Title"], StringComparison.OrdinalIgnoreCase);
    }

    // ── Create generic entity ───────────────────────────────────────────────

    [Fact]
    public void Classify_CreateEmployee_ReturnsCreateEntityIntent()
    {
        var result = IntentClassifier.Classify("create an employee");
        Assert.NotNull(result);
        Assert.Equal("create-entity", result!.Intent);
        Assert.Equal("employee", result.Entity);
    }

    [Fact]
    public void Classify_CreateWithNoEntity_ReturnsGenericCreate()
    {
        var result = IntentClassifier.Classify("create");
        Assert.NotNull(result);
        Assert.Equal("create-entity", result!.Intent);
    }

    // ── Describe entity ─────────────────────────────────────────────────────

    [Fact]
    public void Classify_DescribeCustomers_ReturnsDescribeIntent()
    {
        var result = IntentClassifier.Classify("describe customers fields");
        Assert.NotNull(result);
        Assert.Equal("describe-entity", result!.Intent);
        Assert.Equal("customers", result.Entity);
    }

    [Fact]
    public void Classify_DescribeOrders_ReturnsDescribeIntent()
    {
        var result = IntentClassifier.Classify("describe orders");
        Assert.NotNull(result);
        Assert.Equal("describe-entity", result!.Intent);
        Assert.Equal("orders", result.Entity);
    }

    // ── Query / find / show entity ──────────────────────────────────────────

    [Theory]
    [InlineData("show customers", "show-entity", "customers")]
    [InlineData("find orders", "show-entity", "orders")]
    [InlineData("query products", "show-entity", "products")]
    [InlineData("search employees", "show-entity", "employees")]
    [InlineData("get invoices", "show-entity", "invoices")]
    public void Classify_ShowEntity_ReturnsCorrectIntent(string input, string expectedIntent, string expectedEntity)
    {
        var result = IntentClassifier.Classify(input);
        Assert.NotNull(result);
        Assert.Equal(expectedIntent, result!.Intent);
        Assert.Equal(expectedEntity, result.Entity);
    }

    [Fact]
    public void Classify_FindWithFilter_ReturnsQueryEntityIntent()
    {
        var result = IntentClassifier.Classify("find customers where name equals Smith");
        Assert.NotNull(result);
        Assert.Equal("query-entity", result!.Intent);
        Assert.Equal("customers", result.Entity);
        Assert.Equal("name equals Smith", result.Parameters["query"]);
    }

    // ── Count entity ────────────────────────────────────────────────────────

    [Fact]
    public void Classify_CountOrders_ReturnsCountIntent()
    {
        var result = IntentClassifier.Classify("count orders");
        Assert.NotNull(result);
        Assert.Equal("count-entity", result!.Intent);
        Assert.Equal("orders", result.Entity);
    }

    [Fact]
    public void Classify_HowManyCustomers_ReturnsCountIntent()
    {
        var result = IntentClassifier.Classify("how many customers");
        Assert.NotNull(result);
        Assert.Equal("count-entity", result!.Intent);
        Assert.Equal("customers", result.Entity);
    }

    // ── Plan workflow ───────────────────────────────────────────────────────

    [Fact]
    public void Classify_PlanWorkflow_ReturnsPlanIntent()
    {
        var result = IntentClassifier.Classify("plan a backup workflow");
        Assert.NotNull(result);
        Assert.Equal("plan-workflow", result!.Intent);
    }

    // ── Ambiguous / freeform ────────────────────────────────────────────────

    [Theory]
    [InlineData("what is the meaning of life")]
    [InlineData("tell me a joke")]
    [InlineData("explain quantum computing")]
    public void Classify_AmbiguousQuery_ReturnsNull(string input)
    {
        var result = IntentClassifier.Classify(input);
        Assert.Null(result);
    }

    // ── ChatResponse structure ──────────────────────────────────────────────

    [Fact]
    public void ChatResponse_NavigateUrl_DefaultsToNull()
    {
        var response = new ChatResponse("msg", "intent", 0.5f);
        Assert.Null(response.NavigateUrl);
        Assert.Null(response.PrefillFields);
    }

    [Fact]
    public void ChatResponse_WithNavigateAndPrefill_RoundTrips()
    {
        var fields = new Dictionary<string, string> { ["Title"] = "Beer reminder" };
        var response = new ChatResponse("msg", "create-todo", 0.9f, "/to-do/new", fields);

        Assert.Equal("/to-do/new", response.NavigateUrl);
        Assert.Equal("Beer reminder", response.PrefillFields!["Title"]);
    }
}
