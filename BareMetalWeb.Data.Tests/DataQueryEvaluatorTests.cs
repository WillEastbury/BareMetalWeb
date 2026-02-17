using Xunit;
using BareMetalWeb.Data;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for DataQueryEvaluator - critical component for filtering and querying data.
/// Note: These tests use the User class which is properly registered with DataEntityRegistry.
/// </summary>
public class DataQueryEvaluatorTests
{
    public DataQueryEvaluatorTests()
    {
        // Ensure entities are registered
        DataEntityRegistry.RegisterAllEntities();
    }

    [Fact]
    public void Matches_NullQuery_ReturnsTrue()
    {
        // Arrange
        var evaluator = new DataQueryEvaluator();
        var user = new User { UserName = "john" };

        // Act
        var result = evaluator.Matches(user, null);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Matches_EqualsOperator_MatchingValue_ReturnsTrue()
    {
        // Arrange
        var evaluator = new DataQueryEvaluator();
        var user = new User { UserName = "john" };
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "UserName", Operator = QueryOperator.Equals, Value = "john" }
            }
        };

        // Act
        var result = evaluator.Matches(user, query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Matches_EqualsOperator_CaseInsensitive_ReturnsTrue()
    {
        // Arrange
        var evaluator = new DataQueryEvaluator();
        var user = new User { UserName = "john" };
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "UserName", Operator = QueryOperator.Equals, Value = "JOHN" }
            }
        };

        // Act
        var result = evaluator.Matches(user, query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Matches_NotEqualsOperator_NonMatchingValue_ReturnsTrue()
    {
        // Arrange
        var evaluator = new DataQueryEvaluator();
        var user = new User { UserName = "john" };
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "UserName", Operator = QueryOperator.NotEquals, Value = "jane" }
            }
        };

        // Act
        var result = evaluator.Matches(user, query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Matches_ContainsOperator_StringContains_ReturnsTrue()
    {
        // Arrange
        var evaluator = new DataQueryEvaluator();
        var user = new User { Email = "john@example.com" };
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "Email", Operator = QueryOperator.Contains, Value = "john" }
            }
        };

        // Act
        var result = evaluator.Matches(user, query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Matches_StartsWithOperator_StringStartsWith_ReturnsTrue()
    {
        // Arrange
        var evaluator = new DataQueryEvaluator();
        var user = new User { Email = "john@example.com" };
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "Email", Operator = QueryOperator.StartsWith, Value = "john" }
            }
        };

        // Act
        var result = evaluator.Matches(user, query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Matches_EndsWithOperator_StringEndsWith_ReturnsTrue()
    {
        // Arrange
        var evaluator = new DataQueryEvaluator();
        var user = new User { Email = "john@example.com" };
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "Email", Operator = QueryOperator.EndsWith, Value = "example.com" }
            }
        };

        // Act
        var result = evaluator.Matches(user, query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Matches_InOperator_ValueInList_ReturnsTrue()
    {
        // Arrange
        var evaluator = new DataQueryEvaluator();
        var user = new User { UserName = "john" };
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "UserName", Operator = QueryOperator.In, Value = "john,jane,bob" }
            }
        };

        // Act
        var result = evaluator.Matches(user, query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Matches_MultipleClausesAndLogic_AllMatch_ReturnsTrue()
    {
        // Arrange
        var evaluator = new DataQueryEvaluator();
        var user = new User { UserName = "john", IsActive = true };
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.And,
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "UserName", Operator = QueryOperator.Equals, Value = "john" },
                new QueryClause { Field = "IsActive", Operator = QueryOperator.Equals, Value = "true" }
            }
        };

        // Act
        var result = evaluator.Matches(user, query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Matches_MultipleClausesOrLogic_OneMatches_ReturnsTrue()
    {
        // Arrange
        var evaluator = new DataQueryEvaluator();
        var user = new User { UserName = "john", IsActive = true };
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.Or,
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "UserName", Operator = QueryOperator.Equals, Value = "jane" },
                new QueryClause { Field = "IsActive", Operator = QueryOperator.Equals, Value = "true" }
            }
        };

        // Act
        var result = evaluator.Matches(user, query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Matches_NonExistentField_ReturnsFalse()
    {
        // Arrange
        var evaluator = new DataQueryEvaluator();
        var user = new User { UserName = "john" };
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "NonExistentField", Operator = QueryOperator.Equals, Value = "value" }
            }
        };

        // Act
        var result = evaluator.Matches(user, query);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void ApplySorts_NullQuery_ReturnsOriginalSequence()
    {
        // Arrange
        var evaluator = new DataQueryEvaluator();
        var users = new List<User>
        {
            new User { UserName = "charlie" },
            new User { UserName = "alice" },
            new User { UserName = "bob" }
        };

        // Act
        var result = evaluator.ApplySorts(users, null);

        // Assert
        Assert.Equal(users, result);
    }

    [Fact]
    public void ApplySorts_SingleFieldAscending_SortsCorrectly()
    {
        // Arrange
        var evaluator = new DataQueryEvaluator();
        var users = new List<User>
        {
            new User { UserName = "charlie" },
            new User { UserName = "alice" },
            new User { UserName = "bob" }
        };
        var query = new QueryDefinition
        {
            Sorts = new List<SortClause>
            {
                new SortClause { Field = "UserName", Direction = SortDirection.Asc }
            }
        };

        // Act
        var result = evaluator.ApplySorts(users, query).ToList();

        // Assert
        Assert.Equal("alice", result[0].UserName);
        Assert.Equal("bob", result[1].UserName);
        Assert.Equal("charlie", result[2].UserName);
    }

    [Fact]
    public void ApplySorts_SingleFieldDescending_SortsCorrectly()
    {
        // Arrange
        var evaluator = new DataQueryEvaluator();
        var users = new List<User>
        {
            new User { UserName = "charlie" },
            new User { UserName = "alice" },
            new User { UserName = "bob" }
        };
        var query = new QueryDefinition
        {
            Sorts = new List<SortClause>
            {
                new SortClause { Field = "UserName", Direction = SortDirection.Desc }
            }
        };

        // Act
        var result = evaluator.ApplySorts(users, query).ToList();

        // Assert
        Assert.Equal("charlie", result[0].UserName);
        Assert.Equal("bob", result[1].UserName);
        Assert.Equal("alice", result[2].UserName);
    }
}
