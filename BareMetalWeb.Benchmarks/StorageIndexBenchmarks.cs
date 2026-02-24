using System;
using System.Collections.Generic;
using System.IO;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;
using BenchmarkDotNet.Attributes;

namespace BareMetalWeb.Benchmarks;

/// <summary>
/// Benchmarks that compare index-accelerated queries against full scans for common entity types.
/// Establishes baseline metrics for secondary index performance on demo objects.
/// </summary>
[MemoryDiagnoser]
[ShortRunJob]
public class StorageIndexBenchmarks : IDisposable
{
    private string _testRoot = null!;
    private LocalFolderBinaryDataProvider _provider = null!;

    // Queries exercised in each benchmark
    private QueryDefinition _indexedCustomerQuery = null!;
    private QueryDefinition _nonIndexedCustomerQuery = null!;
    private QueryDefinition _indexedOrderQuery = null!;
    private QueryDefinition _indexedProductQuery = null!;

    [Params(50)]
    public int RecordCount { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _testRoot = Path.Combine(Path.GetTempPath(), "bmw_bench_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testRoot);

        DataScaffold.RegisterEntity<Customer>();
        DataScaffold.RegisterEntity<Order>();
        DataScaffold.RegisterEntity<Product>();

        _provider = new LocalFolderBinaryDataProvider(_testRoot);

        // Seed customers
        for (int i = 0; i < RecordCount; i++)
        {
            _provider.Save(new Customer
            {
                Id = $"cust{i}",
                Name = $"Customer {i}",
                Email = $"cust{i}@example.com",
                Company = i % 5 == 0 ? "Acme Corp" : $"Company{i}",
                IsActive = true
            });
        }

        // Seed orders (half referencing cust0)
        for (int i = 0; i < RecordCount; i++)
        {
            _provider.Save(new Order
            {
                Id = $"ord{i}",
                OrderNumber = $"ORD-{i:D4}",
                CustomerId = i % 2 == 0 ? "cust0" : $"cust{i}",
                Status = i % 3 == 0 ? "Open" : "Closed",
                OrderDate = DateOnly.FromDateTime(DateTime.UtcNow)
            });
        }

        // Seed products
        for (int i = 0; i < RecordCount; i++)
        {
            _provider.Save(new Product
            {
                Id = $"prod{i}",
                Name = $"Product {i}",
                Sku = $"SKU-{i:D4}",
                Category = i % 4 == 0 ? "Electronics" : $"Category{i}",
                IsActive = true,
                Price = 9.99m + i
            });
        }

        // Build queries used by benchmarks
        _indexedCustomerQuery = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "Company", Operator = QueryOperator.Equals, Value = "Acme Corp" }
            }
        };

        // Notes field is not indexed — exercises full scan path
        _nonIndexedCustomerQuery = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "IsActive", Operator = QueryOperator.Equals, Value = "True" }
            }
        };

        _indexedOrderQuery = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "Status", Operator = QueryOperator.Equals, Value = "Open" }
            }
        };

        _indexedProductQuery = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "Category", Operator = QueryOperator.Equals, Value = "Electronics" }
            }
        };
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _provider = null!;
        if (Directory.Exists(_testRoot))
            Directory.Delete(_testRoot, recursive: true);
    }

    /// <summary>Index-accelerated query on Customer.Company ([DataIndex]).</summary>
    [Benchmark(Baseline = true)]
    public int IndexedQuery_CustomerByCompany()
    {
        var results = _provider.Query<Customer>(_indexedCustomerQuery);
        int count = 0;
        foreach (var _ in results) count++;
        return count;
    }

    /// <summary>Full-scan query on a non-indexed Customer field (IsActive).</summary>
    [Benchmark]
    public int FullScanQuery_CustomerByIsActive()
    {
        var results = _provider.Query<Customer>(_nonIndexedCustomerQuery);
        int count = 0;
        foreach (var _ in results) count++;
        return count;
    }

    /// <summary>Index-accelerated query on Order.Status ([DataIndex]).</summary>
    [Benchmark]
    public int IndexedQuery_OrderByStatus()
    {
        var results = _provider.Query<Order>(_indexedOrderQuery);
        int count = 0;
        foreach (var _ in results) count++;
        return count;
    }

    /// <summary>Index-accelerated query on Product.Category ([DataIndex]).</summary>
    [Benchmark]
    public int IndexedQuery_ProductByCategory()
    {
        var results = _provider.Query<Product>(_indexedProductQuery);
        int count = 0;
        foreach (var _ in results) count++;
        return count;
    }

    public void Dispose() => Cleanup();
}
