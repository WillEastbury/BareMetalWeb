using System.Diagnostics;
using System.Globalization;
using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;

namespace BareMetalWeb.PerformanceTests;

/// <summary>
/// Performance test application that benchmarks:
/// - Sample data generation
/// - Data serialization/deserialization
/// - Search indexing
/// - Data store operations
/// </summary>
class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("BareMetalWeb Performance Tests");
        Console.WriteLine("================================\n");

        // Parse arguments
        int addressCount = GetArgument(args, "--addresses", 1000);
        int customerCount = GetArgument(args, "--customers", 500);
        int productCount = GetArgument(args, "--products", 250);
        int unitCount = GetArgument(args, "--units", 50);
        bool runSearchTests = !HasFlag(args, "--skip-search");
        bool runSerializationTests = !HasFlag(args, "--skip-serialization");

        Console.WriteLine($"Configuration:");
        Console.WriteLine($"  Addresses: {addressCount}");
        Console.WriteLine($"  Customers: {customerCount}");
        Console.WriteLine($"  Products: {productCount}");
        Console.WriteLine($"  Units: {unitCount}");
        Console.WriteLine($"  Search tests: {runSearchTests}");
        Console.WriteLine($"  Serialization tests: {runSerializationTests}");
        Console.WriteLine();

        // Test 1: Sample Data Generation
        Console.WriteLine("Test 1: Sample Data Generation");
        Console.WriteLine("-------------------------------");
        var (addresses, customers, products, units) = GenerateSampleData(
            addressCount, customerCount, productCount, unitCount);
        Console.WriteLine();

        // Test 2: Serialization Performance
        if (runSerializationTests)
        {
            Console.WriteLine("Test 2: Binary Serialization Performance");
            Console.WriteLine("-----------------------------------------");
            TestSerialization(addresses, customers, products, units);
            Console.WriteLine();
        }

        // Test 3: Search Index Performance
        if (runSearchTests)
        {
            Console.WriteLine("Test 3: Search Index Performance");
            Console.WriteLine("---------------------------------");
            TestSearchIndexing(customers, products);
            Console.WriteLine();
        }

        Console.WriteLine("All performance tests completed!");
    }

    static (List<Address>, List<Customer>, List<Product>, List<UnitOfMeasure>) GenerateSampleData(
        int addressCount, int customerCount, int productCount, int unitCount)
    {
        var sw = Stopwatch.StartNew();

        var usedAddressIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var usedCustomerIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var usedProductIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var usedUnitIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var addresses = GenerateAddresses(addressCount, usedAddressIds);
        var units = GenerateUnits(unitCount, usedUnitIds);
        var customers = GenerateCustomers(customerCount, addresses, usedCustomerIds);
        var products = GenerateProducts(productCount, units, usedProductIds);

        sw.Stop();
        Console.WriteLine($"Generated {addresses.Count + customers.Count + products.Count + units.Count} objects in {sw.ElapsedMilliseconds}ms");
        Console.WriteLine($"  - {addresses.Count} addresses");
        Console.WriteLine($"  - {customers.Count} customers");
        Console.WriteLine($"  - {products.Count} products");
        Console.WriteLine($"  - {units.Count} units");

        return (addresses, customers, products, units);
    }

    static void TestSerialization(
        List<Address> addresses, 
        List<Customer> customers, 
        List<Product> products, 
        List<UnitOfMeasure> units)
    {
        var serializer = new BinaryObjectSerializer();
        var totalObjects = addresses.Count + customers.Count + products.Count + units.Count;
        var sw = Stopwatch.StartNew();

        // Serialize all objects
        var serializedData = new List<byte[]>();
        foreach (var address in addresses)
            serializedData.Add(serializer.Serialize(address));
        foreach (var customer in customers)
            serializedData.Add(serializer.Serialize(customer));
        foreach (var product in products)
            serializedData.Add(serializer.Serialize(product));
        foreach (var unit in units)
            serializedData.Add(serializer.Serialize(unit));

        var serializeTime = sw.Elapsed;
        Console.WriteLine($"Serialized {totalObjects} objects in {serializeTime.TotalMilliseconds:F2}ms");
        Console.WriteLine($"  Average: {serializeTime.TotalMilliseconds / totalObjects:F4}ms per object");
        
        var totalBytes = serializedData.Sum(d => d.Length);
        Console.WriteLine($"  Total size: {totalBytes:N0} bytes ({totalBytes / 1024.0:F2} KB)");
        Console.WriteLine($"  Average size: {totalBytes / (double)totalObjects:F2} bytes per object");

        // Note: Deserialization requires schema definitions
        // This would be tested in integration tests with the full data store
        Console.WriteLine("  Note: Deserialization requires schema definitions - test via DataStore integration tests");
    }

    static void TestSearchIndexing(List<Customer> customers, List<Product> products)
    {
        // Note: SearchIndexManager is internal, so we test it indirectly through data operations
        // In a real scenario, you would use the data store's indexing capabilities
        Console.WriteLine($"Search indexing would be tested with {customers.Count} customers and {products.Count} products");
        Console.WriteLine("  Note: SearchIndexManager is internal - test through DataStore in integration tests");
        
        // We can still test search-related operations
        var sw = Stopwatch.StartNew();
        
        // Simulate indexing by extracting searchable text
        var customerSearchableText = new List<string>();
        foreach (var customer in customers)
        {
            customerSearchableText.Add($"{customer.Name} {customer.Email} {customer.Company}");
        }
        
        var productSearchableText = new List<string>();
        foreach (var product in products)
        {
            productSearchableText.Add($"{product.Name} {product.Sku} {product.Category}");
        }
        
        sw.Stop();
        Console.WriteLine($"Extracted searchable text in {sw.ElapsedMilliseconds}ms");
        
        // Test simple search operations
        sw.Restart();
        var searchTerm = "test";
        var customerMatches = customerSearchableText.Count(t => 
            t.Contains(searchTerm, StringComparison.OrdinalIgnoreCase));
        var productMatches = productSearchableText.Count(t => 
            t.Contains(searchTerm, StringComparison.OrdinalIgnoreCase));
        sw.Stop();
        
        Console.WriteLine($"Simple search for '{searchTerm}' completed in {sw.Elapsed.TotalMilliseconds:F4}ms");
        Console.WriteLine($"  Found {customerMatches} customer matches and {productMatches} product matches");
    }

    // Sample data generation methods (simplified versions from RouteHandlers)
    static List<Address> GenerateAddresses(int count, HashSet<string> usedIds)
    {
        var list = new List<Address>(count);
        if (count <= 0)
            return list;

        var streets = new[] { "Maple", "Oak", "Cedar", "Pine", "Lake", "Hill", "River", "Sunset" };
        var cities = new[] { "Springfield", "Riverton", "Lakeside", "Fairview", "Oakridge" };
        var regions = new[] { "CA", "TX", "NY", "WA", "IL" };
        var rnd = Random.Shared;

        for (var i = 1; i <= count; i++)
        {
            var street = streets[rnd.Next(streets.Length)];
            var city = cities[rnd.Next(cities.Length)];
            var region = regions[rnd.Next(regions.Length)];
            var address = new Address
            {
                Label = $"Address {i}",
                Line1 = $"{rnd.Next(10, 9999)} {street} St",
                Line2 = string.Empty,
                City = city,
                Region = region,
                PostalCode = rnd.Next(10000, 99999).ToString(CultureInfo.InvariantCulture),
                Country = "US"
            };
            EnsureUniqueId(address, usedIds);
            list.Add(address);
        }

        return list;
    }

    static List<UnitOfMeasure> GenerateUnits(int count, HashSet<string> usedIds)
    {
        var list = new List<UnitOfMeasure>(count);
        if (count <= 0)
            return list;

        var defaults = new (string Name, string Abbr)[]
        {
            ("Each", "EA"),
            ("Box", "BOX"),
            ("Kilogram", "KG"),
            ("Liter", "L"),
            ("Pack", "PK"),
            ("Hour", "HR")
        };

        var index = 1;
        foreach (var unit in defaults)
        {
            if (list.Count >= count)
                break;
            list.Add(new UnitOfMeasure
            {
                Name = unit.Name,
                Abbreviation = unit.Abbr,
                Description = string.Empty,
                IsActive = true
            });
            EnsureUniqueId(list[^1], usedIds);
        }

        while (list.Count < count)
        {
            list.Add(new UnitOfMeasure
            {
                Name = $"Unit {index}",
                Abbreviation = $"U{index}",
                Description = string.Empty,
                IsActive = true
            });
            EnsureUniqueId(list[^1], usedIds);
            index++;
        }

        return list;
    }

    static List<Customer> GenerateCustomers(int count, List<Address> addresses, HashSet<string> usedIds)
    {
        var list = new List<Customer>(count);
        if (count <= 0)
            return list;

        var firstNames = new[] { "Alex", "Taylor", "Jordan", "Morgan", "Casey", "Riley" };
        var lastNames = new[] { "Smith", "Lee", "Patel", "Garcia", "Nguyen", "Brown" };
        var companies = new[] { "Acme Co", "Northwind", "Contoso", "Globex", "Initech" };
        var rnd = Random.Shared;

        for (var i = 0; i < count; i++)
        {
            var first = firstNames[rnd.Next(firstNames.Length)];
            var last = lastNames[rnd.Next(lastNames.Length)];
            var company = companies[rnd.Next(companies.Length)];
            var name = $"{first} {last}";
            var email = $"{first}.{last}.{i + 1}@example.com".ToLowerInvariant();
            var address = addresses.Count > 0 ? addresses[rnd.Next(addresses.Count)] : null;

            list.Add(new Customer
            {
                Name = name,
                Email = email,
                Phone = $"555-{rnd.Next(100, 999)}-{rnd.Next(1000, 9999)}",
                Company = company,
                AddressId = address?.Id ?? string.Empty,
                IsActive = true,
                Notes = string.Empty,
                Tags = new List<string>()
            });
            EnsureUniqueId(list[^1], usedIds);
        }

        return list;
    }

    static List<Product> GenerateProducts(int count, List<UnitOfMeasure> units, HashSet<string> usedIds)
    {
        var list = new List<Product>(count);
        if (count <= 0)
            return list;

        var names = new[] { "Widget", "Gadget", "Doohickey", "Contraption", "Gizmo" };
        var categories = new[] { "Hardware", "Supplies", "Accessories", "Tools" };
        var rnd = Random.Shared;

        for (var i = 0; i < count; i++)
        {
            var name = $"{names[rnd.Next(names.Length)]} {i + 1}";
            var unit = units.Count > 0 ? units[rnd.Next(units.Count)] : null;
            var price = Math.Round((decimal)(rnd.NextDouble() * 250 + 5), 2);
            var product = new Product
            {
                Name = name,
                Sku = $"SKU-{i + 1:0000}",
                Category = categories[rnd.Next(categories.Length)],
                UnitOfMeasureId = unit?.Id ?? string.Empty,
                Price = price,
                InventoryCount = rnd.Next(0, 5000),
                ReorderLevel = rnd.Next(0, 200),
                LaunchDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-rnd.Next(0, 365))),
                IsActive = true,
                Description = string.Empty,
                Tags = new List<string>()
            };
            EnsureUniqueId(product, usedIds);
            list.Add(product);
        }

        return list;
    }

    static void EnsureUniqueId(BaseDataObject obj, HashSet<string> usedIds)
    {
        while (usedIds.Contains(obj.Id))
        {
            obj.Id = Guid.NewGuid().ToString("N");
        }
        usedIds.Add(obj.Id);
    }

    static int GetArgument(string[] args, string flag, int defaultValue)
    {
        var idx = Array.IndexOf(args, flag);
        if (idx >= 0 && idx + 1 < args.Length && int.TryParse(args[idx + 1], out var value))
            return value;
        return defaultValue;
    }

    static bool HasFlag(string[] args, string flag)
    {
        return Array.IndexOf(args, flag) >= 0;
    }
}

