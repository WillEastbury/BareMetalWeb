# BareMetalWeb Performance Tests

This console application provides performance benchmarks for the BareMetalWeb framework.

## Features

The performance test application benchmarks:

1. **Sample Data Generation** - Tests the generation of sample data objects (Addresses, Customers, Products, Units)
2. **Binary Serialization** - Measures serialization performance and output size
3. **Search Operations** - Tests basic search/indexing operations

## Usage

Run the performance tests with default settings:

```bash
dotnet run --project BareMetalWeb.PerformanceTests
```

### Command Line Arguments

- `--addresses <count>` - Number of addresses to generate (default: 1000)
- `--customers <count>` - Number of customers to generate (default: 500)
- `--products <count>` - Number of products to generate (default: 250)
- `--units <count>` - Number of units of measure to generate (default: 50)
- `--skip-search` - Skip search performance tests
- `--skip-serialization` - Skip serialization performance tests

### Examples

Run with a small data set:
```bash
dotnet run --project BareMetalWeb.PerformanceTests -- --addresses 100 --customers 50 --products 25 --units 10
```

Run with a large data set:
```bash
dotnet run --project BareMetalWeb.PerformanceTests -- --addresses 10000 --customers 5000 --products 2500 --units 100
```

Skip search tests:
```bash
dotnet run --project BareMetalWeb.PerformanceTests -- --skip-search
```

## Sample Data Generation

The performance test includes utilities to generate realistic sample data for:

- **Addresses** - Street addresses with city, region, postal code
- **Customers** - Customer records with names, emails, phone numbers, companies
- **Products** - Products with SKUs, prices, inventory counts, categories
- **Units of Measure** - Standard units like EA, BOX, KG, L, etc.

All generated data includes unique IDs and follows the same patterns as the production sample data generator.

## Notes

- **Deserialization tests** require schema definitions and are tested through the DataStore in integration tests
- **SearchIndexManager** is internal and is tested indirectly through DataStore operations
- Performance results may vary based on system resources and configuration
