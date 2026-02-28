using System.Linq;
using BareMetalWeb.Runtime;
using Xunit;

namespace BareMetalWeb.Runtime.Tests;

/// <summary>
/// Tests for <see cref="SampleGalleryService"/> package loading.
/// </summary>
public class SampleGalleryServiceTests
{
    [Fact]
    public void GetAllPackages_Returns_FourPackages()
    {
        var packages = SampleGalleryService.GetAllPackages();
        Assert.Equal(4, packages.Count);
    }

    [Theory]
    [InlineData("sales")]
    [InlineData("todo")]
    [InlineData("employee")]
    [InlineData("school")]
    public void GetAllPackages_ContainsExpectedSlug(string slug)
    {
        var packages = SampleGalleryService.GetAllPackages();
        Assert.Contains(packages, p => p.Slug == slug);
    }

    [Theory]
    [InlineData("sales")]
    [InlineData("todo")]
    [InlineData("employee")]
    [InlineData("school")]
    public void GetPackage_BySlug_ReturnsPackage(string slug)
    {
        var pkg = SampleGalleryService.GetPackage(slug);
        Assert.NotNull(pkg);
        Assert.Equal(slug, pkg!.Slug);
    }

    [Fact]
    public void GetPackage_UnknownSlug_ReturnsNull()
    {
        var pkg = SampleGalleryService.GetPackage("nonexistent-package");
        Assert.Null(pkg);
    }

    [Theory]
    [InlineData("sales")]
    [InlineData("todo")]
    [InlineData("employee")]
    [InlineData("school")]
    public void GetPackage_HasEntitiesAndFields(string slug)
    {
        var pkg = SampleGalleryService.GetPackage(slug)!;

        Assert.NotEmpty(pkg.Entities);
        Assert.NotEmpty(pkg.Fields);
        // Each field must reference a valid entity EntityId
        var entityIds = pkg.Entities.Select(e => e.EntityId).ToHashSet();
        Assert.All(pkg.Fields, f => Assert.Contains(f.EntityId, entityIds));
    }

    [Fact]
    public void SalesPackage_HasExpectedEntities()
    {
        var pkg = SampleGalleryService.GetPackage("sales")!;
        var names = pkg.Entities.Select(e => e.Name).ToHashSet();

        Assert.Contains("Addresses", names);
        Assert.Contains("Customers", names);
        Assert.Contains("Products", names);
        Assert.Contains("Orders", names);
        Assert.Contains("Currencies", names);
        Assert.Contains("Units Of Measure", names);
    }

    [Fact]
    public void EmployeePackage_HasEmployeeEntity()
    {
        var pkg = SampleGalleryService.GetPackage("employee")!;
        Assert.Contains(pkg.Entities, e => e.Name == "Employees");
    }

    [Fact]
    public void TodoPackage_HasToDoEntity()
    {
        var pkg = SampleGalleryService.GetPackage("todo")!;
        Assert.Contains(pkg.Entities, e => e.Name == "To Do");
    }

    [Fact]
    public void SchoolPackage_HasExpectedEntities()
    {
        var pkg = SampleGalleryService.GetPackage("school")!;
        var names = pkg.Entities.Select(e => e.Name).ToHashSet();

        Assert.Contains("Subjects", names);
        Assert.Contains("Time Table Plans", names);
        Assert.Contains("Lesson Logs", names);
    }

    [Theory]
    [InlineData("sales")]
    [InlineData("todo")]
    [InlineData("employee")]
    [InlineData("school")]
    public void GetPackage_HasNonEmptyNameAndDescription(string slug)
    {
        var pkg = SampleGalleryService.GetPackage(slug)!;

        Assert.False(string.IsNullOrWhiteSpace(pkg.Name));
        Assert.False(string.IsNullOrWhiteSpace(pkg.Description));
        Assert.False(string.IsNullOrWhiteSpace(pkg.Icon));
    }
}
