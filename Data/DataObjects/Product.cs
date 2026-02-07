namespace BareMetalWeb.Data.DataObjects;

[DataEntity("Products", ShowOnNav = true, NavGroup = "Sales", NavOrder = 20)]
public class Product : RenderableDataObject
{
    [DataField(Label = "Name", Order = 1, Required = true)]
    public string Name { get; set; } = string.Empty;

    [DataField(Label = "SKU", Order = 2, Required = true)]
    public string Sku { get; set; } = string.Empty;

    [DataField(Label = "Category", Order = 3)]
    public string Category { get; set; } = string.Empty;

    [DataField(Label = "Unit Of Measure", Order = 4, Required = true)]
    [DataLookup(typeof(UnitOfMeasure), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc, CacheSeconds = 120)]
    public string UnitOfMeasureId { get; set; } = string.Empty;

    [DataField(Label = "Currency", Order = 5, Required = true)]
    [DataLookup(typeof(Currency), DisplayField = "IsoCode", SortField = "IsoCode", SortDirection = SortDirection.Asc, CacheSeconds = 120)]
    public string CurrencyId { get; set; } = string.Empty;

    [DataField(Label = "Price", Order = 6, Required = true, FieldType = Rendering.FormFieldType.Decimal)]
    public decimal Price { get; set; }

    [DataField(Label = "Inventory", Order = 7)]
    public int InventoryCount { get; set; }

    [DataField(Label = "Reorder Level", Order = 8)]
    public int ReorderLevel { get; set; }

    [DataField(Label = "Launch Date", Order = 9)]
    public DateOnly LaunchDate { get; set; }

    [DataField(Label = "Active", Order = 10)]
    public bool IsActive { get; set; } = true;

    [DataField(Label = "Description", Order = 11)]
    public string Description { get; set; } = string.Empty;

    [DataField(Label = "Tags", Order = 12)]
    public List<string> Tags { get; set; } = new();
}
