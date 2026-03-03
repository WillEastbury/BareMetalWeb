using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;
using BareMetalWeb.UserClasses.DataObjects;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Registers all compiled entity types for test use.
/// Replaces the removed DataEntityRegistry.RegisterAllEntities().
/// </summary>
internal static class TestEntityRegistration
{
    public static void RegisterAll()
    {
        // System entities
        DataScaffold.RegisterEntity<User>();
        DataScaffold.RegisterEntity<AppSetting>();
        DataScaffold.RegisterEntity<AuditEntry>();
        DataScaffold.RegisterEntity<ReportDefinition>();
        DataScaffold.RegisterEntity<SystemPrincipal>();

        // UserClasses entities
        DataScaffold.RegisterEntity<Address>();
        DataScaffold.RegisterEntity<Currency>();
        DataScaffold.RegisterEntity<Customer>();
        DataScaffold.RegisterEntity<DomainEventSubscription>();
        DataScaffold.RegisterEntity<Employee>();
        DataScaffold.RegisterEntity<LessonLog>();
        DataScaffold.RegisterEntity<ModuleDefinition>();
        DataScaffold.RegisterEntity<Order>();
        DataScaffold.RegisterEntity<Page>();
        DataScaffold.RegisterEntity<Permission>();
        DataScaffold.RegisterEntity<Product>();
        DataScaffold.RegisterEntity<ProductCategory>();
        DataScaffold.RegisterEntity<Quote>();
        DataScaffold.RegisterEntity<SecurityGroup>();
        DataScaffold.RegisterEntity<SecurityRole>();
        DataScaffold.RegisterEntity<SessionLog>();
        DataScaffold.RegisterEntity<Subject>();
        DataScaffold.RegisterEntity<TimeTablePlan>();
        DataScaffold.RegisterEntity<ToDo>();
        DataScaffold.RegisterEntity<UnitOfMeasure>();
    }
}
