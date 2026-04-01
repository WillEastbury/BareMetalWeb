using System.Security.Cryptography;
using System.Text;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Defines all built-in entity schemas as EntityDefinition + FieldDefinition records,
/// independent of C# entity classes. On first startup these are seeded into the WAL
/// so the RuntimeEntityRegistry can compile them into DataRecord-backed runtime entities.
/// </summary>
public static class SystemCatalog
{
    public record CatalogEntry(
        EntityDefinition Entity,
        List<FieldDefinition> Fields,
        List<IndexDefinition> Indexes);

    /// <summary>Deterministic ID from a seed string for stable cross-seed identity.</summary>
    private static string Id(string seed)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes("bmw.sys." + seed));
        return new Guid(hash.AsSpan(0, 16)).ToString("D");
    }

    /// <summary>Builds the complete system catalog — 13 entities.</summary>
    public static IReadOnlyList<CatalogEntry> Build()
    {
        return new[]
        {
            Settings(),
            Users(),
            SystemPrincipals(),
            AuditEntries(),
            ReportDefinitions(),
            DashboardDefinitions(),
            ViewDefinitions(),
            FileAttachments(),
            RecordComments(),
            InboxMessages(),
            WorkflowRules(),
            ScheduledActions(),
            NotificationChannels(),
        };
    }

    /// <summary>
    /// Seeds system catalog entities that don't already exist in the store.
    /// Returns the number of entities seeded.
    /// </summary>
    public static async Task<int> SeedIfNeededAsync(
        IDataObjectStore store,
        Action<string>? logger = null,
        CancellationToken ct = default)
    {
        var existing = (await store.QueryAsync("EntityDefinition", null, ct).ConfigureAwait(false))
            .Cast<EntityDefinition>().ToList();
        var bySlug = new Dictionary<string, EntityDefinition>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in existing)
        {
            var s = !string.IsNullOrWhiteSpace(e.Slug) ? e.Slug! : DataScaffold.ToSlug(e.Name);
            bySlug[s] = e;
        }

        int seeded = 0;
        foreach (var entry in Build())
        {
            var slug = entry.Entity.Slug ?? DataScaffold.ToSlug(entry.Entity.Name);
            if (bySlug.ContainsKey(slug))
            {
                logger?.Invoke($"System catalog: '{entry.Entity.Name}' already exists — skipping.");
                continue;
            }

            await store.SaveAsync(entry.Entity.EntityTypeName, entry.Entity, ct).ConfigureAwait(false);
            foreach (var f in entry.Fields)
                await store.SaveAsync(f.EntityTypeName, f, ct).ConfigureAwait(false);
            foreach (var i in entry.Indexes)
                await store.SaveAsync(i.EntityTypeName, i, ct).ConfigureAwait(false);

            logger?.Invoke(
                $"System catalog: seeded '{entry.Entity.Name}' ({entry.Fields.Count} fields, {entry.Indexes.Count} indexes).");
            seeded++;
        }

        return seeded;
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    /// <summary>Visible field with default List/View/Edit/Create = true.</summary>
    private static FieldDefinition F(string entityId, string name, string label, int order,
        string type = "string", bool required = false,
        bool list = true, bool view = true, bool edit = true, bool create = true,
        bool readOnly = false, bool nullable = false,
        string? placeholder = null, string? enumValues = null,
        string? lookupSlug = null, string? lookupDisplay = null, string? lookupValue = null,
        bool multiline = false)
    {
        return new FieldDefinition
        {
            FieldId = Id(entityId + "." + name),
            EntityId = entityId,
            Name = name,
            Label = label,
            Ordinal = order,
            Type = type,
            Required = required,
            List = list,
            View = view,
            Edit = edit,
            Create = create,
            ReadOnly = readOnly,
            IsNullable = nullable,
            Placeholder = placeholder,
            EnumValues = enumValues,
            LookupEntitySlug = lookupSlug,
            LookupDisplayField = lookupDisplay,
            LookupValueField = lookupValue,
            Multiline = multiline,
        };
    }

    /// <summary>Hidden field — not shown in any UI view.</summary>
    private static FieldDefinition H(string entityId, string name, string label, int order,
        string type = "string", bool nullable = false)
    {
        return F(entityId, name, label, order, type,
            list: false, view: false, edit: false, create: false, nullable: nullable);
    }

    private static IndexDefinition Ix(string entityId, string fieldName, string indexType = "secondary")
    {
        return new IndexDefinition
        {
            EntityId = entityId,
            FieldNames = fieldName,
            Type = indexType,
        };
    }

    /// <summary>Adds all User fields (visible + hidden) to a field list for the given entity.</summary>
    private static void AddUserFields(string entityId, List<FieldDefinition> fields, List<IndexDefinition> indexes)
    {
        // ── Visible fields ──
        fields.Add(F(entityId, "UserName", "Username", 1, required: true, placeholder: "username"));
        fields.Add(F(entityId, "DisplayName", "Display Name", 2, required: true, placeholder: "Display name"));
        fields.Add(F(entityId, "Email", "Email", 3, type: "email", required: true, placeholder: "you@example.com"));
        fields.Add(F(entityId, "Permissions", "Permissions", 4, placeholder: "comma,separated,roles"));
        fields.Add(F(entityId, "IsActive", "Active", 5, type: "bool"));
        fields.Add(F(entityId, "LastLoginUtc", "Last Login", 6, type: "datetime", nullable: true, readOnly: true, edit: false, create: false));
        fields.Add(F(entityId, "FailedLoginCount", "Failed Logins", 7, type: "int", readOnly: true, list: false, edit: false, create: false));
        fields.Add(F(entityId, "LockoutUntilUtc", "Lockout Until", 8, type: "datetime", nullable: true, readOnly: true, list: false, edit: false, create: false));
        fields.Add(F(entityId, "MfaEnabled", "MFA Enabled", 9, type: "bool", readOnly: true, edit: false, create: false));

        // ── Hidden internal fields (auth/MFA state) ──
        fields.Add(H(entityId, "PasswordHash", "Password Hash", 100));
        fields.Add(H(entityId, "PasswordSalt", "Password Salt", 101));
        fields.Add(H(entityId, "PasswordIterations", "Password Iterations", 102, type: "int"));
        fields.Add(H(entityId, "MfaSecret", "MFA Secret", 103, nullable: true));
        fields.Add(H(entityId, "MfaLastVerifiedStep", "MFA Last Verified Step", 104, type: "int"));
        fields.Add(H(entityId, "MfaSecretEncrypted", "MFA Secret Encrypted", 105, nullable: true));
        fields.Add(H(entityId, "MfaPendingSecret", "MFA Pending Secret", 106, nullable: true));
        fields.Add(H(entityId, "MfaPendingExpiresUtc", "MFA Pending Expires", 107, type: "datetime", nullable: true));
        fields.Add(H(entityId, "MfaPendingFailedAttempts", "MFA Pending Failed Attempts", 108, type: "int"));
        fields.Add(H(entityId, "MfaPendingSecretEncrypted", "MFA Pending Secret Encrypted", 109, nullable: true));
        fields.Add(H(entityId, "MfaBackupCodeHashes", "MFA Backup Code Hashes", 110));
        fields.Add(H(entityId, "MfaBackupCodesGeneratedUtc", "MFA Backup Generated", 111, type: "datetime", nullable: true));

        indexes.Add(Ix(entityId, "UserName"));
        indexes.Add(Ix(entityId, "Email"));
    }

    // ── Entity Builders ─────────────────────────────────────────────────────────

    private static CatalogEntry Settings()
    {
        var eid = Id("settings");
        return new CatalogEntry(
            new EntityDefinition
            {
                EntityId = eid, Name = "Settings", Slug = "settings",
                Permissions = "admin", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1,
                IdStrategy = "sequential",
            },
            new List<FieldDefinition>
            {
                F(eid, "SettingId", "Setting ID", 1, required: true),
                F(eid, "Value", "Value", 2),
                F(eid, "Description", "Description", 3),
            },
            new List<IndexDefinition> { Ix(eid, "SettingId") });
    }

    private static CatalogEntry Users()
    {
        var eid = Id("users");
        var fields = new List<FieldDefinition>();
        var indexes = new List<IndexDefinition>();
        AddUserFields(eid, fields, indexes);

        return new CatalogEntry(
            new EntityDefinition
            {
                EntityId = eid, Name = "Users", Slug = "users",
                Permissions = "admin", ShowOnNav = false, NavGroup = "Admin", NavOrder = 10,
                IdStrategy = "sequential",
            },
            fields, indexes);
    }

    private static CatalogEntry SystemPrincipals()
    {
        var eid = Id("system-principals");
        var fields = new List<FieldDefinition>();
        var indexes = new List<IndexDefinition>();
        AddUserFields(eid, fields, indexes);

        // SystemPrincipal-specific fields
        fields.Add(F(eid, "ApiKeyHashes", "API Keys", 10, list: false, view: false, placeholder: "one key per line"));
        fields.Add(F(eid, "Role", "Principal Role", 11, type: "enum",
            enumValues: "FullAccess|DeploymentProcess|DeploymentAgent|TenantCallback"));
        fields.Add(F(eid, "OwnerTenantId", "Owner Tenant ID", 12,
            placeholder: "tenant scope (TenantCallback only)"));
        fields.Add(F(eid, "OwnerInstanceId", "Owner Instance ID", 13,
            placeholder: "instance scope (TenantCallback only)"));

        return new CatalogEntry(
            new EntityDefinition
            {
                EntityId = eid, Name = "System Principals", Slug = "system-principals",
                Permissions = "admin", ShowOnNav = false, NavGroup = "Admin", NavOrder = 20,
                IdStrategy = "sequential",
            },
            fields, indexes);
    }

    private static CatalogEntry AuditEntries()
    {
        var eid = Id("auditentry");
        return new CatalogEntry(
            new EntityDefinition
            {
                EntityId = eid, Name = "Audit Entry", Slug = "auditentry",
                Permissions = "admin", ShowOnNav = true, NavGroup = "Admin", NavOrder = 30,
                IdStrategy = "sequential",
            },
            new List<FieldDefinition>
            {
                F(eid, "EntityType", "Entity Type", 1, required: true),
                F(eid, "EntityKey", "Entity Key", 2, type: "int", required: true),
                F(eid, "Operation", "Operation", 3, type: "enum", required: true,
                    enumValues: "Create|Update|Delete|RemoteCommand|AccessDenied"),
                F(eid, "TimestampUtc", "Timestamp", 4, type: "datetime", required: true),
                F(eid, "UserName", "User", 5, required: true),
                F(eid, "FieldChangesJson", "Field Changes", 6),
                F(eid, "CommandName", "Command Name", 7, nullable: true),
                F(eid, "CommandParameters", "Command Parameters", 8, nullable: true),
                F(eid, "CommandResult", "Command Result", 9, nullable: true),
                F(eid, "Notes", "Notes", 10, nullable: true),
            },
            new List<IndexDefinition>
            {
                Ix(eid, "EntityType"),
                Ix(eid, "EntityKey"),
                Ix(eid, "Operation"),
                Ix(eid, "TimestampUtc", "btree"),
                Ix(eid, "UserName"),
            });
    }

    private static CatalogEntry ReportDefinitions()
    {
        var eid = Id("report-definitions");
        return new CatalogEntry(
            new EntityDefinition
            {
                EntityId = eid, Name = "Report Definitions", Slug = "report-definitions",
                Permissions = "admin", ShowOnNav = false, NavGroup = "Admin", NavOrder = 90,
                IdStrategy = "sequential",
            },
            new List<FieldDefinition>
            {
                F(eid, "Name", "Name", 1, required: true),
                F(eid, "Description", "Description", 2, type: "multiline"),
                F(eid, "RootEntity", "Root Entity (slug)", 3, required: true),
                F(eid, "JoinsJson", "Joins (JSON)", 4, type: "multiline"),
                F(eid, "ColumnsJson", "Columns (JSON)", 5, type: "multiline"),
                F(eid, "FiltersJson", "Filters (JSON)", 6, type: "multiline"),
                F(eid, "ParametersJson", "Parameters (JSON)", 7, type: "multiline"),
                F(eid, "SortField", "Sort Field", 8),
                F(eid, "SortDescending", "Sort Descending", 9, type: "bool"),
            },
            new List<IndexDefinition>());
    }

    private static CatalogEntry DashboardDefinitions()
    {
        var eid = Id("dashboard-definitions");
        return new CatalogEntry(
            new EntityDefinition
            {
                EntityId = eid, Name = "Dashboard Definitions", Slug = "dashboard-definitions",
                Permissions = "admin", ShowOnNav = false, NavGroup = "Admin", NavOrder = 95,
                IdStrategy = "sequential",
            },
            new List<FieldDefinition>
            {
                F(eid, "Name", "Name", 1, required: true),
                F(eid, "Description", "Description", 2, type: "multiline"),
                F(eid, "TilesJson", "Tiles (JSON)", 3, type: "multiline"),
            },
            new List<IndexDefinition>());
    }

    private static CatalogEntry ViewDefinitions()
    {
        var eid = Id("view-definitions");
        return new CatalogEntry(
            new EntityDefinition
            {
                EntityId = eid, Name = "View Definitions", Slug = "view-definitions",
                Permissions = "admin", ShowOnNav = false, NavGroup = "Admin", NavOrder = 95,
                IdStrategy = "sequential",
            },
            new List<FieldDefinition>
            {
                F(eid, "ViewName", "View Name", 1, required: true),
                F(eid, "RootEntity", "Root Entity (slug)", 2, required: true),
                F(eid, "ProjectionsJson", "Projections (JSON)", 3, type: "multiline"),
                F(eid, "JoinsJson", "Joins (JSON)", 4, type: "multiline"),
                F(eid, "FiltersJson", "Filters (JSON)", 5, type: "multiline"),
                F(eid, "SortsJson", "Sorts (JSON)", 6, type: "multiline"),
                F(eid, "Limit", "Limit", 7, type: "int"),
                F(eid, "Offset", "Offset", 8, type: "int"),
                F(eid, "Materialised", "Materialised", 9, type: "bool"),
            },
            new List<IndexDefinition>());
    }

    private static CatalogEntry FileAttachments()
    {
        var eid = Id("fileattachment");
        return new CatalogEntry(
            new EntityDefinition
            {
                EntityId = eid, Name = "File Attachment", Slug = "fileattachment",
                Permissions = "Authenticated", ShowOnNav = false,
                IdStrategy = "sequential",
            },
            new List<FieldDefinition>
            {
                F(eid, "RecordType", "Record Type", 1, required: true),
                F(eid, "RecordKey", "Record Key", 2, type: "int", required: true),
                F(eid, "FileName", "File Name", 3, required: true),
                F(eid, "ContentType", "Content Type", 4),
                F(eid, "SizeBytes", "Size (bytes)", 5, type: "int"),
                F(eid, "StorageKey", "Storage Key", 6, list: false, view: false, edit: false, create: false),
                F(eid, "Description", "Description", 7, nullable: true, list: false),
                F(eid, "AttachmentGroupId", "Version Group", 8, type: "int", list: false, view: false, edit: false, create: false),
                F(eid, "VersionNumber", "Version", 9, type: "int"),
                F(eid, "IsCurrentVersion", "Current Version", 10, type: "bool"),
            },
            new List<IndexDefinition>
            {
                Ix(eid, "RecordType"),
                Ix(eid, "RecordKey"),
                Ix(eid, "AttachmentGroupId"),
                Ix(eid, "IsCurrentVersion"),
            });
    }

    private static CatalogEntry RecordComments()
    {
        var eid = Id("recordcomment");
        return new CatalogEntry(
            new EntityDefinition
            {
                EntityId = eid, Name = "Record Comment", Slug = "recordcomment",
                Permissions = "Authenticated", ShowOnNav = false,
                IdStrategy = "sequential",
            },
            new List<FieldDefinition>
            {
                F(eid, "RecordType", "Record Type", 1, required: true),
                F(eid, "RecordKey", "Record Key", 2, type: "int", required: true),
                F(eid, "Text", "Text", 3, required: true),
            },
            new List<IndexDefinition>
            {
                Ix(eid, "RecordType"),
                Ix(eid, "RecordKey"),
            });
    }

    private static CatalogEntry InboxMessages()
    {
        var eid = Id("inbox-messages");
        return new CatalogEntry(
            new EntityDefinition
            {
                EntityId = eid, Name = "Inbox Messages", Slug = "inbox-messages",
                ShowOnNav = false, NavGroup = "Admin", NavOrder = 1008,
                IdStrategy = "sequential",
            },
            new List<FieldDefinition>
            {
                F(eid, "RecipientUserName", "Recipient", 1, required: true),
                F(eid, "Subject", "Subject", 2, required: true),
                F(eid, "Body", "Body", 3, type: "multiline"),
                F(eid, "Category", "Category", 4),
                F(eid, "IsRead", "Read", 5, type: "bool"),
                F(eid, "CreatedAtUtc", "Created", 6, type: "datetime", readOnly: true, edit: false, create: false),
                F(eid, "EntitySlug", "Entity Slug", 7, list: false),
                F(eid, "EntityId", "Entity Id", 8, list: false),
            },
            new List<IndexDefinition>
            {
                Ix(eid, "RecipientUserName"),
                Ix(eid, "Category"),
                Ix(eid, "IsRead"),
            });
    }

    private static CatalogEntry WorkflowRules()
    {
        var eid = Id("domain-event-subscriptions");
        return new CatalogEntry(
            new EntityDefinition
            {
                EntityId = eid, Name = "Workflow Rules", Slug = "domain-event-subscriptions",
                ShowOnNav = false, NavGroup = "Admin", NavOrder = 1005,
                IdStrategy = "sequential",
            },
            new List<FieldDefinition>
            {
                F(eid, "Name", "Name", 1, required: true),
                F(eid, "SourceEntity", "Source Entity", 2, required: true, placeholder: "e.g. order",
                    lookupSlug: "entity-definitions", lookupDisplay: "Name", lookupValue: "Name"),
                F(eid, "WatchField", "Watch Field", 3, nullable: true, placeholder: "e.g. Status (blank = any save)"),
                F(eid, "FromValue", "From Value", 4, nullable: true, placeholder: "e.g. Draft (blank = any)"),
                F(eid, "TriggerValue", "Trigger Value", 5, nullable: true, placeholder: "e.g. Approved (blank = any change)"),
                F(eid, "TargetAction", "Target Action", 6, required: true, placeholder: "e.g. SendApprovalNotification"),
                F(eid, "TargetResolution", "Target Resolution", 7, placeholder: "self  OR  field:ManagerId"),
                F(eid, "Priority", "Priority", 8, type: "int"),
                F(eid, "Enabled", "Enabled", 9, type: "bool"),
            },
            new List<IndexDefinition>());
    }

    private static CatalogEntry ScheduledActions()
    {
        var eid = Id("scheduled-actions");
        return new CatalogEntry(
            new EntityDefinition
            {
                EntityId = eid, Name = "Scheduled Actions", Slug = "scheduled-actions",
                ShowOnNav = false, NavGroup = "Admin", NavOrder = 1006,
                IdStrategy = "sequential",
            },
            new List<FieldDefinition>
            {
                F(eid, "EntityId", "Entity ID", 1, required: true,
                    lookupSlug: "entity-definitions", lookupDisplay: "Name", lookupValue: "Name"),
                F(eid, "Name", "Name", 2, required: true),
                F(eid, "ActionName", "Action Name", 3, required: true),
                F(eid, "Schedule", "Schedule", 4, required: true, placeholder: "hourly | daily | weekly | monthly | 15"),
                F(eid, "FilterExpression", "Filter Expression", 5, nullable: true),
                F(eid, "Enabled", "Enabled", 6, type: "bool"),
                F(eid, "LastRunUtc", "Last Run (UTC)", 7, type: "datetime", nullable: true, readOnly: true),
                F(eid, "LastRunCount", "Last Run Count", 8, type: "int", readOnly: true),
            },
            new List<IndexDefinition>());
    }

    private static CatalogEntry NotificationChannels()
    {
        var eid = Id("notification-channels");
        return new CatalogEntry(
            new EntityDefinition
            {
                EntityId = eid, Name = "Notification Channels", Slug = "notification-channels",
                ShowOnNav = false, NavGroup = "Admin", NavOrder = 1007,
                IdStrategy = "sequential",
            },
            new List<FieldDefinition>
            {
                F(eid, "Name", "Name", 1, required: true),
                F(eid, "ChannelType", "Channel Type", 2, type: "enum", required: true,
                    enumValues: "Email|Sms|Webhook|InApp"),
                F(eid, "Host", "Host / Endpoint", 3),
                F(eid, "Port", "Port", 4, type: "int"),
                F(eid, "UseTls", "Use TLS", 5, type: "bool"),
                F(eid, "Username", "Username / API Key", 6),
                F(eid, "Password", "Password / Secret", 7),
                F(eid, "FromAddress", "From Address / Number", 8, required: true),
                F(eid, "DefaultRecipients", "Default Recipients", 9),
                F(eid, "SubjectTemplate", "Subject Template", 10),
                F(eid, "BodyTemplate", "Body Template", 11, type: "multiline"),
                F(eid, "Enabled", "Enabled", 12, type: "bool"),
            },
            new List<IndexDefinition>());
    }
}
