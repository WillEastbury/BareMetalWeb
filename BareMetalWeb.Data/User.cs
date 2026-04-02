using System;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Data;

[DataEntity("Users", ShowOnNav = false, NavGroup = "Admin", NavOrder = 10, Permissions = "admin")]
public class User : DataRecord
{
    public override string EntityTypeName => "User";
    private const int Ord_UserName = BaseFieldCount + 0;
    private const int Ord_DisplayName = BaseFieldCount + 1;
    private const int Ord_Email = BaseFieldCount + 2;
    private const int Ord_PasswordHash = BaseFieldCount + 3;
    private const int Ord_PasswordSalt = BaseFieldCount + 4;
    private const int Ord_PasswordIterations = BaseFieldCount + 5;
    private const int Ord_Permissions = BaseFieldCount + 6;
    private const int Ord_IsActive = BaseFieldCount + 7;
    private const int Ord_LastLoginUtc = BaseFieldCount + 8;
    private const int Ord_FailedLoginCount = BaseFieldCount + 9;
    private const int Ord_LockoutUntilUtc = BaseFieldCount + 10;
    private const int Ord_MfaEnabled = BaseFieldCount + 11;
    private const int Ord_MfaSecret = BaseFieldCount + 12;
    private const int Ord_MfaLastVerifiedStep = BaseFieldCount + 13;
    private const int Ord_MfaSecretEncrypted = BaseFieldCount + 14;
    private const int Ord_MfaPendingSecret = BaseFieldCount + 15;
    private const int Ord_MfaPendingExpiresUtc = BaseFieldCount + 16;
    private const int Ord_MfaPendingFailedAttempts = BaseFieldCount + 17;
    private const int Ord_MfaPendingSecretEncrypted = BaseFieldCount + 18;
    private const int Ord_MfaBackupCodeHashes = BaseFieldCount + 19;
    private const int Ord_MfaBackupCodesGeneratedUtc = BaseFieldCount + 20;
    internal new const int TotalFieldCount = BaseFieldCount + 21;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("DisplayName", Ord_DisplayName),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Email", Ord_Email),
        new FieldSlot("FailedLoginCount", Ord_FailedLoginCount),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("IsActive", Ord_IsActive),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("LastLoginUtc", Ord_LastLoginUtc),
        new FieldSlot("LockoutUntilUtc", Ord_LockoutUntilUtc),
        new FieldSlot("MfaBackupCodeHashes", Ord_MfaBackupCodeHashes),
        new FieldSlot("MfaBackupCodesGeneratedUtc", Ord_MfaBackupCodesGeneratedUtc),
        new FieldSlot("MfaEnabled", Ord_MfaEnabled),
        new FieldSlot("MfaLastVerifiedStep", Ord_MfaLastVerifiedStep),
        new FieldSlot("MfaPendingExpiresUtc", Ord_MfaPendingExpiresUtc),
        new FieldSlot("MfaPendingFailedAttempts", Ord_MfaPendingFailedAttempts),
        new FieldSlot("MfaPendingSecret", Ord_MfaPendingSecret),
        new FieldSlot("MfaPendingSecretEncrypted", Ord_MfaPendingSecretEncrypted),
        new FieldSlot("MfaSecret", Ord_MfaSecret),
        new FieldSlot("MfaSecretEncrypted", Ord_MfaSecretEncrypted),
        new FieldSlot("PasswordHash", Ord_PasswordHash),
        new FieldSlot("PasswordIterations", Ord_PasswordIterations),
        new FieldSlot("PasswordSalt", Ord_PasswordSalt),
        new FieldSlot("Permissions", Ord_Permissions),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("UserName", Ord_UserName),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public User() : base(TotalFieldCount) { }
    public User(string createdBy) : base(TotalFieldCount, createdBy) { }
    protected User(int totalFieldCount) : base(totalFieldCount) { }
    protected User(int totalFieldCount, string createdBy) : base(totalFieldCount, createdBy) { }

    [DataField(Label = "Username", Order = 1, Required = true, List = true, View = true, Edit = true, Create = true, Placeholder = "username")]
    [DataIndex]
    public string UserName
    {
        get => (string?)_values[Ord_UserName] ?? string.Empty;
        set => _values[Ord_UserName] = value;
    }

    [DataField(Label = "Display Name", Order = 2, Required = true, List = true, View = true, Edit = true, Create = true, Placeholder = "Display name")]
    public string DisplayName
    {
        get => (string?)_values[Ord_DisplayName] ?? string.Empty;
        set => _values[Ord_DisplayName] = value;
    }

    [DataField(Label = "Email", Order = 3, Required = true, List = true, View = true, Edit = true, Create = true, FieldType = FormFieldType.Email, Placeholder = "you@example.com")]
    [DataIndex]
    public string Email
    {
        get => (string?)_values[Ord_Email] ?? string.Empty;
        set => _values[Ord_Email] = value;
    }

    public string PasswordHash
    {
        get => (string?)_values[Ord_PasswordHash] ?? string.Empty;
        set => _values[Ord_PasswordHash] = value;
    }

    public string PasswordSalt
    {
        get => (string?)_values[Ord_PasswordSalt] ?? string.Empty;
        set => _values[Ord_PasswordSalt] = value;
    }

    public int PasswordIterations
    {
        get => (int)(_values[Ord_PasswordIterations] ?? 100_000);
        set => _values[Ord_PasswordIterations] = value;
    }

    [DataField(Label = "Permissions", Order = 4, Required = false, List = true, View = true, Edit = true, Create = true, Placeholder = "comma,separated,roles")]
    public string[] Permissions
    {
        get
        {
            var val = _values[Ord_Permissions];
            if (val is string[] arr) return arr;
            if (val is string s && !string.IsNullOrEmpty(s))
                return s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            return Array.Empty<string>();
        }
        set => _values[Ord_Permissions] = string.Join(",", value ?? Array.Empty<string>());
    }

    [DataField(Label = "Active", Order = 5, Required = false, List = true, View = true, Edit = true, Create = true, FieldType = FormFieldType.YesNo)]
    public bool IsActive
    {
        get => _values[Ord_IsActive] is true;
        set => _values[Ord_IsActive] = value;
    }

    [DataField(Label = "Last Login", Order = 6, Required = false, List = true, View = true, Edit = false, Create = false, ReadOnly = true)]
    public DateTime? LastLoginUtc
    {
        get => _values[Ord_LastLoginUtc] as DateTime?;
        set => _values[Ord_LastLoginUtc] = value;
    }

    [DataField(Label = "Failed Logins", Order = 7, Required = false, List = false, View = true, Edit = false, Create = false, ReadOnly = true)]
    public int FailedLoginCount
    {
        get => (int)(_values[Ord_FailedLoginCount] ?? 0);
        set => _values[Ord_FailedLoginCount] = value;
    }

    [DataField(Label = "Lockout Until", Order = 8, Required = false, List = false, View = true, Edit = false, Create = false, ReadOnly = true)]
    public DateTime? LockoutUntilUtc
    {
        get => _values[Ord_LockoutUntilUtc] as DateTime?;
        set => _values[Ord_LockoutUntilUtc] = value;
    }

    [DataField(Label = "MFA Enabled", Order = 9, Required = false, List = true, View = true, Edit = false, Create = false, ReadOnly = true, FieldType = FormFieldType.YesNo)]
    public bool MfaEnabled
    {
        get => _values[Ord_MfaEnabled] is true;
        set => _values[Ord_MfaEnabled] = value;
    }

    public string? MfaSecret
    {
        get => (string?)_values[Ord_MfaSecret];
        set => _values[Ord_MfaSecret] = value;
    }

    public long MfaLastVerifiedStep
    {
        get => (long)(_values[Ord_MfaLastVerifiedStep] ?? 0L);
        set => _values[Ord_MfaLastVerifiedStep] = value;
    }

    public string? MfaSecretEncrypted
    {
        get => (string?)_values[Ord_MfaSecretEncrypted];
        set => _values[Ord_MfaSecretEncrypted] = value;
    }

    public string? MfaPendingSecret
    {
        get => (string?)_values[Ord_MfaPendingSecret];
        set => _values[Ord_MfaPendingSecret] = value;
    }

    public DateTime? MfaPendingExpiresUtc
    {
        get => _values[Ord_MfaPendingExpiresUtc] as DateTime?;
        set => _values[Ord_MfaPendingExpiresUtc] = value;
    }

    public int MfaPendingFailedAttempts
    {
        get => (int)(_values[Ord_MfaPendingFailedAttempts] ?? 0);
        set => _values[Ord_MfaPendingFailedAttempts] = value;
    }

    public string? MfaPendingSecretEncrypted
    {
        get => (string?)_values[Ord_MfaPendingSecretEncrypted];
        set => _values[Ord_MfaPendingSecretEncrypted] = value;
    }

    public string[] MfaBackupCodeHashes
    {
        get
        {
            var val = _values[Ord_MfaBackupCodeHashes];
            if (val is string[] arr) return arr;
            if (val is string s && !string.IsNullOrEmpty(s))
                return s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            return Array.Empty<string>();
        }
        set => _values[Ord_MfaBackupCodeHashes] = string.Join(",", value ?? Array.Empty<string>());
    }

    public DateTime? MfaBackupCodesGeneratedUtc
    {
        get => _values[Ord_MfaBackupCodesGeneratedUtc] as DateTime?;
        set => _values[Ord_MfaBackupCodesGeneratedUtc] = value;
    }

    public bool IsLockedOut => LockoutUntilUtc.HasValue && LockoutUntilUtc.Value > DateTime.UtcNow;

    public static async ValueTask<DataRecord?> GetByIdAsync(uint key, CancellationToken cancellationToken = default)
        => await DataStoreProvider.Current.LoadAsync("User", key, cancellationToken).ConfigureAwait(false);

    public ValueTask SaveAsync(CancellationToken cancellationToken = default)
        => DataStoreProvider.Current.SaveAsync("User", this, cancellationToken);

    public void SetPassword(string password, int? iterations = null)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Password cannot be empty.", nameof(password));

        var effectiveIterations = iterations.GetValueOrDefault(PasswordIterations > 0 ? PasswordIterations : 100_000);
        var result = PasswordHasher.CreateHash(password, effectiveIterations);
        PasswordHash = result.Hash;
        PasswordSalt = result.Salt;
        PasswordIterations = result.Iterations;
    }

    public bool VerifyPassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(PasswordHash) || string.IsNullOrWhiteSpace(PasswordSalt))
            return false;

        var iterations = PasswordIterations > 0 ? PasswordIterations : 100_000;
        return PasswordHasher.Verify(password, PasswordHash, PasswordSalt, iterations);
    }

    public void RegisterFailedLogin(int maxFailed = 5, TimeSpan? lockoutDuration = null)
    {
        FailedLoginCount++;
        if (FailedLoginCount >= maxFailed)
        {
            LockoutUntilUtc = DateTime.UtcNow.Add(lockoutDuration ?? TimeSpan.FromMinutes(15));
        }
    }

    public void RegisterSuccessfulLogin()
    {
        FailedLoginCount = 0;
        LockoutUntilUtc = null;
        LastLoginUtc = DateTime.UtcNow;
    }

    [RemoteCommand(Label = "Reset Lockout", Icon = "bi-unlock", ConfirmMessage = "Reset login lockout and failed attempt counter for this user?", Permission = "admin", Order = 1)]
    public RemoteCommandResult ResetLockout()
    {
        FailedLoginCount = 0;
        LockoutUntilUtc = null;
        return RemoteCommandResult.Ok("Lockout reset. User can now sign in.");
    }
}
