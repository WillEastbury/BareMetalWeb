using System;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Rendering;

namespace BareMetalWeb.Data;

[DataEntity("Users", ShowOnNav = false, NavGroup = "", NavOrder = 0)]
public class User : BaseDataObject
{
    [DataField(Label = "Username", Order = 1, Required = true, List = true, View = true, Edit = true, Create = true, Placeholder = "username")]
    public string UserName { get; set; } = string.Empty;

    [DataField(Label = "Display Name", Order = 2, Required = true, List = true, View = true, Edit = true, Create = true, Placeholder = "Display name")]
    public string DisplayName { get; set; } = string.Empty;

    [DataField(Label = "Email", Order = 3, Required = true, List = true, View = true, Edit = true, Create = true, FieldType = FormFieldType.Email, Placeholder = "you@example.com")]
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string PasswordSalt { get; set; } = string.Empty;
    public int PasswordIterations { get; set; } = 100_000;
    [DataField(Label = "Permissions", Order = 4, Required = false, List = true, View = true, Edit = true, Create = true, Placeholder = "comma,separated,roles")]
    public string[] Permissions { get; set; } = Array.Empty<string>();

    [DataField(Label = "Active", Order = 5, Required = false, List = true, View = true, Edit = true, Create = true, FieldType = FormFieldType.YesNo)]
    public bool IsActive { get; set; } = true;

    [DataField(Label = "Last Login", Order = 6, Required = false, List = true, View = true, Edit = false, Create = false, ReadOnly = true)]
    public DateTime? LastLoginUtc { get; set; }

    [DataField(Label = "Failed Logins", Order = 7, Required = false, List = false, View = true, Edit = false, Create = false, ReadOnly = true)]
    public int FailedLoginCount { get; set; }

    [DataField(Label = "Lockout Until", Order = 8, Required = false, List = false, View = true, Edit = false, Create = false, ReadOnly = true)]
    public DateTime? LockoutUntilUtc { get; set; }

    [DataField(Label = "MFA Enabled", Order = 9, Required = false, List = true, View = true, Edit = false, Create = false, ReadOnly = true, FieldType = FormFieldType.YesNo)]
    public bool MfaEnabled { get; set; }
    public string? MfaSecret { get; set; }
    public long MfaLastVerifiedStep { get; set; }
    public string? MfaSecretEncrypted { get; set; }
    public string? MfaPendingSecret { get; set; }
    public DateTime? MfaPendingExpiresUtc { get; set; }
    public int MfaPendingFailedAttempts { get; set; }
    public string? MfaPendingSecretEncrypted { get; set; }
    public string[] MfaBackupCodeHashes { get; set; } = Array.Empty<string>();
    public DateTime? MfaBackupCodesGeneratedUtc { get; set; }

    public bool IsLockedOut => LockoutUntilUtc.HasValue && LockoutUntilUtc.Value > DateTime.UtcNow;

    public static User? GetById(string id) => DataStoreProvider.Current.Load<User>(id);

    public static ValueTask<User?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
        => DataStoreProvider.Current.LoadAsync<User>(id, cancellationToken);

    public void Save() => DataStoreProvider.Current.Save(this);

    public ValueTask SaveAsync(CancellationToken cancellationToken = default)
        => DataStoreProvider.Current.SaveAsync(this, cancellationToken);

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
}
