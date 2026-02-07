using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace BareMetalWeb.Data;


public static class Users
{
    public static User? GetById(string id) => DataStoreProvider.Current.Load<User>(id);

    public static ValueTask<User?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
        => DataStoreProvider.Current.LoadAsync<User>(id, cancellationToken);

    public static void Save(User user) => DataStoreProvider.Current.Save(user);

    public static ValueTask SaveAsync(User user, CancellationToken cancellationToken = default)
        => DataStoreProvider.Current.SaveAsync(user, cancellationToken);

    public static User? FindByEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return null;

        var normalized = email.Trim();
        return DataStoreProvider.Current.Query<User>(null)
            .FirstOrDefault(user => string.Equals(user.Email, normalized, StringComparison.OrdinalIgnoreCase));
    }

    public static User? FindByUserName(string userName)
    {
        if (string.IsNullOrWhiteSpace(userName))
            return null;

        var normalized = userName.Trim();
        return DataStoreProvider.Current.Query<User>(null)
            .FirstOrDefault(user => string.Equals(user.UserName, normalized, StringComparison.OrdinalIgnoreCase));
    }

    public static User? FindByEmailOrUserName(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var normalized = value.Trim();
        return DataStoreProvider.Current.Query<User>(null)
            .FirstOrDefault(user => string.Equals(user.Email, normalized, StringComparison.OrdinalIgnoreCase)
                || string.Equals(user.UserName, normalized, StringComparison.OrdinalIgnoreCase));
    }

    public static bool ExistsByEmailOrUserName(string value)
        => FindByEmailOrUserName(value) != null;
}
