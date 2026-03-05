using System;
using System.Threading;
using System.Threading.Tasks;

namespace BareMetalWeb.Data;


public static class Users
{
    public static ValueTask<User?> GetByIdAsync(uint key, CancellationToken cancellationToken = default)
        => DataStoreProvider.Current.LoadAsync<User>(key, cancellationToken);

    public static ValueTask SaveAsync(User user, CancellationToken cancellationToken = default)
        => DataStoreProvider.Current.SaveAsync(user, cancellationToken);

    public static async ValueTask<User?> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(email))
            return null;

        var normalized = email.Trim();
        var users = await DataStoreProvider.Current.QueryAsync<User>(null, cancellationToken).ConfigureAwait(false);
        foreach (var user in users)
        {
            if (string.Equals(user.Email, normalized, StringComparison.OrdinalIgnoreCase))
                return user;
        }
        return null;
    }

    public static async ValueTask<User?> FindByUserNameAsync(string userName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userName))
            return null;

        var normalized = userName.Trim();
        var users = await DataStoreProvider.Current.QueryAsync<User>(null, cancellationToken).ConfigureAwait(false);
        foreach (var user in users)
        {
            if (string.Equals(user.UserName, normalized, StringComparison.OrdinalIgnoreCase))
                return user;
        }
        return null;
    }

    public static async ValueTask<User?> FindByEmailOrUserNameAsync(string value, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var normalized = value.Trim();
        var users = await DataStoreProvider.Current.QueryAsync<User>(null, cancellationToken).ConfigureAwait(false);
        foreach (var user in users)
        {
            if (string.Equals(user.Email, normalized, StringComparison.OrdinalIgnoreCase)
                || string.Equals(user.UserName, normalized, StringComparison.OrdinalIgnoreCase))
                return user;
        }
        return null;
    }

    public static async ValueTask<bool> ExistsByEmailOrUserNameAsync(string value, CancellationToken cancellationToken = default)
        => await FindByEmailOrUserNameAsync(value, cancellationToken).ConfigureAwait(false) != null;
}
