using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Query helpers for User entities. Works with both typed User objects and
/// DataRecord instances returned by the WAL provider.
/// </summary>
public static class Users
{
    public static async ValueTask<DataRecord?> GetByIdAsync(uint key, CancellationToken cancellationToken = default)
        => await DataStoreProvider.Current.LoadAsync("User", key, cancellationToken).ConfigureAwait(false);

    public static ValueTask SaveAsync(DataRecord user, CancellationToken cancellationToken = default)
        => DataStoreProvider.Current.SaveAsync("User", user, cancellationToken);

    public static async ValueTask<DataRecord?> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(email))
            return null;

        var normalized = email.Trim();
        var users = await DataStoreProvider.Current.QueryAsync("User", null, cancellationToken).ConfigureAwait(false);
        foreach (var user in users)
        {
            var userEmail = user.GetFieldValue(UserFields.Email)?.ToString();
            if (string.Equals(userEmail, normalized, StringComparison.OrdinalIgnoreCase))
                return user;
        }
        return null;
    }

    public static async ValueTask<DataRecord?> FindByUserNameAsync(string userName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userName))
            return null;

        var normalized = userName.Trim();
        var users = await DataStoreProvider.Current.QueryAsync("User", null, cancellationToken).ConfigureAwait(false);
        foreach (var user in users)
        {
            var name = user.GetFieldValue(UserFields.UserName)?.ToString();
            if (string.Equals(name, normalized, StringComparison.OrdinalIgnoreCase))
                return user;
        }
        return null;
    }

    public static async ValueTask<DataRecord?> FindByEmailOrUserNameAsync(string value, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var normalized = value.Trim();
        var users = await DataStoreProvider.Current.QueryAsync("User", null, cancellationToken).ConfigureAwait(false);
        foreach (var user in users)
        {
            var userEmail = user.GetFieldValue(UserFields.Email)?.ToString();
            var userName = user.GetFieldValue(UserFields.UserName)?.ToString();
            if (string.Equals(userEmail, normalized, StringComparison.OrdinalIgnoreCase)
                || string.Equals(userName, normalized, StringComparison.OrdinalIgnoreCase))
                return user;
        }
        return null;
    }

    public static async ValueTask<bool> ExistsByEmailOrUserNameAsync(string value, CancellationToken cancellationToken = default)
        => await FindByEmailOrUserNameAsync(value, cancellationToken).ConfigureAwait(false) != null;
}
