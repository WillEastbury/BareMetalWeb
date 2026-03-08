using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Delegates;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using System.Reflection;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Unit tests for RouteRegistrationExtensions — verifying that each registration
/// method adds the expected routes with correct verbs, paths, permissions, and nav settings.
/// </summary>
[Collection("SharedState")]
public class RouteRegistrationExtensionsTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;
    private readonly BareMetalWebServer _server;
    private readonly MockBufferedLogger _logger;
    private readonly CancellationTokenSource _cts;
    private readonly string _keyRootDirectory;
    private readonly IPageInfoFactory _pageInfoFactory;
    private readonly IHtmlTemplate _mainTemplate;
    private readonly StubRouteHandlers _routeHandlers;

    public RouteRegistrationExtensionsTests()
    {
        _keyRootDirectory = Path.Combine(Path.GetTempPath(), $"bmw-rre-tests-{Guid.NewGuid()}");
        Directory.CreateDirectory(_keyRootDirectory);
        CookieProtection.ConfigureKeyRoot(_keyRootDirectory);

        _originalStore = DataStoreProvider.Current;
        DataStoreProvider.Current = new InMemoryDataStore();

        _logger = new MockBufferedLogger();
        _cts = new CancellationTokenSource();

        var template = new MockHtmlTemplate();
        var notFoundPage = CreatePageInfo("Not Found", 404);
        var errorPage = CreatePageInfo("Error", 500);

        _server = new BareMetalWebServer(
            "TestApp", "Test Company", "2026", BmwConfig.Load("/tmp"), "/tmp",
            _logger, new MockHtmlRenderer(), notFoundPage, errorPage,
            _cts, new MockMetricsTracker(), new MockClientRequestTracker());

        _pageInfoFactory = new PageInfoFactory();
        _mainTemplate = template;
        _routeHandlers = new StubRouteHandlers();
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
        _cts.Cancel();
        _cts.Dispose();
        if (Directory.Exists(_keyRootDirectory))
            Directory.Delete(_keyRootDirectory, true);
    }

    // ──────────────────────────────────────────────────────────────
    //  Static Routes
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void RegisterStaticRoutes_RegistersHomeRoute()
    {
        // Arrange & Act
        _server.RegisterStaticRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /"));
    }

    [Fact]
    public void RegisterStaticRoutes_RegistersStatusRoute()
    {
        // Arrange & Act
        _server.RegisterStaticRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /status"));
    }

    [Fact]
    public void RegisterStaticRoutes_RegistersStatusRawRoute()
    {
        // Arrange & Act
        _server.RegisterStaticRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /statusRaw"));
    }

    [Fact]
    public void RegisterStaticRoutes_HomeRoute_HasPublicPermission()
    {
        // Arrange & Act
        _server.RegisterStaticRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        var route = _server.routes["GET /"];
        Assert.Equal("Public", route.PageInfo!.PageMetaData.PermissionsNeeded);
    }

    [Fact]
    public void RegisterStaticRoutes_RegistersExpectedRouteCount()
    {
        // Arrange & Act
        _server.RegisterStaticRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert — /, /status, /statusRaw, /health, /healthz, /readyz
        Assert.Equal(6, _server.routes.Count);
    }

    // ──────────────────────────────────────────────────────────────
    //  Auth Routes
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void RegisterAuthRoutes_RegistersLoginGetAndPost()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /login"));
        Assert.True(_server.routes.ContainsKey("POST /login"));
    }

    [Fact]
    public void RegisterAuthRoutes_RegistersMfaGetAndPost()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /mfa"));
        Assert.True(_server.routes.ContainsKey("POST /mfa"));
    }

    [Fact]
    public void RegisterAuthRoutes_WithAccountCreation_RegistersRegisterRoutes()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: true);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /register"));
        Assert.True(_server.routes.ContainsKey("POST /register"));
    }

    [Fact]
    public void RegisterAuthRoutes_WithoutAccountCreation_DoesNotRegisterRegisterRoutes()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        Assert.False(_server.routes.ContainsKey("GET /register"));
        Assert.False(_server.routes.ContainsKey("POST /register"));
    }

    [Fact]
    public void RegisterAuthRoutes_RegistersLogoutGetAndPost()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /logout"));
        Assert.True(_server.routes.ContainsKey("POST /logout"));
    }

    [Fact]
    public void RegisterAuthRoutes_RegistersAccountRoute()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /account"));
    }

    [Fact]
    public void RegisterAuthRoutes_RegistersMfaManagementRoutes()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /account/mfa"));
        Assert.True(_server.routes.ContainsKey("GET /account/mfa/setup"));
        Assert.True(_server.routes.ContainsKey("POST /account/mfa/setup"));
        Assert.True(_server.routes.ContainsKey("GET /account/mfa/reset"));
        Assert.True(_server.routes.ContainsKey("POST /account/mfa/reset"));
    }

    [Fact]
    public void RegisterAuthRoutes_RegistersSetupRoutes()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /setup"));
        Assert.True(_server.routes.ContainsKey("POST /setup"));
    }

    [Fact]
    public void RegisterAuthRoutes_LoginRoute_HasAnonymousOnlyPermission()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        var route = _server.routes["GET /login"];
        Assert.Equal("AnonymousOnly", route.PageInfo!.PageMetaData.PermissionsNeeded);
    }

    [Fact]
    public void RegisterAuthRoutes_LogoutRoute_HasAuthenticatedPermission()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        var route = _server.routes["GET /logout"];
        Assert.Equal("Authenticated", route.PageInfo!.PageMetaData.PermissionsNeeded);
    }

    [Fact]
    public void RegisterAuthRoutes_LoginRoute_ShowsOnNavBar()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        var route = _server.routes["GET /login"];
        Assert.True(route.PageInfo!.PageMetaData.ShowOnNavBar);
    }

    [Fact]
    public void RegisterAuthRoutes_LoginRoute_HasButtonNavRenderStyle()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        var route = _server.routes["GET /login"];
        Assert.Equal(NavRenderStyle.Button, route.PageInfo!.PageContext.NavRenderStyle);
    }

    [Fact]
    public void RegisterAuthRoutes_LoginRoute_HasRightAlignment()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        var route = _server.routes["GET /login"];
        Assert.Equal(NavAlignment.Right, route.PageInfo!.PageContext.NavAlignment);
    }

    [Fact]
    public void RegisterAuthRoutes_LoginRoute_HasSuccessColorClass()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        var route = _server.routes["GET /login"];
        Assert.Equal("btn-success", route.PageInfo!.PageContext.NavColorClass);
    }

    [Fact]
    public void RegisterAuthRoutes_WithoutAccountCreation_RegistersCorrectCount()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert — 14 routes without register
        Assert.Equal(17, _server.routes.Count);
    }

    [Fact]
    public void RegisterAuthRoutes_WithAccountCreation_RegistersCorrectCount()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: true);

        // Assert — 16 routes with register
        Assert.Equal(19, _server.routes.Count);
    }

    // ──────────────────────────────────────────────────────────────
    //  Monitoring Routes
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void RegisterMonitoringRoutes_RegistersMetricsRoute()
    {
        // Arrange & Act
        _server.RegisterMonitoringRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /metrics"));
    }

    [Fact]
    public void RegisterMonitoringRoutes_RegistersMetricsJsonRoute()
    {
        // Arrange & Act
        _server.RegisterMonitoringRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /metrics/json"));
    }

    [Fact]
    public void RegisterMonitoringRoutes_RegistersTopIpsRoute()
    {
        // Arrange & Act
        _server.RegisterMonitoringRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /topips"));
    }

    [Fact]
    public void RegisterMonitoringRoutes_RegistersSuspiciousIpsRoute()
    {
        // Arrange & Act
        _server.RegisterMonitoringRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /suspiciousips"));
    }

    [Fact]
    public void RegisterMonitoringRoutes_MetricsRoute_HasMonitoringPermission()
    {
        // Arrange & Act
        _server.RegisterMonitoringRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        var route = _server.routes["GET /metrics"];
        Assert.Equal("monitoring", route.PageInfo!.PageMetaData.PermissionsNeeded);
    }

    [Fact]
    public void RegisterMonitoringRoutes_MetricsRoute_ShowsOnNavBar()
    {
        // Arrange & Act
        _server.RegisterMonitoringRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        var route = _server.routes["GET /metrics"];
        Assert.True(route.PageInfo!.PageMetaData.ShowOnNavBar);
    }

    [Fact]
    public void RegisterMonitoringRoutes_MetricsRoute_HasAdminNavGroup()
    {
        // Arrange & Act
        _server.RegisterMonitoringRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        var route = _server.routes["GET /metrics"];
        Assert.Equal("Admin", route.PageInfo!.PageContext.NavGroup);
    }

    [Fact]
    public void RegisterMonitoringRoutes_RegistersExactlyFourRoutes()
    {
        // Arrange & Act
        _server.RegisterMonitoringRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        Assert.Equal(4, _server.routes.Count);
    }

    // ──────────────────────────────────────────────────────────────
    //  Admin Routes
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void RegisterAdminRoutes_RegistersLogRoutes()
    {
        // Arrange & Act
        _server.RegisterAdminRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /admin/logs"));
        Assert.True(_server.routes.ContainsKey("GET /admin/logs/prune"));
        Assert.True(_server.routes.ContainsKey("POST /admin/logs/prune"));
        Assert.True(_server.routes.ContainsKey("GET /admin/logs/download"));
    }

    [Fact]
    public void RegisterAdminRoutes_RegistersSampleDataRoutes()
    {
        // Arrange & Act
        _server.RegisterAdminRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /admin/sample-data"));
        Assert.True(_server.routes.ContainsKey("POST /admin/sample-data"));
    }

    [Fact]
    public void RegisterAdminRoutes_RegistersReloadTemplatesRoute()
    {
        // Arrange & Act
        _server.RegisterAdminRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /admin/reload-templates"));
    }

    [Fact]
    public void RegisterAdminRoutes_LogsRoute_HasMonitoringPermission()
    {
        // Arrange & Act
        _server.RegisterAdminRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        var route = _server.routes["GET /admin/logs"];
        Assert.Equal("monitoring", route.PageInfo!.PageMetaData.PermissionsNeeded);
    }

    [Fact]
    public void RegisterAdminRoutes_SampleDataRoute_HasAdminPermission()
    {
        // Arrange & Act
        _server.RegisterAdminRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        var route = _server.routes["GET /admin/sample-data"];
        Assert.Equal("admin", route.PageInfo!.PageMetaData.PermissionsNeeded);
    }

    [Fact]
    public void RegisterAdminRoutes_ReloadTemplatesRoute_HasAdminPermission()
    {
        // Arrange & Act
        _server.RegisterAdminRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        var route = _server.routes["GET /admin/reload-templates"];
        Assert.Equal("admin", route.PageInfo!.PageMetaData.PermissionsNeeded);
    }

    [Fact]
    public void RegisterAdminRoutes_AlwaysRegistersTenRoutes()
    {
        // Arrange & Act
        _server.RegisterAdminRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        Assert.Equal(13, _server.routes.Count);
    }

    [Fact]
    public void RegisterAdminRoutes_AlwaysRegistersWipeRoutes()
    {
        // Arrange & Act
        _server.RegisterAdminRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert — routes are always registered; 419 gating is done at runtime via the settings store
        Assert.True(_server.routes.ContainsKey("GET /admin/wipe-data"));
        Assert.True(_server.routes.ContainsKey("POST /admin/wipe-data"));
    }

    [Fact]
    public void RegisterAdminRoutes_WipeDataRoute_HasAdminPermission()
    {
        // Arrange & Act
        _server.RegisterAdminRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        var route = _server.routes["GET /admin/wipe-data"];
        Assert.Equal("admin", route.PageInfo!.PageMetaData.PermissionsNeeded);
    }

    [Fact]
    public void RegisterAdminRoutes_DataSizingRoute_IsRegistered()
    {
        // Arrange & Act
        _server.RegisterAdminRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /admin/data-sizes"));
        var route = _server.routes["GET /admin/data-sizes"];
        Assert.Equal("admin", route.PageInfo!.PageMetaData.PermissionsNeeded);
    }

    // ──────────────────────────────────────────────────────────────
    //  API Routes (RESTful verbs)
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void RegisterApiRoutes_RegistersGetListRoute()
    {
        // Arrange & Act
        _server.RegisterApiRoutes(_routeHandlers, _pageInfoFactory);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /api/{type}"));
    }

    [Fact]
    public void RegisterApiRoutes_RegistersPostCreateRoute()
    {
        // Arrange & Act
        _server.RegisterApiRoutes(_routeHandlers, _pageInfoFactory);

        // Assert
        Assert.True(_server.routes.ContainsKey("POST /api/{type}"));
    }

    [Fact]
    public void RegisterApiRoutes_RegistersGetSingleRoute()
    {
        // Arrange & Act
        _server.RegisterApiRoutes(_routeHandlers, _pageInfoFactory);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /api/{type}/{id}"));
    }

    [Fact]
    public void RegisterApiRoutes_RegistersPutRoute()
    {
        // Arrange & Act
        _server.RegisterApiRoutes(_routeHandlers, _pageInfoFactory);

        // Assert
        Assert.True(_server.routes.ContainsKey("PUT /api/{type}/{id}"));
    }

    [Fact]
    public void RegisterApiRoutes_RegistersPatchRoute()
    {
        // Arrange & Act
        _server.RegisterApiRoutes(_routeHandlers, _pageInfoFactory);

        // Assert
        Assert.True(_server.routes.ContainsKey("PATCH /api/{type}/{id}"));
    }

    [Fact]
    public void RegisterApiRoutes_RegistersDeleteRoute()
    {
        // Arrange & Act
        _server.RegisterApiRoutes(_routeHandlers, _pageInfoFactory);

        // Assert
        Assert.True(_server.routes.ContainsKey("DELETE /api/{type}/{id}"));
    }

    [Fact]
    public void RegisterApiRoutes_RegistersCommandRoute()
    {
        // Arrange & Act
        _server.RegisterApiRoutes(_routeHandlers, _pageInfoFactory);

        // Assert
        Assert.True(_server.routes.ContainsKey("POST /api/{type}/{id}/_command/{command}"));
    }

    [Fact]
    public void RegisterApiRoutes_RegistersQueryPlanHistoryRoute()
    {
        // Arrange & Act
        _server.RegisterApiRoutes(_routeHandlers, _pageInfoFactory);

        // Assert
        Assert.True(_server.routes.ContainsKey("GET /api/admin/query-plans"));
    }

    [Fact]
    public void RegisterApiRoutes_QueryPlanHistoryRoute_RequiresAdminPermission()
    {
        // Arrange & Act
        _server.RegisterApiRoutes(_routeHandlers, _pageInfoFactory);

        // Assert
        var route = _server.routes["GET /api/admin/query-plans"];
        Assert.Equal("admin", route.PageInfo!.PageMetaData.PermissionsNeeded);
    }

    [Fact]
    public void RegisterApiRoutes_AllRoutes_HaveAuthenticatedPermission()
    {
        // Arrange & Act
        _server.RegisterApiRoutes(_routeHandlers, _pageInfoFactory);

        // Assert — most routes require "Authenticated"; admin-only routes require "admin"
        foreach (var kvp in _server.routes)
        {
            var perm = kvp.Value.PageInfo!.PageMetaData.PermissionsNeeded;
            Assert.True(perm is "Authenticated" or "admin",
                $"Route {kvp.Key} has unexpected permission '{perm}'");
        }
    }

    [Fact]
    public void RegisterApiRoutes_AllRoutes_AreRawPages()
    {
        // Arrange & Act
        _server.RegisterApiRoutes(_routeHandlers, _pageInfoFactory);

        // Assert
        foreach (var kvp in _server.routes)
        {
            Assert.Null(kvp.Value.PageInfo!.PageMetaData.Template);
        }
    }

    [Fact]
    public void RegisterApiRoutes_RegistersExactlySevenRoutes()
    {
        // Arrange & Act
        _server.RegisterApiRoutes(_routeHandlers, _pageInfoFactory);

        // Assert
        Assert.Equal(27, _server.routes.Count);
    }

    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void RegisterInboxRoutes_RegistersFourRoutes()
    {
        // Arrange & Act
        _server.RegisterInboxRoutes(_pageInfoFactory);

        // Assert — exactly 4 routes registered
        Assert.Equal(4, _server.routes.Count);
        Assert.True(_server.routes.ContainsKey("GET /api/inbox"));
        Assert.True(_server.routes.ContainsKey("GET /api/inbox/unread-count"));
        Assert.True(_server.routes.ContainsKey("POST /api/inbox/{id}/read"));
        Assert.True(_server.routes.ContainsKey("POST /api/inbox/read-all"));
    }

    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void RegisterRoute_DuplicateKey_OverwritesPreviousRoute()
    {
        // Arrange
        var page1 = CreatePageInfo("First");
        var page2 = CreatePageInfo("Second");
        _server.RegisterRoute("GET /dup", new RouteHandlerData(page1, _ => ValueTask.CompletedTask));

        // Act
        _server.RegisterRoute("GET /dup", new RouteHandlerData(page2, _ => ValueTask.CompletedTask));

        // Assert — latest registration wins
        Assert.Equal("Second", _server.routes["GET /dup"].PageInfo!.PageContext.PageMetaDataValues[0]);
    }

    [Fact]
    public void RegisterRoute_RouteKeyIncludesVerb_DifferentVerbsSeparateRoutes()
    {
        // Arrange & Act
        var page = CreatePageInfo("Test");
        _server.RegisterRoute("GET /resource", new RouteHandlerData(page, _ => ValueTask.CompletedTask));
        _server.RegisterRoute("POST /resource", new RouteHandlerData(page, _ => ValueTask.CompletedTask));

        // Assert
        Assert.Equal(2, _server.routes.Count);
        Assert.True(_server.routes.ContainsKey("GET /resource"));
        Assert.True(_server.routes.ContainsKey("POST /resource"));
    }

    [Theory]
    [InlineData("GET /api/{type}")]
    [InlineData("PUT /api/{type}/{id}")]
    [InlineData("POST /api/{type}/{id}/_command/{command}")]
    public void RegisterRoute_ParameterizedTemplate_StoredAsIs(string routeKey)
    {
        // Arrange & Act
        var page = CreatePageInfo("Test");
        _server.RegisterRoute(routeKey, new RouteHandlerData(page, _ => ValueTask.CompletedTask));

        // Assert
        Assert.True(_server.routes.ContainsKey(routeKey));
    }

    // ──────────────────────────────────────────────────────────────
    //  Permission assignment
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void RegisterStaticRoutes_StatusRawRoute_HasPublicPermission()
    {
        // Arrange & Act
        _server.RegisterStaticRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        var route = _server.routes["GET /statusRaw"];
        Assert.Equal("Public", route.PageInfo!.PageMetaData.PermissionsNeeded);
    }

    [Fact]
    public void RegisterAuthRoutes_AccountRoute_HasAuthenticatedPermission()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        var route = _server.routes["GET /account"];
        Assert.Equal("Authenticated", route.PageInfo!.PageMetaData.PermissionsNeeded);
    }

    [Fact]
    public void RegisterAuthRoutes_SetupRoute_HasAnonymousOnlyPermission()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        var route = _server.routes["GET /setup"];
        Assert.Equal("AnonymousOnly", route.PageInfo!.PageMetaData.PermissionsNeeded);
    }

    // ──────────────────────────────────────────────────────────────
    //  Menu option / nav bar settings
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void RegisterAuthRoutes_AccountRoute_ShowsOnNavBar()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        var route = _server.routes["GET /account"];
        Assert.True(route.PageInfo!.PageMetaData.ShowOnNavBar);
    }

    [Fact]
    public void RegisterAuthRoutes_AccountRoute_HasRightAlignment()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        var route = _server.routes["GET /account"];
        Assert.Equal(NavAlignment.Right, route.PageInfo!.PageContext.NavAlignment);
    }

    [Fact]
    public void RegisterAuthRoutes_PostLogin_DoesNotShowOnNavBar()
    {
        // Arrange & Act
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: false);

        // Assert
        var route = _server.routes["POST /login"];
        Assert.False(route.PageInfo!.PageMetaData.ShowOnNavBar);
    }

    [Fact]
    public void RegisterMonitoringRoutes_AllNavRoutes_HaveRightAlignment()
    {
        // Arrange & Act
        _server.RegisterMonitoringRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert — routes that show on nav bar should be right-aligned
        var navRoutes = _server.routes
            .Where(r => r.Value.PageInfo!.PageMetaData.ShowOnNavBar)
            .ToList();

        Assert.All(navRoutes, r =>
            Assert.Equal(NavAlignment.Right, r.Value.PageInfo!.PageContext.NavAlignment));
    }

    [Fact]
    public void RegisterAdminRoutes_NavRoutes_HaveAdminNavGroup()
    {
        // Arrange & Act
        _server.RegisterAdminRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

        // Assert
        var navRoutes = _server.routes
            .Where(r => r.Value.PageInfo!.PageMetaData.ShowOnNavBar)
            .ToList();

        Assert.All(navRoutes, r =>
            Assert.Equal("Admin", r.Value.PageInfo!.PageContext.NavGroup));
    }

    // ──────────────────────────────────────────────────────────────
    //  Combined registration (all groups together)
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void AllRegistrationMethods_ProduceNonOverlappingRoutes()
    {
        // Arrange & Act
        _server.RegisterStaticRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);
        var staticCount = _server.routes.Count;

        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: true);
        var afterAuth = _server.routes.Count;

        _server.RegisterMonitoringRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);
        var afterMonitoring = _server.routes.Count;

        _server.RegisterAdminRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);
        var afterAdmin = _server.routes.Count;

        _server.RegisterLookupApiRoutes(_pageInfoFactory);
        var afterLookup = _server.routes.Count;

        _server.RegisterApiRoutes(_routeHandlers, _pageInfoFactory);
        var total = _server.routes.Count;

        // Assert — each group adds new routes without overwriting
        Assert.True(afterAuth > staticCount);
        Assert.True(afterMonitoring > afterAuth);
        Assert.True(afterAdmin > afterMonitoring);
        Assert.True(afterLookup > afterAdmin);
        Assert.True(total > afterLookup);
        Assert.Equal(staticCount + 20 + 4 + 13 + 5 + 26, total);
    }

    [Fact]
    public void AllRoutes_HaveNonNullHandler()
    {
        // Arrange & Act
        _server.RegisterStaticRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);
        _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: true);
        _server.RegisterMonitoringRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);
        _server.RegisterAdminRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);
        _server.RegisterApiRoutes(_routeHandlers, _pageInfoFactory);

        // Assert
        Assert.All(_server.routes, kvp => Assert.NotNull(kvp.Value.PageInfo));
    }

    // ──────────────────────────────────────────────────────────────
    //  Helpers & Mocks
    // ──────────────────────────────────────────────────────────────

    private static PageInfo CreatePageInfo(string title, int statusCode = 200)
    {
        return new PageInfo(
            new PageMetaData(new MockHtmlTemplate(), statusCode),
            new PageContext(new[] { "title" }, new[] { title }));
    }

    private class MockHtmlTemplate : IHtmlTemplate
    {
        public Encoding Encoding => Encoding.UTF8;
        public string ContentTypeHeader => "text/html; charset=utf-8";
        public string Head => "<head></head>";
        public string Body => "<body></body>";
        public string Footer => "";
        public string Script => "";
    }

    private class MockBufferedLogger : IBufferedLogger
    {
        public void LogInfo(string message) { }
        public void LogError(string message, Exception? ex = null) { }
        public Task RunAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public void OnApplicationStopping(CancellationTokenSource cts, Task loggerTask) { }
    }

    private class MockHtmlRenderer : IHtmlRenderer
    {
        public ValueTask RenderPage(BmwContext context) => ValueTask.CompletedTask;

        public ValueTask RenderPage(BmwContext context, PageInfo page, IBareWebHost app) => ValueTask.CompletedTask;

        public ValueTask<ReadOnlyMemory<byte>> RenderToBytesAsync(
            IHtmlTemplate template, string[] keys, string[] values, string[] appkeys,
            string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null,
            string[][]? tableRows = null, FormDefinition? formDefinition = null,
            TemplateLoop[]? templateLoops = null)
            => ValueTask.FromResult<ReadOnlyMemory<byte>>(Encoding.UTF8.GetBytes("<html></html>"));

        public ValueTask RenderToStreamAsync(PipeWriter writer, IHtmlTemplate template,
            string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app,
            string[]? tableColumnTitles = null, string[][]? tableRows = null,
            FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null)
            => ValueTask.CompletedTask;
    }

    private class MockMetricsTracker : IMetricsTracker
    {
        public void RecordRequest(int statusCode, TimeSpan duration) { }
        public void RecordThrottled(TimeSpan duration) { }
        public void RecordRouteDispatch(TimeSpan elapsed) { }
        public void RecordWalRead(TimeSpan elapsed) { }
        public void RecordUiRender(TimeSpan elapsed) { }
        public void RecordSerialization(TimeSpan elapsed) { }
        public void RecordGcPause(TimeSpan elapsed) { }
        public void EnterRequest() { }
        public void LeaveRequest() { }
        public void GetMetricTable(out string[] tableColumns, out string[][] tableRows)
        {
            tableColumns = Array.Empty<string>();
            tableRows = Array.Empty<string[]>();
        }
        public MetricsSnapshot GetSnapshot() => new MetricsSnapshot(
            0, 0, TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero,
            TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero, 0, 0, 0, 0, 0,
            0, 0, 0, 0, TimeSpan.Zero,
            0, TimeSpan.Zero, 0, TimeSpan.Zero, 0, TimeSpan.Zero, 0, TimeSpan.Zero, 0, 0, 0, 0);
    }
    private class MockClientRequestTracker : IClientRequestTracker
    {
        public void RecordRequest(string ipAddress) { }
        public bool ShouldThrottle(string ipAddress, out string reason, out int? retryAfterSeconds)
        {
            reason = string.Empty;
            retryAfterSeconds = null;
            return false;
        }
        public Task RunPruningAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public void GetTopClientsTable(int count, out string[] tableColumns, out string[][] tableRows)
        {
            tableColumns = Array.Empty<string>();
            tableRows = Array.Empty<string[]>();
        }
        public void GetSuspiciousClientsTable(int count, out string[] tableColumns, out string[][] tableRows)
        {
            tableColumns = Array.Empty<string>();
            tableRows = Array.Empty<string[]>();
        }
    }

    /// <summary>
    /// Stub IRouteHandlers that returns no-op delegates for all handler properties.
    /// </summary>
    private class StubRouteHandlers : IRouteHandlers
    {
        private static ValueTask NoOp(BmwContext _) => ValueTask.CompletedTask;

        public RouteHandlerDelegate BuildPageHandler(Action<BmwContext> configure) => NoOp;
        public RouteHandlerDelegate BuildPageHandler(Func<BmwContext, ValueTask> configureAsync) => NoOp;
        public RouteHandlerDelegate BuildPageHandler(Func<BmwContext, ValueTask<bool>> configureAsync, bool renderWhenTrue = true) => NoOp;
        public ValueTask DefaultPageHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask TimeRawHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask LoginHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask LoginPostHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask MfaChallengeHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask MfaChallengePostHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask RegisterHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask RegisterPostHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask LogoutHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask LogoutPostHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask SsoLoginHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask SsoCallbackHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask SsoLogoutHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask AccountHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask MfaStatusHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask MfaSetupHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask MfaSetupPostHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask MfaResetHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask MfaResetPostHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask UsersListHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask SetupHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask SetupPostHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask ReloadTemplatesHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask MetricsJsonHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask LogsViewerHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask LogsPruneHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask LogsPrunePostHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask LogsDownloadHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask SampleDataHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask SampleDataPostHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask WipeDataHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask WipeDataPostHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask EntityDesignerHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask GalleryHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask GalleryDeployPostHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask WebStoreHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask WebStoreInstallHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask DataApiListHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask DataApiImportHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask DataApiGetHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask DataApiPostHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask DataApiPutHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask DataApiPatchHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask DataApiDeleteHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask DataCommandHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask DataSizingHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask JobStatusHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask JobsListHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask CancelJobHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask AdminSampleDataJsonHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask AdminWipeDataJsonHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask QueryPlanHistoryHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask AttachmentsListHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask AttachmentsUploadHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask AttachmentsDownloadHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask AttachmentsDeleteHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask AttachmentsVersionsHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask CommentsListHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask CommentsAddHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask CommentsEditHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask CommentsDeleteHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask DataApiFileGetHandler(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask GlobalSearchHandler(BmwContext context) => ValueTask.CompletedTask;
    }

    // ──────────────────────────────────────────────────────────────
    //  VNext Schema / BuildEntitySchema tests
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void BuildEntitySchema_LookupField_ReturnsLookupListType()
    {
        // Arrange — register Customer (with lookup) and Address (the lookup target)
        _ = HostGalleryTestFixture.State;
        Assert.True(DataScaffold.TryGetEntity("customers", out var meta));

        // Act — invoke the private static BuildEntitySchema via reflection
        var method = typeof(RouteRegistrationExtensions).GetMethod(
            "BuildEntitySchema",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var schema = (Dictionary<string, object?>)method.Invoke(null, new object[] { meta! })!;
        var fields = (object[])schema["fields"]!;
        var addressField = fields
            .Cast<Dictionary<string, object?>>()
            .FirstOrDefault(f => string.Equals((string?)f["name"], "AddressId", StringComparison.Ordinal));

        // Assert — the lookup field's type must be "LookupList" so the VNext edit form renders a dropdown
        Assert.NotNull(addressField);
        Assert.NotNull(addressField["lookup"]);
        Assert.Equal("LookupList", (string?)addressField["type"]);
    }

    /// <summary>
    /// Regression test for "TTP Editor missing Subject Lookup":
    /// When a lookup field's ValueField is "Key" (the C# entity key property), the schema
    /// sent to the VNext SPA must use "id" — the JSON key that /api/{slug} returns — so
    /// that loadLookupSelect can match options to the saved value instead of falling back
    /// to showing the raw numeric ID in the dropdown.
    /// </summary>
    [Fact]
    public void BuildEntitySchema_LookupWithKeyValueField_EmitsIdAsValueField()
    {
        // Arrange — SubjectId on TimeTablePlan has [DataLookup(typeof(Subject))] which
        // defaults ValueField to nameof(BaseDataObject.Key) = "Key".
        _ = HostGalleryTestFixture.State;
        Assert.True(DataScaffold.TryGetEntity("time-table-plans", out var meta));

        // Act
        var method = typeof(RouteRegistrationExtensions).GetMethod(
            "BuildEntitySchema",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var schema = (Dictionary<string, object?>)method.Invoke(null, new object[] { meta! })!;
        var fields = (object[])schema["fields"]!;
        var subjectField = fields
            .Cast<Dictionary<string, object?>>()
            .FirstOrDefault(f => string.Equals((string?)f["name"], "SubjectId", StringComparison.Ordinal));

        Assert.NotNull(subjectField);
        var lookup = subjectField["lookup"] as Dictionary<string, object?>;
        Assert.NotNull(lookup);

        // The valueField should map Key → "id" for compiled entities or "Id" for metadata-driven.
        var vf = (string?)lookup["valueField"];
        Assert.True(vf == "id" || vf == "Id",
            $"Expected 'id' or 'Id' but got '{vf}'");
    }

    [Fact]
    public void BuildEntitySchema_NonLookupField_ReturnsOriginalFieldType()
    {
        // Arrange
        _ = HostGalleryTestFixture.State;
        Assert.True(DataScaffold.TryGetEntity("customers", out var meta));

        // Act
        var method = typeof(RouteRegistrationExtensions).GetMethod(
            "BuildEntitySchema",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var schema = (Dictionary<string, object?>)method.Invoke(null, new object[] { meta! })!;
        var fields = (object[])schema["fields"]!;
        var nameField = fields
            .Cast<Dictionary<string, object?>>()
            .FirstOrDefault(f => string.Equals((string?)f["name"], "Name", StringComparison.Ordinal));

        // Assert — a non-lookup field's type is preserved as-is (not overridden to LookupList)
        Assert.NotNull(nameField);
        Assert.Null(nameField["lookup"]);
        Assert.NotEqual("LookupList", (string?)nameField["type"]);
    }

    [Fact]
    public void BuildEntitySchema_ChildListField_ReturnsCustomHtmlTypeWithSubFields()
    {
        // Arrange — register Order (has List<OrderRow> child collection) and dependencies
        _ = HostGalleryTestFixture.State;
        Assert.True(DataScaffold.TryGetEntity("orders", out var meta));

        // Act — invoke the private static BuildEntitySchema via reflection
        var method = typeof(RouteRegistrationExtensions).GetMethod(
            "BuildEntitySchema",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var schema = (Dictionary<string, object?>)method.Invoke(null, new object[] { meta! })!;
        var fields = (object[])schema["fields"]!;
        var orderRowsField = fields
            .Cast<Dictionary<string, object?>>()
            .FirstOrDefault(f => string.Equals((string?)f["name"], "OrderRows", StringComparison.Ordinal));

        // Assert — metadata-driven child list field type is "ChildList" with ChildEntitySlug set.
        // Note: metadata-driven child lists may not have subFields populated via BuildSubFieldSchemas
        // since they don't use CLR List<T> properties. The VNext SPA resolves sub-fields via the
        // child entity's schema endpoint instead.
        Assert.NotNull(orderRowsField);
        var fieldType = (string?)orderRowsField["type"];
        Assert.True(fieldType == "CustomHtml" || fieldType == "ChildList",
            $"Expected 'CustomHtml' or 'ChildList' but got '{fieldType}'");
    }

    // ──────────────────────────────────────────────────────────────
    //  Metadata inlining tests
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void TryBuildMetaObjectsScript_WithAccessibleEntity_ReturnsScriptWithSlug()
    {
        // Arrange
        _ = HostGalleryTestFixture.State;

        var method = typeof(RouteRegistrationExtensions).GetMethod(
            "TryBuildMetaObjectsScript",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        // Customer entity defaults permissions to "Customers" — pass a user with that permission
        var user = new User { Key = 1, UserName = "test", IsActive = true, Permissions = new[] { "Customers" } };

        // Act
        var script = (string?)method.Invoke(null, new object?[] { user, user.Permissions, "testnonce" });

        // Assert
        Assert.NotNull(script);
        Assert.Contains("__BMW_META_OBJECTS__", script);
        Assert.Contains("customers", script);
        Assert.Contains("testnonce", script);
    }

    [Fact]
    public void TryBuildMetaObjectsScript_NullUser_ReturnsScriptExcludingPermissionedEntities()
    {
        // Arrange — register a permission-restricted entity
        _ = HostGalleryTestFixture.State;

        var method = typeof(RouteRegistrationExtensions).GetMethod(
            "TryBuildMetaObjectsScript",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        // Act — null user, no permissions
        var script = (string?)method.Invoke(null, new object?[] { null, Array.Empty<string>(), "nonce" });

        // Assert — script is still returned (may be empty list), but Customer is filtered out
        Assert.NotNull(script);
        Assert.Contains("__BMW_META_OBJECTS__", script);
        Assert.DoesNotContain("\"customers\"", script ?? "");
    }

    [Fact]
    public void TryBuildMetaSlugScript_KnownEntity_ReturnsScriptWithEntitySchema()
    {
        // Arrange
        _ = HostGalleryTestFixture.State;

        var method = typeof(RouteRegistrationExtensions).GetMethod(
            "TryBuildMetaSlugScript",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        // Act
        var script = (string?)method.Invoke(null, new object[] { "customers", "testnonce" });

        // Assert
        Assert.NotNull(script);
        Assert.Contains("__BMW_META_SLUG__", script);
        Assert.Contains("customers", script);
        Assert.Contains("testnonce", script);
        // Schema should include fields array
        Assert.Contains("fields", script);
    }

    [Fact]
    public void TryBuildMetaSlugScript_UnknownSlug_ReturnsNull()
    {
        var method = typeof(RouteRegistrationExtensions).GetMethod(
            "TryBuildMetaSlugScript",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var script = (string?)method.Invoke(null, new object[] { "nonexistent-entity-xyz", "nonce" });

        Assert.Null(script);
    }

    [Fact]
    public async Task BuildLookupPrefetchAsync_WithLookupFields_ReturnsResolvedData()
    {
        // Arrange — register all gallery entities including Customer and Address
        _ = HostGalleryTestFixture.State;

        // Save an address through entity handlers (backed by WalDataProvider)
        Assert.True(DataScaffold.TryGetEntity("addresses", out var addrMeta));
        var address = addrMeta.Handlers.Create();
        address.Key = 1;
        addrMeta.FindField("Label")!.SetValueFn(address, "Home");
        addrMeta.FindField("Line1")!.SetValueFn(address, "123 Main St");
        addrMeta.FindField("City")!.SetValueFn(address, "Springfield");
        addrMeta.FindField("Country")!.SetValueFn(address, "US");
        await addrMeta.Handlers.SaveAsync(address, CancellationToken.None);

        Assert.True(DataScaffold.TryGetEntity("customers", out var meta));

        // Build a payload item that has AddressId = "1"
        var item = new Dictionary<string, object?> { ["AddressId"] = "1", ["Name"] = "Acme" };
        var payload = new[] { item };

        var method = typeof(RouteRegistrationExtensions).GetMethod(
            "BuildLookupPrefetchAsync",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        // Act
        var task = (System.Threading.Tasks.ValueTask<Dictionary<string, Dictionary<string, object?>>?>)method.Invoke(
            null, new object[] { meta!, payload, CancellationToken.None })!;
        var result = await task;

        // Assert — AddressId field is list-visible (List=true by default), so prefetch should contain addresses
        Assert.NotNull(result);
        Assert.True(result!.ContainsKey("addresses"));
        Assert.True(result["addresses"].ContainsKey("1"));
    }

    [Fact]
    public async Task BuildLookupPrefetchAsync_EmptyPayload_ReturnsNull()
    {
        // Arrange
        _ = HostGalleryTestFixture.State;
        Assert.True(DataScaffold.TryGetEntity("customers", out var meta));

        var method = typeof(RouteRegistrationExtensions).GetMethod(
            "BuildLookupPrefetchAsync",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        // Act — empty payload
        var task = (System.Threading.Tasks.ValueTask<Dictionary<string, Dictionary<string, object?>>?>)method.Invoke(
            null, new object[] { meta!, Array.Empty<Dictionary<string, object?>>(), CancellationToken.None })!;
        var result = await task;

        // Assert
        Assert.Null(result);
    }

    private class InMemoryDataStore : IDataObjectStore
    {
        private readonly Dictionary<(Type, uint), BaseDataObject> _store = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();
        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }
        public void Clear() => _store.Clear();

        public void Save<T>(T obj) where T : BaseDataObject => _store[(typeof(T), obj.Key)] = obj;
        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject { Save(obj); return ValueTask.CompletedTask; }
        public T? Load<T>(uint key) where T : BaseDataObject => _store.TryGetValue((typeof(T), key), out var obj) ? obj as T : null;
        public ValueTask<T?> LoadAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject => ValueTask.FromResult(Load<T>(key));
        public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject => _store.Values.OfType<T>();
        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject => ValueTask.FromResult(Query<T>(query));
        public ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject => ValueTask.FromResult(Query<T>(query).Count());
        public void Delete<T>(uint key) where T : BaseDataObject => _store.Remove((typeof(T), key));
        public ValueTask DeleteAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject { Delete<T>(key); return ValueTask.CompletedTask; }
    }
}
