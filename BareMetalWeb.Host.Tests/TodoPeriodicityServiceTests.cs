using System;

namespace BareMetalWeb.Host.Tests;

public class TodoPeriodicityServiceTests
{
    // ── AdvanceDeadline ───────────────────────────────────────────────────────

    [Theory]
    [InlineData("Hourly",    1,  0)]
    [InlineData("Daily",     1,  0)]
    [InlineData("Weekly",    7,  0)]
    [InlineData("Monthly",   0,  1)]
    [InlineData("Quarterly", 0,  3)]
    [InlineData("Yearly",    0, 12)]
    public void AdvanceDeadline_ReturnsDateStrictlyAfterNow(
        string periodicity, int addDays, int addMonths)
    {
        // Arrange
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = DateOnly.FromDateTime(nowUtc).AddDays(-1); // already past

        // Act
        var result = TodoPeriodicityService.AdvanceDeadline(current, periodicity, nowUtc);

        // Assert
        Assert.True(result > DateOnly.FromDateTime(nowUtc),
            $"Expected advanced date to be after {DateOnly.FromDateTime(nowUtc)} but got {result}");
    }

    [Fact]
    public void AdvanceDeadline_Hourly_AdvancesByOneDay()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = new DateOnly(2025, 6, 14);

        var result = TodoPeriodicityService.AdvanceDeadline(current, "Hourly", nowUtc);

        Assert.Equal(new DateOnly(2025, 6, 16), result);
    }

    [Fact]
    public void AdvanceDeadline_Daily_AdvancesByOneDay()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = new DateOnly(2025, 6, 14);

        var result = TodoPeriodicityService.AdvanceDeadline(current, "Daily", nowUtc);

        Assert.Equal(new DateOnly(2025, 6, 16), result);
    }

    [Fact]
    public void AdvanceDeadline_Weekly_AdvancesBySevenDays()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = new DateOnly(2025, 6, 8);

        var result = TodoPeriodicityService.AdvanceDeadline(current, "Weekly", nowUtc);

        Assert.Equal(new DateOnly(2025, 6, 22), result);
    }

    [Fact]
    public void AdvanceDeadline_Monthly_AdvancesByOneMonth()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = new DateOnly(2025, 5, 10);

        var result = TodoPeriodicityService.AdvanceDeadline(current, "Monthly", nowUtc);

        Assert.Equal(new DateOnly(2025, 7, 10), result);
    }

    [Fact]
    public void AdvanceDeadline_Quarterly_AdvancesByThreeMonths()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = new DateOnly(2025, 3, 1);

        var result = TodoPeriodicityService.AdvanceDeadline(current, "Quarterly", nowUtc);

        Assert.Equal(new DateOnly(2025, 9, 1), result);
    }

    [Fact]
    public void AdvanceDeadline_Yearly_AdvancesByOneYear()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = new DateOnly(2024, 6, 1);

        var result = TodoPeriodicityService.AdvanceDeadline(current, "Yearly", nowUtc);

        Assert.Equal(new DateOnly(2026, 6, 1), result);
    }

    [Fact]
    public void AdvanceDeadline_FarInPast_SkipsMultiplePeriods()
    {
        // current is 14 days in the past; weekly should skip forward to first future occurrence
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = new DateOnly(2025, 6, 1); // 14 days ago

        var result = TodoPeriodicityService.AdvanceDeadline(current, "Weekly", nowUtc);

        // 2025-06-01 + 7 = 2025-06-08 (still past) + 7 = 2025-06-15 (today, still <=) + 7 = 2025-06-22
        Assert.Equal(new DateOnly(2025, 6, 22), result);
    }
}
