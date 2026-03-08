# ── Multi-stage AOT build ─────────────────────────────────────────────
# Stage 1: Build with .NET SDK (produces self-contained native binary)
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Install clang for AOT native compilation
RUN apt-get update && apt-get install -y --no-install-recommends clang zlib1g-dev && rm -rf /var/lib/apt/lists/*

# Copy solution and project files first for layer caching
COPY BareMetalWeb.sln ./
COPY BareMetalWeb.Core/BareMetalWeb.Core.csproj BareMetalWeb.Core/
COPY BareMetalWeb.Data/BareMetalWeb.Data.csproj BareMetalWeb.Data/
COPY BareMetalWeb.Rendering/BareMetalWeb.Rendering.csproj BareMetalWeb.Rendering/
COPY BareMetalWeb.Runtime/BareMetalWeb.Runtime.csproj BareMetalWeb.Runtime/
COPY BareMetalWeb.Host/BareMetalWeb.Host.csproj BareMetalWeb.Host/

RUN dotnet restore BareMetalWeb.Host/BareMetalWeb.Host.csproj

# Copy everything else and publish
COPY . .

ARG VERSION=0.0.0+local
RUN dotnet publish BareMetalWeb.Host/BareMetalWeb.Host.csproj \
    --configuration Release \
    --output /app \
    -p:InformationalVersion="${VERSION}"

# Create the data directory in the build stage (chiseled has no shell)
RUN mkdir -p /app/Data

# ── Stage 2: Minimal runtime image ───────────────────────────────────
# Chiseled image: distroless, no shell, no package manager, non-root by default.
# runtime-deps only — AOT binary has no JIT dependency.
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-chiseled

WORKDIR /app

# Copy the published AOT binary, config, and data directory
COPY --from=build /app .

# Persistent data directory — mount a volume here in production
VOLUME /app/Data

# Default port — override with PORT env var at runtime
ENV PORT=5232
EXPOSE 5232

# Non-root user (chiseled images default to 'app' UID 1654)
USER app

ENTRYPOINT ["./BareMetalWeb.Host"]
