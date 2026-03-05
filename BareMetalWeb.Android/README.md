# BareMetalWeb Android Shell

Thin WebView wrapper that packages the BareMetalWeb SPA as a native Android app.

## Build

```bash
cd BareMetalWeb.Android
./gradlew assembleRelease
```

## Configuration

Edit `app/src/main/res/values/strings.xml` to set your server URL:
```xml
<string name="server_url">https://your-server.example.com</string>
```

## Features

- Full-screen WebView with the BareMetalWeb SPA
- Push notification support via Firebase Cloud Messaging
- Offline splash screen
- Deep link handling for `baremetalweb://` URLs
- Hardware back button navigation within the SPA
- File upload support
- Network connectivity monitoring
