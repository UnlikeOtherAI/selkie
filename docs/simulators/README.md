# Simulator & Emulator Streaming

> Remote desktop access to iOS simulators and Android emulators, served over
> the web through selkie's zero-trust access layer.

## Documents in this folder

- [architecture.md](architecture.md) — full system design: capture pipeline,
  lifecycle manager, pool, app cloning, URL generation, selkie integration
- [ios.md](ios.md) — iOS-specific detail: xcrun simctl, capture, input injection
- [android.md](android.md) — Android-specific detail: AVD management, adb
  screenrecord, emulator gRPC API
- [config.md](config.md) — configuration schema and reference
- [research.md](research.md) — deep research report: simctl output format,
  CoreGraphics capture, idb_companion stability, Android emulator gRPC,
  WebCodecs browser support, AVD cloning edge cases
- [scripting.md](scripting.md) — manual scripting: record sidebar, action
  timeline editor, replay with tap/swipe overlays, Final Record handoff
- [research-2.md](research-2.md) — deep research report: macOS TCC screen
  recording for daemons, fMP4 incremental demux in Go (mp4ff), MSE live push
  patterns, idb_companion on Apple Silicon (arm64 breakage)
- [headless-recording.md](headless-recording.md) — multi-headless recording:
  spawn headless WebKit instances via MCP, batch-execute scripts, async job
  polling, output file path control
