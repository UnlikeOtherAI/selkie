# Headless Multi-Recording

> Spawn headless WebKit instances to execute recording scripts in parallel,
> controllable via MCP tools. Each job returns an ID for async status polling.

## Overview

The headless recording system enables LLMs and automation tools to batch-execute
recording scripts without a visible browser. Each recording job:

1. Spawns a headless WebKit instance with a configured viewport.
2. Connects to a simulator stream.
3. Loads and executes a recording script (from [scripting.md](scripting.md)).
4. Composites tap/swipe/text overlays onto the stream.
5. Writes the output video to a specified file path.
6. Reports completion asynchronously via job status polling.

Multiple jobs run concurrently, limited by a configurable max concurrency.

---

## MCP Tools

All tools use the `selkie_` prefix (matching the selkie MCP namespace).

### `selkie_headless_record`

Start a new headless recording job.

**Input:**

```typescript
{
  // Required
  script: Script;               // Full script object (see scripting.md data model)
  udid: string;                 // Target simulator UDID
  viewport: {
    width: number;              // Logical pixels, e.g. 390
    height: number;             // Logical pixels, e.g. 844
  };
  output_path: string;          // Absolute path for the output video file

  // Optional
  create_directories?: boolean; // Create missing parent dirs (default: true)
  output_format?: "mp4" | "webm"; // Default: "mp4"
  playback_speed?: number;      // 0.5, 1, 2 — default: 1
  overlay?: boolean;            // Composite tap/swipe overlays (default: true)
  timeout_seconds?: number;     // Max job duration before abort (default: 300)
}
```

**Output:**

```typescript
{
  job_id: string;               // UUID — use to poll status
  status: "queued";
  message: "Recording job queued";
}
```

**Errors:**

| Code | Condition |
|------|-----------|
| `invalid_script` | Script JSON fails validation |
| `simulator_not_found` | UDID does not match a booted simulator |
| `simulator_busy` | Simulator is already running a script or recording |
| `path_not_writable` | Output path parent exists but is not writable |
| `max_concurrency` | All recording slots are in use — retry later |

### `selkie_headless_status`

Poll the status of a recording job.

**Input:**

```typescript
{
  job_id: string;
}
```

**Output:**

```typescript
{
  job_id: string;
  status: "queued" | "running" | "completed" | "failed" | "aborted";
  progress?: {
    current_step: number;       // 0-indexed
    total_steps: number;
    elapsed_ms: number;
    estimated_remaining_ms?: number;
  };
  result?: {                    // Present when status is "completed"
    output_path: string;        // Confirmed path of the written file
    file_size_bytes: number;
    duration_ms: number;        // Video duration
    steps_executed: number;
    steps_skipped: number;      // Disabled steps
  };
  error?: {                     // Present when status is "failed"
    step_index?: number;        // Step that failed (if applicable)
    message: string;
  };
}
```

### `selkie_headless_abort`

Cancel a running or queued recording job.

**Input:**

```typescript
{
  job_id: string;
}
```

**Output:**

```typescript
{
  job_id: string;
  status: "aborted";
  message: "Job aborted";
  partial_output_path?: string; // If partial file was written
}
```

### `selkie_headless_list`

List all active and recent recording jobs.

**Input:**

```typescript
{
  status_filter?: "queued" | "running" | "completed" | "failed" | "aborted";
  limit?: number;               // Default: 20
}
```

**Output:**

```typescript
{
  jobs: Array<{
    job_id: string;
    status: string;
    udid: string;
    script_name: string;
    output_path: string;
    created_at: string;         // ISO 8601
    completed_at?: string;
  }>;
}
```

---

## Architecture

### Headless WebKit Instance

Each recording job spawns a headless `WKWebView` process. On macOS this uses
`WKWebViewConfiguration` with:

```swift
let config = WKWebViewConfiguration()
config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
let webView = WKWebView(frame: CGRect(x: 0, y: 0,
                                       width: viewport.width,
                                       height: viewport.height),
                        configuration: config)
```

The process runs without a window (no `NSWindow`). The WebView loads the stream
client page, which connects to the simulator's stream endpoint and renders the
video feed plus overlay canvas.

### Recording Pipeline

```
┌─────────────┐     ┌───────────────┐     ┌──────────────┐
│  Headless    │     │  Stream       │     │  Simulator   │
│  WKWebView   │◄────│  Proxy        │◄────│  Capture     │
│              │     │  (WebSocket)  │     │  Service     │
│  stream +    │     └───────────────┘     └──────────────┘
│  overlay     │
│  canvas      │          ┌───────────────┐
│      │       │          │  Script       │
│      ▼       │          │  Executor     │
│  captureStream()        │  (step loop)  │───► idb/adb
│      │       │          └───────────────┘
│      ▼       │
│  MediaRecorder           
│      │       │
│      ▼       │
│  Write to    │
│  output_path │
└─────────────┘
```

The headless WebKit instance runs two parallel operations:

1. **Stream rendering**: WebSocket connection to the simulator stream, rendered
   on a `<canvas>` element with overlay compositing.
2. **Script execution**: the server-side executor runs the script steps via
   `POST /script/{udid}/run` with `record: true`. SSE events drive the overlay
   animations on the canvas.

The `canvas.captureStream(30)` API feeds a `MediaRecorder` that writes the
composited output (stream + overlays) to the specified output file.

### Output File Handling

**Directory creation:** when `create_directories` is `true` (the default), the
server calls `mkdir -p` on the parent directory of `output_path` before
starting the job. If the directory cannot be created (permissions, disk full),
the job fails immediately with `path_not_writable`.

**File naming:** the output file is written atomically — first to a temporary
file (`{output_path}.tmp`), then renamed on completion. This prevents partial
files from appearing at the final path if the job is aborted.

**Overwrite behavior:** if a file already exists at `output_path`, the job
overwrites it. The MCP tool does not check for existing files — the caller is
responsible for path uniqueness.

### Concurrency

```yaml
headless_recording:
  max_concurrent_jobs: 4          # Total across all simulators
  max_per_simulator: 1            # One recording per simulator at a time
  job_history_retention: "24h"    # Keep completed/failed job records
  default_timeout_seconds: 300
```

Jobs exceeding `max_concurrent_jobs` are queued (FIFO). Queued jobs start
automatically when a slot opens. Jobs waiting in queue for longer than
`queue_timeout_seconds` (default: 120) are failed with `max_concurrency`.

Only one recording job can target a given simulator at a time
(`max_per_simulator: 1`). A second job targeting the same UDID is queued until
the first completes.

---

## Job Lifecycle

```
                    ┌─────────┐
     submit ──────► │ queued  │
                    └────┬────┘
                         │ slot available
                    ┌────▼────┐
                    │ running │◄─── resume (after pause, if supported)
                    └────┬────┘
                    ┌────┼────────────┐
               ┌────▼──┐  ┌────▼───┐  ┌───▼────┐
               │complete│  │ failed │  │aborted │
               └────────┘  └────────┘  └────────┘
```

**State transitions:**

| From | To | Trigger |
|------|----|---------|
| — | `queued` | `selkie_headless_record` called |
| `queued` | `running` | Concurrency slot available, headless WebKit spawned |
| `queued` | `aborted` | `selkie_headless_abort` called |
| `running` | `completed` | All steps executed, video written |
| `running` | `failed` | Step error, timeout, simulator crash, write error |
| `running` | `aborted` | `selkie_headless_abort` called |

Failed and completed jobs retain their status records for `job_history_retention`
(default 24h), then are purged. The output file is not deleted on purge.

---

## Viewport Configuration

The viewport dimensions control the headless WebKit's rendering size, which
directly determines the output video resolution.

| Viewport | Output resolution | Use case |
|----------|-------------------|----------|
| `390 x 844` | 390x844 | iPhone 15 (1x logical) |
| `780 x 1688` | 780x1688 | iPhone 15 (2x Retina) |
| `1170 x 2532` | 1170x2532 | iPhone 15 (3x full res) |
| `360 x 800` | 360x800 | Android medium density |
| `1080 x 2400` | 1080x2400 | Android full HD |

The stream viewport inside the WebView scales the simulator feed to fill the
canvas. If the viewport aspect ratio differs from the simulator's, the stream is
letterboxed (black bars) — the overlay coordinates are adjusted via the
`coordinate_mapper` in `libscriptcore`.

---

## HTTP API (Internal)

These endpoints are used internally by the MCP tool layer. They are not exposed
through selkie's zero-trust proxy — only the MCP tools are the external
interface.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/headless/jobs` | Create a recording job |
| `GET` | `/headless/jobs` | List jobs (query: `?status=running&limit=20`) |
| `GET` | `/headless/jobs/{job_id}` | Get job status |
| `DELETE` | `/headless/jobs/{job_id}` | Abort a job |

Request body for `POST /headless/jobs`:

```typescript
{
  script: Script;
  udid: string;
  viewport: { width: number; height: number };
  output_path: string;
  create_directories: boolean;
  output_format: "mp4" | "webm";
  playback_speed: number;
  overlay: boolean;
  timeout_seconds: number;
}
```

Response matches `selkie_headless_status` output format.

---

## Error Handling

### Step execution failure

If a step fails during headless recording, the job transitions to `failed`. The
error includes the step index and message. No partial video is saved at
`output_path` (the temp file is deleted). If the caller needs partial output,
they can check `partial_output_path` in the abort response, though this is only
available on explicit abort, not on step failure.

### Simulator disconnection

If the simulator stream drops during recording (reboot, crash, network), the
headless WebKit detects the WebSocket close event. The job fails with:

```json
{
  "error": {
    "step_index": 5,
    "message": "Simulator stream disconnected at step 5"
  }
}
```

### Timeout

Jobs exceeding `timeout_seconds` are aborted by the system. The status becomes
`failed` with message `"Job timed out after {N} seconds"`. The temp file is
deleted.

### Disk space

Before starting the recording, the system checks that the output directory has
at least 500MB of free space. If not, the job fails immediately with
`"Insufficient disk space"`.

---

## Integration with libscriptcore

The headless recording system uses `libscriptcore` (see
[scripting.md](scripting.md#cross-platform-c-core-library)) for:

- **`script_parser`**: validates the incoming script JSON.
- **`step_scheduler`**: drives step execution timing and state transitions.
- **`coordinate_mapper`**: maps between logical and canvas coordinates for the
  configured viewport size.
- **`overlay_geometry`**: computes overlay shapes for the canvas renderer.

The headless WebKit loads `libscriptcore.wasm` the same way the interactive
browser client does. No additional C++ bindings are needed.

---

## MCP Usage Examples

### Record a script to a specific path

```json
{
  "tool": "selkie_headless_record",
  "input": {
    "script": { "version": 1, "name": "Login flow", "...": "..." },
    "udid": "ABCD-1234-EFGH-5678",
    "viewport": { "width": 390, "height": 844 },
    "output_path": "/recordings/2026-04-06/login-flow.mp4",
    "create_directories": true
  }
}
```

Response:
```json
{
  "job_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "status": "queued",
  "message": "Recording job queued"
}
```

### Poll until done

```json
{
  "tool": "selkie_headless_status",
  "input": {
    "job_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
  }
}
```

Response (in progress):
```json
{
  "job_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "status": "running",
  "progress": {
    "current_step": 5,
    "total_steps": 12,
    "elapsed_ms": 7200,
    "estimated_remaining_ms": 7000
  }
}
```

Response (completed):
```json
{
  "job_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "status": "completed",
  "result": {
    "output_path": "/recordings/2026-04-06/login-flow.mp4",
    "file_size_bytes": 4823040,
    "duration_ms": 14200,
    "steps_executed": 11,
    "steps_skipped": 1
  }
}
```

### Batch record multiple scripts

An LLM can fire multiple `selkie_headless_record` calls in parallel, each
targeting a different simulator (or the same simulator sequentially via the
queue). Each returns its own `job_id` for independent polling.

```
selkie_headless_record(script_a, udid_1, ...) → job_1
selkie_headless_record(script_b, udid_2, ...) → job_2
selkie_headless_record(script_c, udid_1, ...) → job_3  (queued behind job_1)

selkie_headless_status(job_1) → running
selkie_headless_status(job_2) → running
selkie_headless_status(job_3) → queued
```

---

## Out of Scope for v1

- **Live preview via MCP** — headless jobs produce a file, not a live stream.
  Watching progress requires polling `selkie_headless_status`.
- **Job priority** — queue is FIFO only, no priority levels.
- **Distributed recording** — all jobs run on the local machine. Multi-machine
  orchestration is a v2 concern.
- **Audio capture** — video only. Simulator audio is not captured.
- **Webhook notifications** — completion is poll-based via MCP. SSE/webhook
  callbacks for job completion can be added in v2.
