# Simulator Manual Scripting

> Record interactions on a live simulator stream, build an editable timeline,
> preview the result, then hand off to the existing recording pipeline.

## Overview

Manual scripting adds a sidebar to the simulator stream browser UI. The user
records their own gestures live, edits the captured timeline (delays, tap
colours, labels), previews a replay, and when satisfied triggers Final Record —
which executes the timeline through the existing capture infrastructure and
produces the finished video.

---

## User Flow

```
Open stream → Open sidebar → Record tab
  → [Start Recording]
      ↓ user taps and scrolls on the simulator view
      ↓ user types text in the sidebar text injection field
      ↓ each action appears in the live action list
  → [Stop Recording]
      ↓ auto-switches to Timeline tab

Timeline tab
  → reorder / delete / edit steps
  → set per-step delay, tap colour, label
  → add manual Wait steps

Preview tab
  → [Play Preview]
      ↓ timeline executes on the live simulator
      ↓ tap/swipe indicators animate in the browser overlay
      ↓ user watches the result
  → [Final Record]
      ↓ hands off to existing recording mode
      ↓ indicators are composited into the output video
```

---

## Native Button Rule (macOS)

If any part of this UI is implemented as a native macOS sidebar (rather than
a browser-only overlay), every button in the sidebar must be an **AppKit-backed
`NSButton` subclass** via `NSViewRepresentable`. SwiftUI `Button` views in a
window that also contains a `WKWebView` or CEF renderer lose mouse events due
to the WebView capturing first-responder status. Follow the
`AppKitToolbarButton` / `AppKitSegmentedStrip` pattern from the kelpie URL bar.

This rule applies to: Start/Stop Recording, Clear, Import, Export, Add Step,
Delete, Play Preview, Stop, Final Record, Undo, every tab selector, and every
drag handle.

If the sidebar is entirely rendered inside the browser's DOM (not native), this
rule does not apply — all controls are standard HTML elements.

---

## Sidebar Layout

The sidebar occupies the right edge of the stream viewer window. It mirrors the
AI sidebar in position and visual treatment.

### Dimensions and responsiveness

```
┌───────────────────────────────────┬────────────────────┐
│                                   │                    │
│         Stream viewport           │     Sidebar        │
│         (scales to fill)          │   320px default    │
│                                   │   min: 280px       │
│                                   │   max: 480px       │
│                                   │   resize handle ┃  │
│                                   │                    │
└───────────────────────────────────┴────────────────────┘
```

- Default width: **320px**. User-resizable via a drag handle on the left edge.
- Minimum: 280px. Below this the sidebar collapses to an icon-only toolbar
  rail (24px) showing tab icons only. Click any icon to re-expand.
- Maximum: 480px.
- When the window width < 600px the sidebar overlays the stream as a sheet
  rather than occupying a fixed column.
- The sidebar header (tabs) is always visible. Content scrolls independently.

### Tab bar

```
┌──────────────────────────────────────┐
│  [● Record]  [≡ Timeline]  [▷ Preview] │
├──────────────────────────────────────┤
```

Active tab has a bottom accent bar (2px, `--accent-color`). Inactive tabs are
dimmed. Tab text is hidden below 300px width — only icons show.

Keyboard shortcut to cycle tabs: `Cmd+1` / `Cmd+2` / `Cmd+3`.

---

## Record Tab

### Controls

```
┌──────────────────────────────────────┐
│  ● REC  00:04.231                    │
│  [■ Stop Recording]                  │
├──────────────────────────────────────┤
│                                      │
│  Live action list                    │
│  ┌────────────────────────────────┐  │
│  │ 00:00.000  ● tap  (195, 400)  │  │
│  │ 00:00.823  ◻ wait     823 ms  │  │
│  │ 00:01.204  ↗ swipe  ↑ 400px   │  │
│  │ 00:01.950  ⌨ text  "hello@…"  │  │
│  │ 00:02.800  ● tap  (120, 680)  │◄ │
│  └────────────────────────────────┘  │
│                                      │
│  Auto-scrolls to latest entry        │
│                                      │
├──────────────────────────────────────┤
│  [Clear]   [Import JSON] [Export JSON]│
├──────────────────────────────────────┤
│  Text injection (visible during     │
│  recording only):                   │
│  ┌────────────────────────────┐     │
│  │ Type here to inject text…  │     │
│  └────────────────────────────┘     │
│  Text entered here is injected live │
│  into the simulator and captured as │
│  a TextStep. Committed on Enter or  │
│  after 500ms of no input.           │
└──────────────────────────────────────┘
```

### States

**Idle (no recording in progress):**
- "Start Recording" button visible, red background, white text.
- Timer shows 00:00.000.
- Action list shows previous recording (if any) or empty state.

**Recording:**
- Button changes to "Stop Recording" (dark background, white square icon).
- Timer counts up in real time (mm:ss.mmm).
- Red pulsing dot (●) in the tab header replaces the tab icon.
- A red semitransparent border pulses around the stream viewport to indicate
  recording is active.
- [Clear] and [Import JSON] are disabled while recording is active.
- Tab switching is locked: Record tab stays active until recording stops.
- New entries append at the bottom. List auto-scrolls to follow unless the
  user manually scrolls up. If the user scrolls away, a "Jump to latest"
  pill appears anchored at the bottom of the list. Clicking it resumes
  auto-scroll.
- Each new entry briefly flashes with a highlight background (200ms fade).
- Accidental stop recovery: immediately after stopping, an "Undo stop" link
  appears for 3 seconds. Clicking it resumes recording from where it left off,
  appending to the existing action list rather than replacing it.

### Script naming

A text field in the sidebar header (between the tab bar and the content area)
shows the script name. Default: "Untitled script". Click to edit inline.
The name is editable from any tab. Changes are saved on blur or Enter.

**Empty state (no actions recorded):**
```
┌────────────────────────────────────┐
│                                    │
│     Tap, swipe, or scroll in       │
│     the simulator view to          │
│     start building your script.    │
│                                    │
│     [Import JSON]                  │
│                                    │
└────────────────────────────────────┘
```

### Recording feedback on the stream

While recording, a canvas overlay on the stream viewport renders:

- **Tap**: translucent red ring at tap position, expanding from 10px to 40px
  over 300ms, opacity 0.6 → 0.0. Colour: `#FF3B30` at 60% opacity.
- **Swipe/Scroll**: a 3px red trail following the pointer from start to end,
  fading out over 500ms after pointer up.
- **Text**: no stream overlay; captured in the sidebar text field.

The recording indicator (pulsing red border around the stream) uses:
```css
border: 2px solid rgba(255, 59, 48, 0.7);
animation: pulse 1.5s ease-in-out infinite;
```

---

## Timeline Tab — Block Design

The timeline is the core editing interface. Each step is rendered as a
**block** — a compact interactive card that can be collapsed or expanded.

### Block anatomy (collapsed — default)

```
┌──────────────────────────────────────────────────────────┐
│ ⠿  ● (195, 400)  "Tap login button"    500ms    [×]    │
└──────────────────────────────────────────────────────────┘
  │   │  │            │                    │         │
  │   │  coordinates  label (truncated)    delay     delete
  │   type icon + colour dot
  drag handle
```

- **Drag handle** (⠿): 6-dot grip on the left. Cursor changes to `grab` on
  hover, `grabbing` during drag.
- **Type icon**: `●` tap (filled circle in `tap_color`), `↗` swipe, `↕`
  scroll, `⌨` text, `⏎` key, `◻` wait.
- **Coordinates or value**: tap shows `(x, y)`, swipe shows `→ dx, dy`,
  scroll shows `↑↓ delta`, text shows `"first 20 chars…"`, wait shows
  `duration_ms`.
- **Label**: truncated with ellipsis if > 20 chars in collapsed view.
- **Delay badge**: rounded pill showing `delay_before_ms` value. Light grey
  background. Click to edit inline.
- **Delete button** [×]: appears on hover only (unless the block is selected).
  12px muted icon, red on hover.

Height: **36px** collapsed.

### Block anatomy (expanded)

Click anywhere on the collapsed block (except drag handle or delete) to
expand it. Only one block can be expanded at a time — expanding one collapses
any other.

```
┌──────────────────────────────────────────────────────────┐
│ ⠿  ● (195, 400)  "Tap login button"    500ms    [×]    │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Label:  [Tap login button                      ]        │
│                                                          │
│  Position:  x [195]   y [400]          [Re-pick ◎]      │
│                                                          │
│  Delay before:  [500] ms                                 │
│                                                          │
│  Tap colour:  [● #FF3B30]   Size: [40] px                │
│  Animation:   [ripple ▾]                                 │
│                                                          │
│  Recorded at: 00:01.204  (read-only)                     │
│                                                          │
│  [Duplicate]   [Insert before]   [Insert after]          │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

For swipe blocks, the expanded view adds:
```
│  Start:  x [195]  y [600]          [Re-pick start ◎]    │
│  End:    x [195]  y [200]          [Re-pick end ◎]      │
│  Duration: [300] ms                                      │
│  Trail colour: [● #FF3B30]                               │
```

For text blocks:
```
│  Text:  [hello@example.com                      ]        │
```

For scroll blocks:
```
│  Anchor:  x [200]  y [500]          [Re-pick ◎]         │
│  Delta:   dx [0]   dy [-400]                             │
│  Duration: [300] ms                                      │
│  Scroll colour: [● #FF3B30]                              │
```

For key blocks:
```
│  Key: [home ▾]                                           │
│  (dropdown filtered by script.platform — iOS-only and    │
│   Android-only keys hidden for the wrong platform)       │
```

For wait blocks:
```
│  Duration: [1000] ms                                     │
```

All expanded blocks include an **Enabled** checkbox in the bottom-left corner:
```
│  [✓ Enabled]                                             │
```
Unchecking it sets `enabled: false`, dims the block to 50% opacity, and adds
a strikethrough on the label. The step is skipped during replay.

### Block interaction states

| State | Visual treatment |
|-------|-----------------|
| Default | White background, 1px border `#E5E5E5` |
| Hover | Light grey background `#F5F5F5`, shadow lifts slightly |
| Selected (clicked) | Blue left accent bar (3px), expanded view opens |
| Drag in progress | Block lifts with drop shadow (8px blur), 5% scale up, 0.9 opacity. A horizontal blue line (2px) appears at the drop target position between blocks |
| Drag over valid drop zone | Drop line turns solid blue, gap between blocks opens to 8px |
| Error (failed during replay) | Red left accent bar, red background tint `rgba(255,0,0,0.05)`, error icon replaces type icon |
| Currently executing (replay) | Pulsing blue left accent bar, slight blue background tint |
| Disabled (idb unavailable) | 50% opacity, no pointer events |

### Clicking a block highlights on stream

When any block is selected (expanded), the stream viewport shows a persistent
**position indicator** at the block's coordinates:

- **Tap block**: crosshair + translucent circle at `(x, y)` in `tap_color`.
  Circle diameter = `tap_size`. Crosshair extends 20px beyond the circle.
- **Swipe block**: start point (filled dot) → end point (arrow head), connected
  by a dashed line in `swipe_color`. Both endpoints show coordinate labels.
- **Scroll block**: anchor point with directional arrow showing scroll vector.
- **Key**: no stream indicator.

The indicator stays visible as long as the block is expanded. Collapsing the
block removes it. This is how the user "clicks through stuff" — clicking block
after block shows where each action targets on the simulator screen.

**Important limitation:** the stream is live. Clicking a block shows the
overlay at the stored coordinates on the *current* simulator frame, not the
frame that was visible when the action was originally recorded. If the
simulator has navigated away from that screen, the coordinates may not
correspond to the intended UI element. This is intentional — the overlay is a
spatial reference aid, not a state-aware replayer. To verify that coordinates
still hit the correct targets after editing, use Preview (which replays the
full script from the beginning and puts the simulator through the actual state
transitions).

### Click-through navigation

**Arrow keys** navigate between blocks when the timeline has focus:
- `↑` / `↓`: move selection to previous / next block.
- `Enter`: expand the selected block (or collapse if already expanded).
- `Escape`: collapse the expanded block and return focus to the block list.
- `Delete` / `Backspace`: delete the selected block (with undo).

**Click on stream**: when a block is expanded and showing its position
indicator on the stream, clicking elsewhere on the stream viewport updates the
block's coordinates to the clicked position (same as "Re-pick" but implicit).
This lets the user click a block, then click the stream to reposition it.

---

## Reorder (Drag and Drop)

### Initiation

- Drag starts only from the **drag handle** (⠿). Dragging from other parts of
  the block does not initiate drag — it selects/expands.
- Touch: long-press (300ms) on the drag handle initiates drag on touch devices.

### During drag

- The dragged block lifts out of the list with a drop shadow and slight
  enlargement (scale 1.05).
- The original position shows a dashed border placeholder (same height as the
  collapsed block).
- A **blue drop line** (2px solid, full sidebar width) appears between blocks
  at the nearest valid drop position, tracking the pointer.
- Blocks above and below the drop line shift smoothly (150ms ease) to open a
  gap.
- The timeline scrolls automatically when the dragged block approaches the top
  or bottom of the visible area (scroll speed: 3px/frame within 40px of edge).

### Drop

- Release drops the block at the line position. The list reflows with a 200ms
  ease transition.
- If dropped on the same position: no-op, block returns with no animation.
- An undo entry is pushed (see Undo section).

### Cancel

- `Escape` during drag cancels and returns the block to its original position
  with a snap-back animation (200ms ease-out).
- Dragging outside the sidebar area cancels the drag.

---

## Insert

### Insert points

Between every pair of blocks, and at the top and bottom of the list, there is
an invisible **insert zone** (8px tall). On hover the zone renders as:

```
          ···· [+ Insert] ····
```

A dashed line with a centred "+ Insert" pill. Click it to open the insert menu.

### Insert menu

A dropdown anchored to the insert point:

```
┌─────────────────┐
│  ● Tap          │
│  ↗ Swipe        │
│  ↕ Scroll       │
│  ⌨ Text         │
│  ⏎ Key          │
│  ◻ Wait         │
└─────────────────┘
```

Selecting a type inserts a new block at that position with default values and
immediately expands it for editing. For Tap, the stream enters single-click
pick mode: the next click sets `(x, y)` and pick mode exits. For Swipe, the
stream enters two-click pick mode: the first click sets `start_x/start_y`,
the second click sets `end_x/end_y`, then pick mode exits. A step counter
("Click start point" → "Click end point") appears in the pick banner. Scroll
also uses single-click pick for the anchor point.

### Insert from expanded block

The expanded block view includes [Insert before] and [Insert after] buttons as
an alternative entry point. These open the same insert menu positioned above or
below the current block.

### Duplicate

The expanded block includes a [Duplicate] button. It creates an identical copy
inserted immediately after the current block with a new UUID. The duplicate
opens expanded.

---

## Delete

### Single delete

Click the [×] on a block (visible on hover or when selected). The block slides
out to the right (200ms) and the list collapses. An undo toast appears at the
bottom of the sidebar for 5 seconds:

```
┌──────────────────────────────────────────────┐
│  Deleted "Tap login button"       [Undo]     │
└──────────────────────────────────────────────┘
```

### Multi-select and bulk delete

- `Cmd+Click` toggles individual block selection (adds blue checkmark to the
  left of the drag handle).
- `Shift+Click` selects a range from the last selected block to the clicked
  block.
- When multiple blocks are selected, a **bulk action bar** appears pinned to
  the bottom of the timeline:

```
┌──────────────────────────────────────────────┐
│  3 selected     [Delete]    [Deselect all]   │
└──────────────────────────────────────────────┘
```

- Clicking [Delete] removes all selected blocks and pushes a single undo entry
  that restores all of them.

### Undo / Redo

- `Cmd+Z` undoes the last edit (delete, reorder, insert, property change).
- `Cmd+Shift+Z` redoes.
- Undo stack depth: 50 entries.
- Undo applies within the current timeline session. Switching tabs or saving
  does not clear the stack, but closing the sidebar does.

---

## Re-pick Flow

When the user clicks [Re-pick] (or [Re-pick start] / [Re-pick end] for swipe):

1. The sidebar dims slightly (opacity 0.7) and a banner appears at the top:
   ```
   Click on the simulator to set new position. [Cancel]
   ```
2. The stream viewport cursor changes to crosshair.
3. The existing position indicator on the stream blinks to show the current
   value.
4. The user clicks on the stream. The coordinates update in the block's fields.
5. The position indicator snaps to the new location.
6. Pick mode exits automatically after the click. The sidebar returns to full
   opacity.
7. For swipe [Re-pick start] / [Re-pick end]: only one point updates per pick.
   The user must explicitly click [Re-pick end] to change the other endpoint.
8. [Cancel] or `Escape` exits pick mode without changing coordinates.

---

## Preview Tab

### Controls

```
┌──────────────────────────────────────────────────┐
│  Script: "Login flow demo"                       │
│  Steps: 12    Duration: ~14.2s                   │
├──────────────────────────────────────────────────┤
│                                                  │
│  [▶ Play]   [⏸ Pause]   [⏹ Stop]               │
│                                                  │
│  Speed: [0.5x] [1x] [2x]                        │
│                                                  │
│  ━━━━━━━━━━━━━━━━━━░░░░░░  4.2 / 14.2 s        │
│  Step 5 of 12: "Tap login button"                │
│                                                  │
├──────────────────────────────────────────────────┤
│                                                  │
│  Step list (read-only, live highlight)           │
│  ┌──────────────────────────────────────────┐    │
│  │ ✓  ● tap   (195, 400)   "Open app"     │    │
│  │ ✓  ◻ wait  500ms                       │    │
│  │ ✓  ● tap   (120, 300)   "Tap email"    │    │
│  │ ✓  ⌨ text  "hello@…"                   │    │
│  │ ▶  ● tap   (195, 400)   "Tap login" ◄  │    │
│  │ ○  ◻ wait  1000ms                      │    │
│  │ ○  ↗ swipe ↑ 400px                     │    │
│  │ …                                       │    │
│  └──────────────────────────────────────────┘    │
│                                                  │
│  ✓ = completed   ▶ = executing   ○ = pending    │
│                                                  │
├──────────────────────────────────────────────────┤
│  [ Final Record ]                                │
│  Disabled until preview completes without error  │
└──────────────────────────────────────────────────┘
```

### Playback controls

- **Play**: executes the script on the live simulator. During play, the step
  list auto-scrolls to the current step (indicated with ▶). The stream shows
  the tap/swipe overlays.
- **Pause**: pauses execution between the current step and the next. The
  current step completes (input is injected atomically). Resume by clicking
  Play again.
- **Stop**: aborts execution. The simulator remains in its current state.
  Sends `DELETE /script/{udid}/run`.
- **Speed**: affects the `delay_before_ms` between steps only (not swipe/scroll
  `duration_ms`). At 2x, delays are halved. At 0.5x, delays are doubled.
- **Progress bar**: shows elapsed time vs estimated total. Not scrubbable (you
  cannot seek in a live simulator). The bar fills as steps complete.
- **Step counter**: "Step N of M: label" updates in real time.

### Step-through mode

For fine-grained control, hold `Shift` while clicking Play. This enters
**step-through mode**: the executor pauses after each step. Click Play (or
press `Space`) to advance one step. Click Stop or press `Escape` to abort.

### Error during preview

If a step fails (idb/adb error, timeout), the step list entry shows a red
icon and a brief error message. Execution halts. The user can:

- Click the failed step to switch to the Timeline tab with that block expanded.
- Fix the issue and click [Play] again (resumes from the failed step).

---

## Visual Overlay Specification

### Tap indicator

| Property | Value |
|----------|-------|
| Shape | Filled circle |
| Colour | `tap_color` from step (default `#FF3B30`) |
| Initial radius | 0px |
| Final radius | `tap_size / 2` px |
| Expand duration | 150ms, `ease-out` |
| Hold at final size | 100ms |
| Fade out | 250ms, opacity 1.0 → 0.0 |
| Total visible time | 500ms |
| Opacity at peak | 0.6 |
| Z-order | Above stream, below any UI chrome |
| Border | none |

### Swipe trail

| Property | Value |
|----------|-------|
| Shape | Line from start to end |
| Colour | `swipe_color` from step (default `#FF3B30`) |
| Line width | 3px |
| Dash pattern | none (solid during trace), then dashes during fade |
| Trace animation | Line draws from start to end over `duration_ms` |
| End cap | Arrow head (6px) at the end point |
| Start cap | Filled dot (6px diameter) at the start point |
| Fade after trace | 400ms, opacity 0.8 → 0.0 |
| Z-order | Same layer as tap indicators |

### Scroll trail

| Property | Value |
|----------|-------|
| Shape | Line from anchor to anchor + delta |
| Colour | `scroll_color` from step (default `#FF3B30`) |
| Line width | 3px |
| Dash pattern | none (solid during trace), then dashes during fade |
| Trace animation | Line draws over `duration_ms` |
| End cap | Arrow head (6px) indicating scroll direction |
| Start cap | Filled dot (6px diameter) at anchor point |
| Fade after trace | 400ms, opacity 0.8 → 0.0 |
| Z-order | Same layer as tap indicators |

### Text indicator

| Property | Value |
|----------|-------|
| Shape | Rounded rectangle pill at bottom-centre of stream |
| Background | `rgba(0, 0, 0, 0.7)` |
| Text colour | white |
| Font | 13px system monospace |
| Content | keyboard icon + first 30 chars of text |
| Duration | 600ms (200ms fade in, 200ms hold, 200ms fade out) |

### Wait indicator

| Property | Value |
|----------|-------|
| Shape | Circular spinner at centre of stream |
| Colour | `rgba(255, 255, 255, 0.5)` |
| Size | 24px diameter |
| Animation | Rotating arc, 1 revolution per second |
| Duration | visible for the full `duration_ms` of the wait step |

### Label pill (Tap, Swipe, Scroll steps only — if label is non-empty)

| Property | Value |
|----------|-------|
| Shape | Rounded rectangle, positioned 8px above the tap/swipe/scroll anchor point |
| Background | `rgba(0, 0, 0, 0.75)` |
| Text colour | white |
| Font | 11px system sans-serif, medium weight |
| Max width | 200px (truncate with ellipsis) |
| Duration | Same as the parent indicator |

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Cmd+1` | Switch to Record tab |
| `Cmd+2` | Switch to Timeline tab |
| `Cmd+3` | Switch to Preview tab |
| `Cmd+Z` | Undo last timeline edit |
| `Cmd+Shift+Z` | Redo |
| `↑` / `↓` | Navigate between blocks (Timeline tab) |
| `Enter` | Expand/collapse selected block |
| `Escape` | Collapse expanded block / cancel pick mode / cancel drag |
| `Delete` | Delete selected block(s) |
| `Space` | Start/pause preview playback (Preview tab) |
| `Cmd+D` | Duplicate selected block |
| `Cmd+A` | Select all blocks (Timeline tab) |
| `Cmd+Click` | Toggle block selection |
| `Shift+Click` | Range select blocks |
| `Cmd+/` | Toggle enabled/disabled on selected block(s) |
| `Shift+Play` | Step-through mode (Preview tab) |

---

## Data Model: Script

```typescript
interface Script {
  version: 1;
  name: string;
  platform: "ios" | "android";
  device_type: string;     // e.g. "iPhone 15"
  bundle_id: string;
  created_at: string;      // ISO 8601
  updated_at: string;      // ISO 8601

  settings: {
    default_tap_color: string;   // CSS hex, e.g. "#FF3B30"
    default_tap_size: number;    // logical px diameter, e.g. 40
    default_tap_animation: "ripple" | "pulse" | "none";
    default_swipe_color: string;
    auto_wait_threshold_ms: number; // default 500
    playback_speed: number;         // 0.5, 1, 2
  };

  steps: Step[];
}

type Step =
  | TapStep
  | SwipeStep
  | ScrollStep
  | TextStep
  | KeyStep
  | WaitStep;

interface BaseStep {
  id: string;             // uuid
  label: string;          // user-editable description
  delay_before_ms: number; // pause before executing this step
  recorded_at_ms: number; // offset from recording start (0 for manual inserts)
  enabled: boolean;       // false = skip during replay (greyed out in timeline)
}

interface TapStep extends BaseStep {
  type: "tap";
  x: number;   // logical pixels
  y: number;
  tap_color: string;      // overrides default
  tap_size: number;
  tap_animation: "ripple" | "pulse" | "none"; // overrides default
}

interface SwipeStep extends BaseStep {
  type: "swipe";
  start_x: number;
  start_y: number;
  end_x: number;
  end_y: number;
  duration_ms: number;
  swipe_color: string;
}

interface ScrollStep extends BaseStep {
  type: "scroll";
  x: number;         // anchor point
  y: number;
  delta_x: number;   // logical px
  delta_y: number;
  duration_ms: number;
  scroll_color: string;  // overrides default_swipe_color
}

interface TextStep extends BaseStep {
  type: "text";
  text: string;
}

interface KeyStep extends BaseStep {
  type: "key";
  key_code: KeyCode;
}

// Supported key codes (union of iOS and Android)
type KeyCode =
  | "home"       // iOS: home button; Android: KEYCODE_HOME (3)
  | "back"       // Android only: KEYCODE_BACK (4)
  | "return"     // Enter / submit
  | "backspace"  // Delete backward
  | "delete"     // Delete forward (iOS only)
  | "escape"     // Escape
  | "tab"        // Tab
  | "space"      // Space bar
  | "up" | "down" | "left" | "right"  // Arrow keys
  | "volume_up" | "volume_down"       // Hardware volume
  | "power"      // Android: KEYCODE_POWER (26)
  | "lock"       // iOS: lock button
  | "menu"       // Android: KEYCODE_MENU (82)
  | "siri";      // iOS: Siri button

// Platform validation: sc_script_parse rejects key codes that are
// incompatible with script.platform. The timeline editor's key dropdown
// only shows codes valid for the current platform. Cross-platform codes
// (return, backspace, escape, tab, space, arrows, volume) are always shown.

interface WaitStep extends BaseStep {
  type: "wait";
  duration_ms: number;
}
```

---

## Recording: Capturing Interactions

During recording the simulator stream is displayed normally in the browser.
The browser client intercepts pointer and keyboard events on the stream
viewport and converts them to Step records.

### Event capture (client-side)

An invisible overlay `<div>` sits above the `<video>`/`<img>` element. It
intercepts pointer events, records them as steps, **and simultaneously forwards
them to the existing input injection proxy** (`POST /input/{udid}`). The
simulator receives every gesture in real time — the overlay does not block
interaction. Steps are recorded after successful injection; if injection fails,
the step is still recorded but flagged with a warning icon.

Events intercepted:

| DOM event | Captured as |
|-----------|------------|
| `pointerdown` + `pointerup` (same position +/-5px, <300ms) | TapStep |
| `pointerdown` -> `pointermove` -> `pointerup` | SwipeStep or ScrollStep |
| `input` on sidebar text field (buffered — committed on Enter or 500ms idle) | TextStep |
| `keydown` for known function keys | KeyStep |
| gap between events > threshold | auto-WaitStep |

Scroll vs swipe disambiguation: if the primary axis displacement is vertical
and the velocity is above a threshold, emit ScrollStep; otherwise SwipeStep.

Wait steps are inserted automatically when the gap between two consecutive
recorded events exceeds `auto_wait_threshold_ms` (default 500ms, configurable
in script settings). Gaps below the threshold are absorbed into the
`delay_before_ms` of the next step.

### Coordinate mapping

The stream viewport renders at a scaled size. All stored coordinates are in
**simulator logical pixels**, not viewport pixels. The client maps at capture
time:

```
logical_x = viewport_x / (viewport_width / sim_logical_width)
logical_y = viewport_y / (viewport_height / sim_logical_height)
```

The simulator's logical dimensions are provided by the server in the session
metadata (`screen_width_px / scale_factor`, `screen_height_px / scale_factor`).

**Rotation:** if the simulator rotates during recording, stored coordinates
become invalid for the new orientation. Recording does not pause automatically.
Steps recorded before the rotation retain their original coordinates. The user
should re-pick affected steps after rotation, or use Preview to verify that
coordinates still hit the correct targets.

---

## Replay Execution

### Server-side executor

The server receives the `Script` object as a `POST /script/{udid}/run` request.
The response includes a `run_id` (UUID) that identifies this execution:

```json
{ "run_id": "a1b2c3d4-...", "status": "started", "total_steps": 12 }
```

The client connects to the SSE stream at `GET /script/{udid}/events?run_id={run_id}`
to receive progress events. The `run_id` binds pause, resume, and abort
requests to the correct execution. If the SSE connection drops, the client
reconnects to the same URL — the server replays missed events from the run's
event log (capped at the full run, not a fixed ring buffer).

The executor runs steps sequentially:

```
for each step in script.steps:
  if not step.enabled: skip, emit script.progress with status "skipped"
  sleep(step.delay_before_ms / playback_speed)
  dispatch to platform input layer (idb / adb)
  emit progress event to browser via SSE: { step_id, status, wall_clock_ms }
```

The input dispatch reuses the same idb/adb calls already defined in
[ios.md](ios.md) and [android.md](android.md).

Request body for `POST /script/{udid}/run`:

```typescript
{
  script: Script;
  record?: boolean;           // true = Final Record mode (captures video)
  playback_speed?: number;    // 0.5, 1, 2 — default: 1
  start_from_step?: number;   // 0-indexed step to start from (default: 0)
}
```

When `start_from_step` is set, steps before that index are skipped (no
execution, no SSE events). This is used to resume after a failed step —
the client sets `start_from_step` to the index of the failed step.

SSE event types:

| Event | Payload |
|-------|---------|
| `script.progress` | `{ step_id, status: "executing"\|"completed"\|"skipped"\|"failed", wall_clock_ms }` |
| `script.paused` | `{ after_step_id }` |
| `script.error` | `{ step_id, error_message }` |
| `script.complete` | `{ total_duration_ms, output_path? }` |
| `script.aborted` | `{}` |

Abort: `DELETE /script/{udid}/run?run_id={run_id}`. The server terminates the
step loop.

Pause: `POST /script/{udid}/pause?run_id={run_id}`. The server finishes the
current step then waits. Resume: `POST /script/{udid}/resume?run_id={run_id}`.

---

## Final Record

### What it does

Final Record executes the script in replay mode but simultaneously starts the
platform video capture pipeline and composites the tap/swipe indicators into
the output.

### Compositing

**Interactive browser (default for Preview):** the browser records the stream
canvas (stream + overlay combined) using `MediaRecorder` with
`canvas.captureStream()`. The output is a WebM file downloaded locally. This is
the Preview path and is not Final Record.

**Final Record (v1 authoritative path):** Final Record is always server-driven.
The client sends `POST /script/{udid}/run` with `record: true`. The server:

1. Starts the platform video capture (`simctl io recordVideo` / `adb screenrecord`).
2. Executes the script steps via idb/adb.
3. Stops capture after the last step completes.
4. Composites overlay indicators onto the raw capture using ffmpeg.
5. Returns the output file path in the `script.complete` SSE event.

The server always completes the full pipeline regardless of client connection
state. On reconnect, the `script.complete` event delivers the `output_path`.

Client-side `MediaRecorder` recording is available as a convenience for quick
exports but is not the Final Record path. The [Final Record] button always
triggers the server-side pipeline.

---

## Persistence

Scripts are stored as JSON files on the client (localStorage or IndexedDB) and
optionally uploaded to the server as named assets attached to the simulator
service. The server stores them at `/scripts/{service_id}/{script_id}.json`
under the agent's data directory.

The `service_id` identifies the simulator service instance in selkie's service
catalog. The `udid` is the simulator's unique device identifier. The client
obtains both from the session metadata when connecting to a stream. Script
storage is keyed by `service_id` (persistent across simulator reboots);
execution is keyed by `udid` (addresses the running simulator process).

Script CRUD:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/scripts/{service_id}` | list scripts |
| `GET` | `/scripts/{service_id}/{script_id}` | fetch script |
| `PUT` | `/scripts/{service_id}/{script_id}` | save / update |
| `DELETE` | `/scripts/{service_id}/{script_id}` | delete |
| `POST` | `/script/{udid}/run` | execute (preview or record), returns `run_id` |
| `GET` | `/script/{udid}/events?run_id={run_id}` | SSE stream for run progress |
| `POST` | `/script/{udid}/pause?run_id={run_id}` | pause execution |
| `POST` | `/script/{udid}/resume?run_id={run_id}` | resume execution |
| `DELETE` | `/script/{udid}/run?run_id={run_id}` | abort execution |

### Saved scripts browser

When the sidebar opens and no script is loaded, the Record tab shows a saved
scripts list above the recording controls:

```
┌──────────────────────────────────────┐
│  Saved scripts                       │
│  ┌────────────────────────────────┐  │
│  │ Login flow demo     2 min ago  │  │
│  │ Onboarding tour     yesterday  │  │
│  │ Settings check      Apr 3      │  │
│  └────────────────────────────────┘  │
│  Click to load, or start a new      │
│  recording below.                   │
└──────────────────────────────────────┘
```

**Empty state (no saved scripts):**
```
│  No saved scripts yet.              │
│  Record your first interaction      │
│  below, or import a JSON file.      │
```

---

## Cross-Platform C++ Core Library

### Motivation

The scripting engine (script parsing, step scheduling, coordinate mapping,
replay state machine, overlay geometry computation) should be implemented once
in portable C++ and reused across all platforms: the Go server agent (via cgo),
the browser client (compiled to WASM), and any future native clients (iOS app,
Android app, macOS app, Windows/Linux desktop).

### What lives in C++ (`libscriptcore`)

| Module | Responsibility |
|--------|---------------|
| `script_parser` | Deserialise/validate Script JSON, versioned schema migration |
| `step_scheduler` | Walk the step list, apply delays and speed multiplier, emit step events, handle pause/resume/abort state transitions |
| `coordinate_mapper` | Convert between logical pixels, viewport pixels, and canvas pixels given a `ScreenGeometry` struct. Handles scale factor, aspect ratio letterboxing, and rotation |
| `overlay_geometry` | Compute overlay shapes (circle position, swipe trail path, label pill position) from step data and current canvas size. Does NOT render — returns geometry primitives (circles, lines, rects with colours and timings) for the platform renderer to draw |
| `script_differ` | Diff two Script objects for undo/redo. Produces a reversible patch (insert, delete, move, property change) |
| `timeline_model` | In-memory step list with indexed access, insert-at, remove-at, move, multi-select, enable/disable. Emits change events. Backs the timeline UI on all platforms |

### What does NOT live in C++

- **Rendering**: each platform draws overlays using its own graphics API
  (HTML canvas, CoreGraphics, Android Canvas, Skia). The C++ layer emits
  geometry, the platform layer draws it.
- **Input capture**: pointer/touch event handling is inherently platform-specific.
  The platform layer captures events and pushes them into the C++ `timeline_model`.
- **Input injection**: idb, adb, simctl calls are OS-specific. The C++ scheduler
  emits a "dispatch step" event; the platform handler executes it.
- **Network transport**: SSE, WebSocket, HTTP calls are platform-specific. The
  C++ library is transport-agnostic.
- **Persistence**: file I/O and IndexedDB are platform-specific. The C++ library
  serialises to/from JSON byte buffers.

### Build targets

| Target | Binding | Notes |
|--------|---------|-------|
| WASM (browser) | Emscripten, exported C API consumed by JS | `libscriptcore.wasm` loaded by the web client |
| Go (server agent) | cgo, thin Go wrapper in `internal/scriptcore` | Links `libscriptcore.a` statically |
| iOS / macOS | Swift package wrapping the C API via module map | Framework: `ScriptCore.xcframework` |
| Android | JNI via Kotlin, NDK build | Shared library: `libscriptcore.so` |
| Linux / Windows | C API, dynamic or static linking | For desktop clients or CI tooling |

### C API surface (header sketch)

```c
// libscriptcore.h

typedef struct sc_script sc_script;
typedef struct sc_scheduler sc_scheduler;
typedef struct sc_timeline sc_timeline;
typedef struct sc_geometry sc_geometry;

// --- Script parsing ---
sc_script* sc_script_parse(const char* json, size_t len, char** error_out);
void       sc_script_free(sc_script* s);
char*      sc_script_to_json(const sc_script* s, size_t* len_out);

// --- Timeline model ---
sc_timeline* sc_timeline_create(sc_script* s);
void         sc_timeline_free(sc_timeline* t);
int          sc_timeline_count(const sc_timeline* t);
int          sc_timeline_insert(sc_timeline* t, int index, const char* step_json);
int          sc_timeline_remove(sc_timeline* t, int index);
int          sc_timeline_move(sc_timeline* t, int from_index, int to_index);
int          sc_timeline_update_step(sc_timeline* t, int index, const char* step_json);
char*        sc_timeline_get_step(const sc_timeline* t, int index);
int          sc_timeline_set_enabled(sc_timeline* t, int index, int enabled);
int          sc_timeline_select(sc_timeline* t, int index, int selected);
int          sc_timeline_select_range(sc_timeline* t, int from, int to);
int          sc_timeline_remove_selected(sc_timeline* t);
int          sc_timeline_get_selected(const sc_timeline* t,
                                       int** indices_out, int* count_out);
int          sc_timeline_undo(sc_timeline* t);
int          sc_timeline_redo(sc_timeline* t);

// --- Coordinate mapping ---
typedef struct {
  int sim_width;       // logical pixels
  int sim_height;
  double scale_factor; // e.g. 2.0 for Retina, 3.0 for ProMotion
  int canvas_width;    // display pixels
  int canvas_height;
  int viewport_x;      // stream render offset within canvas (letterboxing)
  int viewport_y;
  int viewport_width;  // actual stream render area
  int viewport_height;
  int rotation;        // 0, 90, 180, 270 degrees clockwise
} sc_screen_geometry;

void sc_map_to_canvas(const sc_screen_geometry* g, double lx, double ly,
                      double* cx, double* cy);
void sc_map_to_logical(const sc_screen_geometry* g, double cx, double cy,
                       double* lx, double* ly);
void sc_map_viewport_to_logical(const sc_screen_geometry* g,
                                double vx, double vy,
                                double* lx, double* ly);

// --- Overlay geometry ---
typedef struct {
  int type;          // 0=circle, 1=line, 2=rect, 3=text, 4=spinner, 5=arrow
  double x, y;
  double x2, y2;    // for lines and arrows
  double radius;    // for circles and spinners
  double width, height; // for rects and text pills
  uint32_t color;   // RGBA
  double opacity;
  int duration_ms;
  int animation;    // 0=none, 1=expand, 2=trace, 3=fade, 4=pulse, 5=rotate
  const char* text; // for type=3 (text pill) — label content, NULL otherwise
  int font_size;    // for type=3 — logical px
  int dashed;       // for type=1 — 0=solid, 1=dashed
  double arrow_size; // for type=5 — arrow head size in px
} sc_shape;

int       sc_overlay_shapes(const sc_timeline* t, int step_index,
                            const sc_screen_geometry* g,
                            sc_shape** shapes_out, int* count_out);
void      sc_shapes_free(sc_shape* shapes, int count);

// --- Scheduler ---
typedef void (*sc_step_callback)(int step_index, const char* step_json,
                                  void* user_data);
typedef void (*sc_event_callback)(const char* event_json, void* user_data);

sc_scheduler* sc_scheduler_create(sc_timeline* t, double speed);
void          sc_scheduler_free(sc_scheduler* s);
int           sc_scheduler_start(sc_scheduler* s,
                                  sc_step_callback on_dispatch,
                                  sc_event_callback on_event,
                                  void* user_data);
int           sc_scheduler_pause(sc_scheduler* s);
int           sc_scheduler_resume(sc_scheduler* s);
int           sc_scheduler_abort(sc_scheduler* s);
int           sc_scheduler_step_forward(sc_scheduler* s);

// --- Memory management ---
void          sc_string_free(char* s);  // Free any char* returned by the API
void          sc_ints_free(int* arr);   // Free any int* returned by the API
```

**Note:** `script_differ` is an implementation detail of `sc_timeline`. Diffs
are computed internally to support undo/redo. The differ is not exposed via the
C API — consumers use `sc_timeline_undo` / `sc_timeline_redo` and do not need
to manipulate patches directly.

### Build integration

The C++ library uses CMake. Each platform consumer includes it as a dependency:

- **Browser**: `emcmake cmake .. && make` produces `libscriptcore.wasm` +
  `libscriptcore.js` glue. The web client loads it as an ES module.
- **Go agent**: `cgo` links the static library. The Go wrapper translates
  between Go types and the C API.
- **iOS/macOS**: Xcode project imports `ScriptCore.xcframework` (built by a
  CI script using `xcodebuild -create-xcframework`).
- **Android**: Gradle NDK plugin builds `libscriptcore.so` from the CMake
  project and bundles it in the AAR.

### Testing

Unit tests are written in C++ (Google Test). The test suite covers:
- JSON parse round-trip for all step types.
- Timeline insert/remove/move/undo/redo sequencing.
- Coordinate mapping with various scale factors and aspect ratios.
- Overlay geometry output for each step type.
- Scheduler state machine transitions (start, pause, resume, abort, step-through).

Platform integration tests verify the binding layer (cgo, WASM, JNI, Swift)
by round-tripping a sample script through parse → timeline → scheduler →
overlay geometry.

---

## Edge Cases and Constraints

**Text input capture:** the browser cannot intercept keystrokes typed into the
simulator itself (they go to the simulator via the existing input proxy). To
record text steps the user must type in a sidebar text field labelled "Type
here and it will be injected into the simulator". Keystrokes entered there are
captured as a TextStep and simultaneously injected live.

**Scroll detection:** iOS logical scroll (rubber-band) and Android fling
semantics differ. Emit ScrollStep with `delta_y` computed from the pointer
displacement. The executor translates this to the appropriate platform gesture.
Fine-grained velocity is not preserved — if exact velocity matters, the user
edits the step's `duration_ms`.

**idb unavailable (iOS read-only mode):** replay and Final Record require input
injection. If idb is absent or fails the probe tap, the Record and Preview/Final
Record buttons are disabled and a banner explains why:

```
┌────────────────────────────────────────────────────────┐
│  ⚠ Input injection unavailable. idb_companion is not  │
│  running or failed the probe check. Recording and      │
│  replay are disabled. See ios.md for setup.            │
└────────────────────────────────────────────────────────┘
```

**Long scripts:** the SSE `script.progress` stream keeps the connection alive.
If the connection drops mid-execution the server continues executing and buffers
all progress events for the active run in memory. On reconnect (using the same
`run_id`), the server replays all events from the beginning so the client can
reconstruct full step state. Event logs are discarded when the run completes
and the client has acknowledged receipt (or after 60 seconds post-completion).

**Simulator reboot mid-script:** if the simulator reboots between steps, the
executor catches the idb/adb error, emits `script.error` with the failing step
ID, and halts. The client highlights the failing step in the timeline with the
error state styling (red accent bar, red tint).

**Import dialog:** clicking [Import JSON] opens a modal dialog:

```
┌──────────────────────────────────────────────┐
│  Import Script                               │
│                                              │
│  [Choose file…]  or  [Paste JSON]            │
│                                              │
│  ○ Replace current timeline                  │
│  ○ Append to current timeline                │
│                                              │
│  [Cancel]                [Import]            │
└──────────────────────────────────────────────┘
```

Replace clears the undo stack. Append preserves it and pushes a single undo
entry for the appended steps. If the JSON is invalid, an inline error appears
below the file/paste area: "Invalid script: [reason]".

**Export:** downloads as `{script.name}.json` (pretty-printed, UTF-8) via
browser save-as dialog.

**Disconnection during preview/Final Record:** if the SSE connection drops, the
client shows a yellow banner pinned to the top of the Preview tab:

```
┌────────────────────────────────────────────────────────┐
│  Connection lost. Reconnecting…                 [×]   │
└────────────────────────────────────────────────────────┘
```

The progress bar freezes at the last known position. Step list shows the last
completed step. On reconnect, buffered events replay and the progress bar
catches up. If reconnection fails after 30 seconds, the banner changes to:

```
│  Connection lost. Server may still be recording.      │
│  [Retry connection]                                    │
```

For Final Record, the server always completes the script and saves the output
file regardless of client connection state. On reconnect, the `script.complete`
event delivers the output path.

**Scrolling behaviour for long timelines:**
- Timeline tab: the block list scrolls independently from the sidebar header.
  Scroll position is preserved when switching tabs and returning.
- During preview: the step list auto-scrolls to keep the currently executing
  step visible (centred vertically if possible). If the user manually scrolls
  during preview, auto-scroll pauses. A "Follow playback" toggle appears at
  the top of the list; clicking it re-enables auto-scroll.
- Lists with more than 100 steps use virtual scrolling (only DOM-render the
  visible blocks plus 10 above/below as a buffer).

**Manual step `recorded_at_ms` display:** manually inserted steps show "Manual"
instead of a timestamp in the collapsed block header.

**Final Record gating rules:** the [Final Record] button is enabled only when:
1. The script has at least one enabled step.
2. At least one preview has completed without any `script.error` events since
   the last edit to the timeline. Editing any step (including reorder, insert,
   delete, or property change) resets this flag and requires a new preview.

**Disabled steps:** steps with `enabled: false` are shown in the timeline with
50% opacity and a strikethrough on the label. They are skipped during replay.
Toggle enabled/disabled via right-click context menu or a checkbox in the
expanded block.

---

## Out of Scope for v1

- Branching / conditional steps (e.g. "tap X only if element Y is visible").
- Parameterised scripts (template variables).
- Multi-device synchronised playback.
- Assertion steps (screenshot comparison).
- Step groups / loops.
- Screenshot-on-step (capture frame after each step completes).

These can be added as step types in v2 without changing the execution model.
The C++ core library's step scheduler and timeline model are designed to accept
new step types via the JSON schema without recompilation — unknown step types
are passed through to the platform dispatch handler.
