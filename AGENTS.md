# AGENTS.md

Notes for anyone, human or AI agent, changing this code. `README.md` covers what the program finds and does; this file
covers how the code is put together and the rules that keep it working.

## What this is

A desktop program (C#, .NET 10, Avalonia 11.3) that finds PHI and personal data in files (CSV, TSV, .xlsx, JSON, JSON
lines, text, folders of them) and databases (SQL Server, PostgreSQL, SQLite), reports where it is, and writes a
de-identified copy in which joins and totals still work. It has a command line (`--scan`, `--deidentify`, `--verify`),
an AI Chat (F12) and an MCP server (`--mcp`, `--mcp --attach`, `--mcp --http`, port 8775). It generalises X12
Explorer's X12-only de-identifier (`X12_820Explorer/src/X12Explorer.Core/Deidentifier.cs`) to ordinary data.

## Commands

```bash
dotnet build AVAPHIScanner.sln
dotnet test AVAPHIScanner.sln                    # everything; SQLite and files need no server
dotnet run --project AVAPHIScanner               # the window
dotnet run --project AVAPHIScanner -- --scan samples --report /tmp/r.html
dotnet run --project AVAPHIScanner -- --deidentify samples --key-file /tmp/k.key --out /tmp/copy
dotnet run --project AVAPHIScanner -- --mcp --root .      # the MCP server on stdio, no window (--attach: the open window)
APS_SHOTS=$PWD/Screenshots dotnet test --filter Screenshots                                   # the README's pictures
APS_LIVE_SERVER=http://localhost:11434 APS_LIVE_MODEL=qwen3:1.7b dotnet test --filter LiveModelTests   # a real model
cd samples && dotnet run make-samples.cs         # make the sample data again (fixed seed)
```

`dotnet test | head` stalls: write the output to a file and grep it.

## Layout

- `AVAPHIScanner/Core/`: everything that isn't the window or the agents, usable from the command line.
  - `Kinds.cs`: `PhiKind`, `ColumnAction`, `PolicyKind`, `DateMode`, and `Kinds.All`, which says each kind's label,
    Safe Harbor item, category (direct, quasi, provider, text) and what Safe Harbor and a limited data set do with it.
  - `Lists.cs` and `Resources/*.txt` (embedded): name lists, US cities, the 17 restricted three-digit ZIP areas, the
    ordinary words free text capitalises, and the made-up names pseudonyms come from.
  - `Detectors.cs`: `Detect.Value` (what one value looks like, with a strength), the check-digit rules (SSN, NPI, MBI,
    DEA, VIN, Luhn, cards), date parsing that keeps the format, and `HeaderHints`.
  - `TextScanner.cs`: `TextScan.Find`, identifiers inside free text, using `KnownValues` (names and IDs found in
    structured columns).
  - `Masking.cs`: `Mask`, the only way a value leaves for an agent, a picture or a report.
  - `Sources.cs`: `SourceSpec` (a project's source), `Sources.Expand` (its datasets: files, sheets, tables),
    `Sources.Read` (a sample for scanning), and the CSV, workbook and JSON helpers.
  - `Database.cs`, `Dialect.cs`: copied from AVA Query Builder (`Dialect` cut to what's needed); `DatabaseRead.cs`
    adds `DbRead.Stream`, reading a table row by row inside a rolled-back transaction.
  - `Scanner.cs`: `Classifier` (header + values → kind and confidence), `Scanner.Scan` (the inventory: structured
    columns first, then free text with the names and IDs found), `Inventory`, `ColumnReport`, and `SensitiveValues`
    (the raw values a scan saw, held in memory only, for guarding agents and verifying copies).
  - `Project.cs`: `Project` (the `.phiscan` JSON: sources, the person's decisions, the policy), `Policy`, and
    `ProjectHistory` (undo: a snapshot of the project per step). `ProjectFiles.cs`: saving with relative paths.
  - `Deidentifier.cs`: tokens, pseudonyms, date shifts, ZIP and age rules, `Apply` (one action on one value) and
    `Scrub` (free text). `DeidentifyRun.cs`: writing the copy in each format. `Verifier.cs`: checking a copy.
    `Report.cs`: `RiskSummary` and the .xlsx/.html reports. `CommandLine.cs`: the command line.
- `AVAPHIScanner/MainWindow.axaml(.cs)`: the window. Its controls change the project through `Change`/`Commit` (one
  undo step each) and redraw from the history (`ShowProject`). `MainWindow.Agents.cs`: the AI menu, the chat's place,
  Connect an Agent and Database Connections.
- `AVAPHIScanner/Agents/`: AI agents and the AI Chat, adapted from AVA Query Builder's.
  - `Mcp/ScanTools*.cs`: the tools, as `[McpServerTool]` methods. `ScanServer.cs`: the instructions every agent gets,
    the argument checks, the recording of changes, and the **guard** every answer passes. `Recipes.cs`: the recipes.
  - `Mcp/Hosting.cs`: handlers touch the project only through `IScanHost.RunAsync` and an `IScanSession`; `ScanHost`
    runs each call on the UI thread, waiting while a dialog is open; `HeadlessSession` is `--mcp`'s.
  - `Mcp/LiveListener`, `LiveBridge`, `NetworkListener`, `McpCommandLine`, `Workspace`, `ConnectionStore`, `Json`: the
    same files as AVA Query Builder's (and AVA Modeler's, AVASvgMaker's, AVAUIDesigner's), the names apart: fix together.
  - `Chat/`: the chat's conversation and clients, a copy of AVA Modeler's `AVAModeler.Chat` by way of AVA Query
    Builder; a fix there may be wanted here. `ChatPanel.cs`, `LiveAgents.cs` (`WindowSession`, the doors),
    `ScanLibrary.cs` (pictures of the inventory, in the window's hidden `AgentStage`), `AgentMain.cs` (`--mcp`),
    `AgentSettings.cs` (`agents.json` in the `AVAPHIScanner` settings folder).
- `samples/`: made-up data sharing member IDs across files, and `make-samples.cs`, which makes it.
- `tests/AVAPHIScanner.Tests/`: xUnit v3 with Avalonia.Headless, one app for the run.

## Rules that keep it working

- **Agents never see a raw value. No option turns that off.** Every value in a tool's answer is masked where it is
  made (`Mask.Value`, `Mask.Text`, `Mask.AfterText`, `Mask.Label` for names of files, tables and columns), and every
  answer then passes `ScanServer.Guard`, which masks the values scans have seen (`SensitiveValues`) and anything shaped
  like an SSN, email, phone number or full date. Errors go through `Scanner.Safe`. Don't add a tool that reads a file,
  returns rows, or echoes data; don't add a setting to see values; don't put a value in a status line an agent reads.
  A new tool must keep `No_tool_recipe_or_chat_ever_gives_an_agent_a_raw_value` passing: add a call to it there.
- **Sources are only read.** Databases through `DbRead.Stream` (read-only, rolled back); files are opened for reading.
  The copy goes into a folder that is not, and is not inside, a source folder (`DeidentifyRun.CheckOutput`), and never
  over a file unless asked. The key file never goes inside the output folder.
- **Every change to the project is one undo step.** The window uses `Change`/`Commit`; agents' calls go through
  `ScanTools.Edit` (a copy of the project, committed only if the call succeeds and changed something). A batch is
  several steps folded into one with `ProjectHistory.Squash`. Scan results, copies and checks aren't in the history.
- **Classification is header + values.** A new kind needs a `PhiKind`, a row in `Kinds.All` (with both policies'
  actions), a detector or header rule, a mask in `Mask.Value`, a marker or generalisation in `Deidentifier`, a verdict in
  `Verifier.Judge`, and tests with values it should and shouldn't take.
- **Tokens must match everywhere.** Every identifier kind hashes in one namespace ("id:" + `Tokens.Normalise`), so a
  member ID is the same token whichever column (or note) it is in. Date shifts are per person: the person key is the
  policy's `person_key`, else member ID, else MRN, else SSN (`DeidentifyRun.PersonColumn`, `Deidentifier.PersonOf`
  for text). Changing either breaks joins between copies made with the same key.
- **Amounts and clinical values are never changed.** Columns classified `None` are kept as they are; a header that
  names an amount, a code or a clinical value is `NotPhi` in `HeaderHints`.
- **Agent tools.** A new tool needs a `[Description]` on it and on every parameter (snake_case names), a place in
  `AgentTests.ToolNames` (and in `NotInBatch` if it opens, saves, scans, writes or looks), and a call in the no-leak
  test. Every recipe is run call by call by `AgentTests.Every_recipe_runs_call_by_call`. Paths stay inside the working
  folder (`Workspace`).
- **Names are this program's own.** `AVAPHISCANNER_MCP_TOKEN`, `AVAPHISCANNER_MCP_PIPE`, port 8775, settings folder
  `AVAPHIScanner`. After copying from a sibling app, grep for `AVAQUERYBUILDER`, `AVASVGMAKER`, `AVAUIDESIGNER` and
  their mixed-case names.
- **No real model, keys, server or user settings in tests.** `SettingsIsolation` points `AgentSettings.FolderOverride`
  at a temporary folder; chat tests answer from `FakeModelServer` and `FakeMessagesServer`; test windows get key stores
  and pipes of their own.
- **Don't name a Window method `Show()`**: it hides `Window.Show` and breaks the headless tests. Raise a new
  `KeyEventArgs` for each key press in a test (a handled one is skipped).
- **Made-up data only.** Samples come from `make-samples.cs`: fictional phone range, example.com, TEST-NET addresses,
  names that aren't on the pseudonym lists. Keep it that way.

## Making a change

- Run `dotnet test` (it takes seconds) and the screenshot test if the window changed; look at the pictures.
- Scan the samples, de-identify them, and open the copy: the joins, the totals and the notes.
- Update `README.md` (what it finds, the policies, the tools) to match.
