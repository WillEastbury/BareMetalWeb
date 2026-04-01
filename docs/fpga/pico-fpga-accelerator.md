# BareMetalWeb — Pico + iCE40 Accelerator Architecture

> Design exploration: Raspberry Pi Pico (W / 2W) as the main CPU running
> BareMetalWeb firmware, with a Lattice iCE40UP5K as a hardware rendering
> and indexing accelerator connected over a 16-bit PIO-driven parallel bus.

---

## 1. Architecture Overview

```
                         WiFi (UDP/IP)
                              │
                    ┌─────────┴──────────┐
                    │   Raspberry Pi      │
                    │   Pico W / 2W       │
                    │                     │
                    │  ┌───────────────┐  │
                    │  │ lwIP UDP/IP   │  │
                    │  │ HTTP engine   │  │
                    │  │ Router        │  │
                    │  │ Auth / CRUD   │  │
                    │  │ Session mgr   │  │
                    │  └───────┬───────┘  │
                    │          │          │
                    │    PIO state        │
                    │    machines         │
                    └──────────┬──────────┘
                               │
                    16-bit parallel bus
                    (PIO-driven, ~66 MHz)
                               │
                    ┌──────────┴──────────┐
                    │   Lattice iCE40     │
                    │   UP5K              │
                    │                     │
                    │  ┌───────────────┐  │
                    │  │ Template      │  │
                    │  │ render engine │  │
                    │  │               │  │
                    │  │ Search index  │  │
                    │  │ accelerator   │  │
                    │  │               │  │
                    │  │ ATECC508A SPI │  │
                    │  └───────┬───────┘  │
                    │          │          │
                    │   QSPI Flash       │
                    │   AS6C6256 SRAM    │
                    └─────────────────────┘
```

**Division of labour:**

| Concern | Pico (CPU) | iCE40 (Accelerator) |
|---------|------------|---------------------|
| Network | UDP/IP via WiFi (lwIP) | — |
| HTTP parse | ✅ C firmware | — |
| Routing | ✅ Hash table in SRAM | — |
| Auth / sessions | ✅ (delegates HMAC to FPGA→ATECC508A) | ATECC508A crypto ops |
| CRUD logic | ✅ Entity validation, transforms | — |
| Template render | Issues render command | ✅ Hardware streaming `{{token}}` replacement |
| Search / index | Issues query command | ✅ Hardware index traversal, returns match IDs |
| Storage | Commands via parallel bus | ✅ QSPI flash + SRAM controller |
| Binary serialize | ✅ (or delegates to FPGA) | Optional: hardware pack/unpack |

The Pico runs the intelligence — decisions, validation, business logic.
The FPGA runs the muscle — bulk data streaming, parallel index scans, crypto offload.

---

## 2. Bill of Materials

| Device | Part | Interface | Role |
|--------|------|-----------|------|
| **CPU** | RP2040 (Pico W) or RP2350 (Pico 2W) | — | Main processor, WiFi, HTTP, logic |
| **Accelerator** | Lattice iCE40UP5K-SG48 | 16-bit parallel (to Pico) | Render engine, index engine, bus master |
| **Secure element** | Microchip ATECC508A | SPI (to FPGA) | Hardware HMAC, ECDSA, key storage |
| **Parallel SRAM** | Alliance AS6C6256 | 15-bit addr + 8-bit data (to FPGA) | 32 KB — index structures, session cache |
| **Storage** | QSPI Flash (W25Q128JV) | QSPI (to FPGA) | 16 MB — templates, static assets, entity data |
| **Power** | 3.3 V from Pico VSYS | — | Single rail for FPGA + peripherals |

**Estimated BOM cost:** ~$12–18 (Pico W $6 + iCE40 $3–5 + ATECC $1 + SRAM $1 + Flash $2)

---

## 3. Parallel Bus Design

### 3.1 Physical Interface

The Pico's PIO state machines drive a 16-bit parallel bus to the iCE40.
This is a register-mapped command/data interface — the Pico writes commands
and token data, the FPGA streams results back.

| Signal | Width | Direction | Description |
|--------|-------|-----------|-------------|
| `DATA[15:0]` | 16 | Bidir | 16-bit data bus |
| `ADDR[2:0]` | 3 | Pico → FPGA | Register select (8 registers) |
| `WR_N` | 1 | Pico → FPGA | Write strobe (active low) |
| `RD_N` | 1 | Pico → FPGA | Read strobe (active low) |
| `RDY` | 1 | FPGA → Pico | Ready / data valid |
| `IRQ_N` | 1 | FPGA → Pico | Interrupt (render complete, query complete) |

**Total: 23 GPIO pins on Pico side, 23 pins on FPGA side.**

### 3.2 Pin Budget

**Pico W / Pico 2W:** 26 GPIO available.
- Parallel bus: 23 pins
- Spare: 3 pins (UART debug, LED, etc.)

**iCE40UP5K-SG48:** 39 GPIO available.
- Parallel bus: 23 pins
- AS6C6256 SRAM: see below (shared data bus optimisation)
- QSPI Flash: 6 pins
- ATECC508A: SB_SPI hard IP (dedicated pads)

> **SRAM data bus sharing:** The AS6C6256's 8-bit data bus can be shared
> with the lower 8 bits of the parallel bus when the FPGA multiplexes
> access (Pico bus idle during SRAM access and vice versa). This saves
> 8 FPGA pins.
>
> | Bus | FPGA GPIO | Dedicated |
> |-----|-----------|-----------|
> | Pico parallel | 23 | 0 |
> | SRAM (addr + control, data shared) | 18 (15 addr + 3 ctrl) | 0 |
> | QSPI Flash | 6 | 0 |
> | ATECC508A | 0 | 4 (SB_SPI) |
> | **Total** | **47** | **4** |
>
> ⚠️ **47 GPIO needed vs 39 available.** Overshoot by 8.
>
> **Resolution: SRAM address latch.** Use a 74HC573 to latch the upper
> address bits through the shared data bus. This reduces SRAM to 11 GPIO
> (8 shared data + 3 control) and brings the total to **40** — still 1 over.
>
> **Final fix: share ADDR[2:0] with SRAM upper address.** The 3 parallel
> bus address lines are only valid during Pico transactions, so they can
> double as SRAM address bits A[14:12] during FPGA-internal SRAM cycles.
>
> **Revised total: 37 GPIO.** ✅ Fits with 2 spare.

### 3.3 Register Map

The Pico sees the FPGA as 8 memory-mapped 16-bit registers:

| Addr | Register | R/W | Description |
|------|----------|-----|-------------|
| `0x0` | `CMD` | W | Command register — write triggers operation |
| `0x1` | `STATUS` | R | Status/flags: busy, error, render_done, query_done |
| `0x2` | `PARAM0` | R/W | Parameter 0 (e.g. flash address low word) |
| `0x3` | `PARAM1` | R/W | Parameter 1 (e.g. flash address high word, token count) |
| `0x4` | `DATA_W` | W | Bulk data write FIFO (token names, token values, query terms) |
| `0x5` | `DATA_R` | R | Bulk data read FIFO (rendered output, query results) |
| `0x6` | `FIFO_CNT` | R | Number of 16-bit words available in DATA_R FIFO |
| `0x7` | `VERSION` | R | Hardware version / magic number |

### 3.4 Command Set

| CMD value | Operation | Parameters | Result |
|-----------|-----------|------------|--------|
| `0x0001` | **RENDER** | PARAM0/1 = flash addr of template; token table pre-loaded via DATA_W | Rendered HTML bytes streamed to DATA_R |
| `0x0002` | **SEARCH** | Query term bytes written to DATA_W | Matching record IDs streamed to DATA_R |
| `0x0003` | **INDEX_BUILD** | Entity data written via DATA_W | Index structures built in SRAM |
| `0x0004` | **FLASH_READ** | PARAM0/1 = flash addr, PARAM1 high = length | Raw bytes to DATA_R |
| `0x0005` | **FLASH_WRITE** | PARAM0/1 = flash addr; data via DATA_W | Status in STATUS |
| `0x0006` | **HMAC** | Key slot in PARAM0; message via DATA_W | 32-byte HMAC in DATA_R (via ATECC508A) |
| `0x0007` | **RANDOM** | Count in PARAM0 | Random bytes in DATA_R (via ATECC508A) |
| `0x0008` | **SRAM_READ** | PARAM0 = SRAM addr, PARAM1 = length | Bytes to DATA_R |
| `0x0009` | **SRAM_WRITE** | PARAM0 = SRAM addr; data via DATA_W | Status |
| `0x000A` | **ECDSA_SIGN** | Message hash via DATA_W | 64-byte signature in DATA_R |
| `0x000B` | **PREFIX_SEARCH** | Prefix bytes via DATA_W | Matching keys in DATA_R (prefix tree walk) |

### 3.5 Timing

**Bus speed:** PIO at system clock / 2:
- RP2040: 133 MHz / 2 = 66.5 MHz → **133 MB/s** (16-bit × 66.5 MHz)
- RP2350: 150 MHz / 2 = 75 MHz → **150 MB/s**

This is absurdly fast for what we need. A 4 KB rendered page transfers in
~30 μs. The bus is never the bottleneck.

**PIO program (conceptual):**
```
; PIO write strobe — 16-bit parallel output
.program par16_write
    pull block          ; Get 16-bit word from TX FIFO
    out pins, 16        ; Drive DATA[15:0]
    set pins, 0 [1]     ; Assert WR_N low (2 cycles)
    set pins, 1         ; Deassert WR_N
```

```
; PIO read strobe — 16-bit parallel input
.program par16_read
    set pins, 0 [1]     ; Assert RD_N low (2 cycles)
    in pins, 16          ; Sample DATA[15:0]
    set pins, 1          ; Deassert RD_N
    push block           ; Push to RX FIFO
```

Both programs fit in a single PIO state machine (4 instructions each).

---

## 4. Render Accelerator

### 4.1 How It Works

The Pico delegates template rendering to the FPGA as a DMA-like operation:

```
Pico                              FPGA
  │                                 │
  │  1. Write token table           │
  │     via DATA_W:                 │
  │     [name_len][name][val_len]   │
  │     [value] × N tokens          │
  ├────────────────────────────────►│  → stored in SPRAM token table
  │                                 │
  │  2. Write PARAM0/1 =            │
  │     flash address of template   │
  ├────────────────────────────────►│
  │                                 │
  │  3. Write CMD = RENDER          │
  ├────────────────────────────────►│  → FPGA begins streaming
  │                                 │
  │         FPGA reads template     │
  │         from QSPI flash,       │
  │         scans for {{ }},        │
  │         replaces tokens,        │
  │         writes result to        │
  │         output FIFO             │
  │                                 │
  │  4. IRQ_N asserted              │
  │◄────────────────────────────────┤
  │                                 │
  │  5. Read FIFO_CNT, then         │
  │     bulk read DATA_R            │
  │◄───────────────────────────────►│  → rendered HTML bytes
  │                                 │
  │  6. Pico sends to WiFi          │
  │     via lwIP UDP/TCP            │
```

### 4.2 Token Table Format (in SPRAM)

```
Offset  Content
0x0000  [token_count : 16 bits]
0x0002  [token 0: name_len(8) | name(N) | val_len(16) | value(M)]
...     [token 1: ...]
...     [token N-1: ...]
```

The FPGA's token scanner compares incoming `{{...}}` names against this
table using a byte-by-byte match. With ≤32 tokens (typical page), the
linear scan completes in a few clock cycles per character — no hash needed.

### 4.3 Performance

| Step | Time | Notes |
|------|------|-------|
| Token table upload (32 tokens × 64 bytes avg) | ~15 μs | 2 KB @ 133 MB/s parallel bus |
| QSPI flash read (4 KB template) | ~13 μs | QSPI @ 80 MHz, quad mode |
| Token scan + replace (streaming) | ~1–3 μs | Pipelined with flash read |
| Result readback (4 KB rendered) | ~30 μs | Parallel bus |
| **Total render** | **~60 μs** | |

Compare to software-only on Pico (no FPGA):
- C firmware `PipeReader`-style scan: ~200–500 μs for 4 KB template
- With `memchr` + `memcpy`: ~150–300 μs

**FPGA render is ~3–8× faster** than optimised C on the Pico, but more
importantly it **frees the Pico's CPU** to handle the next request, run
auth checks, or process CRUD operations in parallel.

---

## 5. Index Accelerator

### 5.1 Design

The FPGA maintains search index structures in the AS6C6256 SRAM and
SPRAM. The Pico builds indexes by streaming entity data to the FPGA,
which constructs the index in hardware. Queries are offloaded similarly.

**Index types supported in hardware:**

| Index Type | Structure | SRAM/SPRAM Use | Operation |
|------------|-----------|----------------|-----------|
| **Prefix tree** | Compressed trie | SRAM (up to 32 KB) | Prefix search: walk trie nodes in hardware |
| **Inverted index** | Term → posting list | SPRAM (128 KB usable) | Full-text: hash term, scan posting list |
| **Hash index** | FNV-1a → slot | SRAM | Exact match: single hash + compare |

### 5.2 How Search Works

```
Pico                              FPGA
  │                                 │
  │  1. Write query term            │
  │     via DATA_W                  │
  ├────────────────────────────────►│
  │                                 │
  │  2. Write CMD = SEARCH          │
  ├────────────────────────────────►│  → FPGA hashes term,
  │                                 │    walks inverted index
  │                                 │    in SRAM, collects
  │                                 │    matching record IDs
  │                                 │
  │  3. IRQ_N asserted              │
  │◄────────────────────────────────┤
  │                                 │
  │  4. Read match count +          │
  │     record IDs from DATA_R      │
  │◄───────────────────────────────►│
  │                                 │
  │  5. Pico fetches full records   │
  │     from flash (via FLASH_READ) │
  │     or serves from own SRAM     │
```

### 5.3 Performance

| Operation | FPGA Hardware | Pico Software (C) |
|-----------|---------------|-------------------|
| Exact-match hash lookup | **~0.2 μs** (3–5 clocks: hash + SRAM read + compare) | ~5–10 μs |
| Prefix search (5-char prefix, ~1000 entries) | **~10–20 μs** (trie walk in SRAM) | ~50–200 μs |
| Inverted index term lookup (posting list ≤64) | **~5–15 μs** (hash + SRAM scan) | ~20–80 μs |

The FPGA's advantage is deterministic SRAM access at clock speed —
no cache misses, no branch mispredictions, no memory allocator overhead.

---

## 6. iCE40 Module Hierarchy (Accelerator Mode)

```
bmw_accel_top
├── clk_gen                          // PLL → system clock
│
├── par16_bus                        // 16-bit parallel bus interface to Pico
│   ├── cmd_decoder                  // CMD register → operation dispatch
│   ├── data_fifo_in                 // DATA_W write FIFO (SPRAM-backed)
│   ├── data_fifo_out               // DATA_R read FIFO (SPRAM-backed)
│   └── irq_ctrl                    // Interrupt generation to Pico
│
├── render_engine                    // Template rendering accelerator
│   ├── qspi_flash_reader           // Stream template bytes from flash
│   ├── token_scanner               // Detect {{ and }} delimiters
│   ├── token_table                  // SPRAM-backed token name/value store
│   ├── token_matcher               // Compare scanned name against table
│   └── output_mux                  // Splice: literal bytes or token value → FIFO out
│
├── index_engine                     // Search index accelerator
│   ├── hash_unit                   // FNV-1a hardware hash (streaming)
│   ├── trie_walker                  // Prefix tree traversal FSM (SRAM)
│   ├── posting_scanner             // Inverted index posting list scan (SPRAM)
│   └── result_collector            // Collect match IDs → FIFO out
│
├── index_builder                    // Build index from streamed entity data
│   ├── trie_insert                  // Insert key into prefix tree (SRAM)
│   └── posting_insert              // Append to posting list (SPRAM)
│
├── spi_atecc                        // SB_SPI hard IP → ATECC508A
│   ├── atecc_cmd                   // Command sequencer (HMAC, Random, Sign)
│   └── atecc_crc16                 // CRC-16 for packets
│
├── qspi_flash_ctrl                  // QSPI flash controller
│   └── flash_addr_map              // Region decode
│
├── sram_ctrl                        // AS6C6256 parallel SRAM controller
│   └── sram_arbiter                // Arbitrate: index engine vs render vs bus
│
└── led_status                       // Debug LEDs
```

### LUT Budget

| Module | Est. LUTs | Notes |
|--------|-----------|-------|
| `par16_bus` + FIFOs | 400 | Bus interface + SPRAM FIFOs |
| `render_engine` | 500 | Token scan/match/mux pipeline |
| `index_engine` | 600 | Hash + trie walker + posting scan |
| `index_builder` | 400 | Trie insert + posting append |
| `spi_atecc` | 250 | SB_SPI + command FSM |
| `qspi_flash_ctrl` | 200 | QSPI state machine |
| `sram_ctrl` + arbiter | 200 | Bus timing + arbitration |
| Misc (clk, LED, glue) | 50 | |
| **Total** | **~2,600** | |
| **Available** | **5,280** | |
| **Margin** | **~51%** | Room for loop support, more index types |

---

## 7. Pico Firmware Architecture

```c
// Main loop — both cores utilised

// Core 0: Network + HTTP + business logic
void core0_main(void) {
    lwip_init();
    wifi_connect();

    while (true) {
        // Poll lwIP
        cyw43_arch_poll();

        // Accept HTTP request (UDP or TCP)
        struct http_request req;
        if (http_recv(&req)) {
            // Route
            struct route *r = router_lookup(req.path);

            // Auth check
            if (r->requires_auth && !session_validate(&req))
                { http_send_401(&req); continue; }

            // Dispatch
            switch (r->handler_type) {
                case HANDLER_TEMPLATE:
                    // Offload to FPGA
                    fpga_load_tokens(&req, r);
                    fpga_cmd_render(r->template_flash_addr);
                    // Continue processing other requests while FPGA renders
                    break;
                case HANDLER_API_READ:
                    handle_api_read(&req, r);
                    break;
                case HANDLER_STATIC:
                    fpga_cmd_flash_read(r->asset_flash_addr, r->asset_len);
                    break;
            }
        }

        // Check FPGA completion
        if (fpga_irq_pending()) {
            uint16_t count = fpga_read_fifo_count();
            fpga_read_bulk(response_buf, count);
            http_send_response(current_req, response_buf, count);
        }
    }
}

// Core 1: FPGA DMA + background tasks
void core1_main(void) {
    while (true) {
        // Handle FPGA data transfers via PIO
        // Background index rebuilds
        // Session expiry sweeps
        // Telemetry / heartbeats to control plane
    }
}
```

### Dual-Core Split

| Core | Responsibility |
|------|---------------|
| **Core 0** | lwIP network polling, HTTP parse, routing, auth, CRUD logic |
| **Core 1** | PIO DMA to/from FPGA, background index builds, housekeeping |

This means the CPU never stalls waiting for the FPGA — Core 1 handles
all FPGA I/O asynchronously while Core 0 keeps serving requests.

---

## 8. End-to-End Request Latency

**Scenario:** HTTP GET for a template page with 12 tokens, 4 KB output.

| Step | Who | Time |
|------|-----|------|
| WiFi RX + lwIP UDP/TCP processing | Pico Core 0 | ~500 μs |
| HTTP parse + route lookup | Pico Core 0 | ~10–20 μs |
| Session/auth check | Pico Core 0 (+ FPGA HMAC if needed) | ~20 μs (cached) / ~5 ms (ATECC) |
| Token table upload to FPGA | Pico Core 1 (PIO) | ~15 μs |
| Render command + FPGA processing | iCE40 | ~15–20 μs |
| Result readback from FPGA | Pico Core 1 (PIO) | ~30 μs |
| HTTP response framing | Pico Core 0 | ~5 μs |
| WiFi TX + lwIP | Pico Core 0 | ~500 μs |
| **Total** | | **~1.1 ms** |

The WiFi stack dominates (~1 ms round-trip). The FPGA render is ~60 μs —
a rounding error in the total. But the critical win is:
- **Pico Core 0 is free** during the ~60 μs FPGA render — it can parse
  the next request, run auth, or do CRUD.
- **Deterministic render latency** — no variance from the rendering path.
- **Search queries return in microseconds** rather than hundreds of μs.

---

## 9. Comparison: Pico-only vs Pico + FPGA

| Metric | Pico-only (C firmware) | Pico + iCE40 Accelerator |
|--------|------------------------|--------------------------|
| Template render (4 KB) | 200–500 μs (CPU bound) | **~60 μs (FPGA, CPU free)** |
| Search (1000 records) | 50–200 μs | **~10–20 μs** |
| Concurrent render + search | ❌ (sequential on CPU) | **✅ (FPGA renders while CPU searches or vice versa)** |
| Max entity records | ~500 (264 KB SRAM limit) | **~4000+ (32 KB SRAM + 16 MB flash on FPGA)** |
| Crypto (HMAC-SHA256) | ~100 μs (software) | **Hardware via ATECC508A** |
| Power | ~150 mW (Pico W) | ~200 mW (Pico W + iCE40 + peripherals) |
| BOM cost | ~$6 | ~$12–18 |
| CPU utilisation under load | 80–100% (render bottleneck) | **~30–50% (FPGA offloads heavy work)** |

The FPGA doesn't make individual requests dramatically faster (WiFi
dominates), but it **doubles or triples throughput** by freeing the CPU.

---

## 10. Memory Architecture

### 10.1 Pico SRAM (264 KB RP2040 / 520 KB RP2350)

| Region | Size | Purpose |
|--------|------|---------|
| lwIP buffers | 32 KB | TCP/UDP packet buffers |
| HTTP parse buffer | 4 KB | Current request headers + body |
| Route table | 2 KB | 32 routes × 64 bytes |
| Session cache | 8 KB | 64 hot sessions (full store on FPGA SRAM) |
| Response buffer | 8 KB | Double-buffered output (ping-pong with FPGA) |
| Entity write cache | 16 KB | Staging area for CRUD writes before flash commit |
| Stack + heap | ~194 KB (RP2040) / ~450 KB (RP2350) | Firmware runtime |

### 10.2 iCE40 SPRAM (1 Mbit = 128 KB)

| Region | Size | Purpose |
|--------|------|---------|
| DATA_W input FIFO | 8 KB | Token data / query input staging |
| DATA_R output FIFO | 16 KB | Rendered output / query results |
| Token table | 8 KB | Current render's token name/value pairs |
| Inverted index postings | 64 KB | Term → record ID posting lists |
| Scratch | 32 KB | Temporary working space |

### 10.3 AS6C6256 SRAM (32 KB — on FPGA bus)

| Region | Size | Purpose |
|--------|------|---------|
| Prefix trie nodes | 16 KB | Compressed trie for prefix search |
| Hash index slots | 8 KB | FNV-1a exact-match hash table (256 slots × 32 bytes) |
| Session full store | 4 KB | 64 sessions × 64 bytes (auth state, expiry) |
| Entity ID index | 4 KB | Record ID → flash address mapping |

### 10.4 QSPI Flash (16 MB)

| Region | Address Range | Size | Purpose |
|--------|--------------|------|---------|
| Config | `0x000000–0x000FFF` | 4 KB | System config, route defs, entity metadata |
| Templates | `0x001000–0x0FFFFF` | ~1 MB | HTML template pages |
| Static assets | `0x100000–0x7FFFFF` | ~7 MB | CSS, JS, images, fonts |
| Entity data | `0x800000–0xEFFFFF` | ~7 MB | Entity records (binary packed) |
| FPGA bitstream | `0xF00000–0xFFFFFF` | 1 MB | iCE40 bitstream (cold boot or reconfigure) |

---

## 11. PIO Program Detail

Two PIO state machines on one PIO block handle the full parallel bus:

### SM0: Write (Pico → FPGA)

```
.program par16_write
.side_set 1                     ; WR_N on side-set pin
.wrap_target
    pull block          side 1  ; Wait for data, WR_N high
    out pins, 16        side 1  ; Drive DATA[15:0]
    nop                 side 0  ; Assert WR_N low (setup time)
    nop                 side 0  ; Hold WR_N low (>10 ns @ 48 MHz FPGA)
    nop                 side 1  ; Deassert WR_N (FPGA latches on rising edge)
.wrap
```

### SM1: Read (FPGA → Pico)

```
.program par16_read
.side_set 1                     ; RD_N on side-set pin
.wrap_target
    set pindirs, 0      side 1  ; Tristate DATA[15:0], RD_N high
    nop                  side 0  ; Assert RD_N low
    wait 1 pin RDY_PIN  side 0  ; Wait for FPGA RDY
    in pins, 16          side 0  ; Sample DATA[15:0]
    push block           side 1  ; Deassert RD_N, push to FIFO
.wrap
```

**Address lines** are set by the Pico's CPU (3 GPIO pins) before
triggering PIO transfers — the address changes infrequently compared
to data bursts.

---

## 12. Practical Considerations

### 12.1 WiFi is the Bottleneck

At ~1 ms per WiFi round-trip, the system can handle ~500–1000 requests/sec
regardless of FPGA speed. The FPGA's value is **CPU offload** (freeing the
Pico to handle more concurrent requests) not raw single-request latency.

### 12.2 Flash Write Endurance

QSPI flash has ~100K write cycles. For entity CRUD writes:
- Use SRAM as a write-back cache (absorb burst writes)
- Batch flash writes (write-ahead log pattern)
- Wear-level across the 7 MB entity region
- At 100 writes/day to a single sector: ~3 years endurance

### 12.3 Power Budget

| Component | Typical | Peak |
|-----------|---------|------|
| Pico W (WiFi active) | 100 mW | 300 mW |
| iCE40UP5K | 30 mW | 50 mW |
| AS6C6256 (active) | 15 mW | 25 mW |
| QSPI Flash (read) | 15 mW | 50 mW |
| ATECC508A (sleep/active) | 0.1 / 30 mW | 50 mW |
| **Total** | **~160 mW** | **~475 mW** |

Easily powered from USB (2.5 W budget) or a small LiPo battery.

### 12.4 Boot Sequence

```
1. Pico powers on → loads FPGA bitstream from QSPI flash (or FPGA cold-boots from its own flash)
2. Pico reads VERSION register to verify FPGA is alive
3. Pico reads config from flash (via FPGA FLASH_READ command)
4. Pico loads route table, entity metadata into its own SRAM
5. Pico commands FPGA to build search indexes (INDEX_BUILD with entity data from flash)
6. Pico connects to WiFi
7. System ready — accepting HTTP requests
```

Total boot time: ~2–3 seconds (dominated by WiFi association).
