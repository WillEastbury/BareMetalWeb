# BareMetalWeb — iCE40 Minimum Engine

> Design exploration: the absolute minimum hardware implementation of the
> BareMetalWeb request pipeline on a Lattice iCE40UP5K FPGA.

---

## 1. Design Philosophy

BareMetalWeb's core pipeline is:

```
REQUEST ──► ROUTE ──► HANDLER ──► RENDER ──► RESPONSE
```

On the iCE40, this becomes a set of cooperating state machines in RTL — no
CPU, no OS, no software stack. Every stage is a hardware FSM operating on a
byte stream. The FPGA never touches TCP/IP (offloaded to the W5500) and
never does TLS (terminated externally or by the ATECC508A).

The design is streaming: bytes flow in from the network, get parsed, routed,
rendered against templates in flash, and flow back out — all without ever
buffering a full HTTP request or response in memory.

---

## 2. Bill of Materials

| Device | Part | Interface | Role |
|--------|------|-----------|------|
| **FPGA** | Lattice iCE40UP5K-SG48 | — | Core logic, bus arbitration |
| **TCP/IP offload** | WIZnet W5500 | SPI (mode 0, ≤33 MHz) | Hardware TCP/IP stack, 8 sockets, 16 KB TX+RX buffer |
| **Secure element** | Microchip ATECC508A | SPI (mode 0, ≤5 MHz) | Hardware key storage, ECDH, ECDSA, SHA-256, random |
| **Parallel SRAM** | Alliance AS6C6256 | 15-bit addr + 8-bit data | 32 KB working memory (sessions, route table, scratch) |
| **Storage** | QSPI Flash (e.g. W25Q128JV) | QSPI (mode 0, ≤80 MHz) | 16 MB — HTML templates, static assets, config, entity data |
| **Clock** | Onboard HFOSC | — | 48 MHz internal oscillator (iCE40UP5K built-in) |
| **Power** | 3.3 V LDO | — | Single rail for all devices |

---

## 3. iCE40UP5K Resource Budget

| Resource | Available | Notes |
|----------|-----------|-------|
| Logic cells (LUT4) | 5,280 | Main constraint |
| EBR (BRAM) | 120 Kbit (15 × 8 Kbit blocks) | Fast on-chip storage |
| SPRAM | 1 Mbit (4 × 256 Kbit blocks) | Single-port, high-density |
| PLL | 1 | Clock synthesis |
| SPI hard IP | 2 | SB_SPI — can service W5500 and ATECC508A |
| I2C hard IP | 2 | SB_I2C — available as fallback |
| IO pins (SG48) | 39 GPIO | Must fit all external buses |

---

## 4. Pin Budget (iCE40UP5K-SG48)

### 4.1 W5500 — SPI Bus

| Signal | FPGA Pin | Direction | Notes |
|--------|----------|-----------|-------|
| `W5500_SCK` | IOB_22a | Output | SPI clock (≤33 MHz) |
| `W5500_MOSI` | IOB_23b | Output | Master out |
| `W5500_MISO` | IOB_24a | Input | Master in |
| `W5500_CS_N` | IOB_25b | Output | Chip select (active low) |
| `W5500_INT_N` | IOB_29b | Input | Socket interrupt (active low) |
| `W5500_RST_N` | IOB_31b | Output | Hardware reset |

**Subtotal: 6 pins**

### 4.2 ATECC508A — SPI Bus

| Signal | FPGA Pin | Direction | Notes |
|--------|----------|-----------|-------|
| `ATECC_SCK` | IOB_32a | Output | SPI clock (≤5 MHz) |
| `ATECC_MOSI` | IOB_33b | Output | Master out |
| `ATECC_MISO` | IOB_34a | Input | Master in |
| `ATECC_CS_N` | IOB_35b | Output | Chip select (active low) |

**Subtotal: 4 pins**

### 4.3 AS6C6256 — Parallel SRAM (32 KB)

| Signal | FPGA Pin(s) | Direction | Notes |
|--------|-------------|-----------|-------|
| `SRAM_A[14:0]` | 15 pins | Output | 15-bit address (2^15 = 32 KB) |
| `SRAM_D[7:0]` | 8 pins | Bidir | 8-bit data bus |
| `SRAM_CE_N` | 1 pin | Output | Chip enable |
| `SRAM_OE_N` | 1 pin | Output | Output enable |
| `SRAM_WE_N` | 1 pin | Output | Write enable |

**Subtotal: 26 pins**

### 4.4 QSPI Flash

| Signal | FPGA Pin | Direction | Notes |
|--------|----------|-----------|-------|
| `FLASH_SCK` | IOT_46b | Output | QSPI clock |
| `FLASH_CS_N` | IOT_44b | Output | Chip select |
| `FLASH_IO[3:0]` | 4 pins | Bidir | Quad data lines |

**Subtotal: 6 pins**

### 4.5 Summary

| Bus | Pins |
|-----|------|
| W5500 SPI | 6 |
| ATECC508A SPI | 4 |
| AS6C6256 SRAM | 26 |
| QSPI Flash | 6 |
| **Total** | **42** |
| **Available (SG48)** | **39** |

> ⚠️ **Pin overrun: 42 needed vs 39 available.**
>
> Resolution options:
> 1. **Share SPI bus** — W5500 and ATECC508A on the same SPI bus with separate CS lines → saves 2 pins (SCK, MOSI shared) → **40 pins → still 1 over**.
> 2. **Additionally multiplex SRAM address** — use a 74HC573 latch to multiplex the upper address bits through the data bus → saves ~7 pins.
> 3. **Move to iCE40UP5K-B-EVN (BGA)** — 52 GPIO.
> 4. **Use the FPGA's SB_SPI hard IP** — frees the SPI pins from GPIO, they're dedicated pads.
>
> **Recommended: Option 1 + SB_SPI hard IP.** The two SB_SPI blocks are on dedicated pads outside the GPIO count, so W5500 and ATECC508A on the two hard SPI blocks uses 0 GPIO for SPI, leaving 39 GPIO for SRAM (26) + QSPI Flash (6) + extras (7 spare).

### 4.6 Revised Pin Budget (with SB_SPI hard IP)

| Bus | GPIO Pins | Dedicated Pads |
|-----|-----------|----------------|
| W5500 SPI (SB_SPI0) | 2 (INT_N, RST_N) | 4 (SCK, MOSI, MISO, CS) |
| ATECC508A SPI (SB_SPI1) | 0 | 4 (SCK, MOSI, MISO, CS) |
| AS6C6256 SRAM | 26 | 0 |
| QSPI Flash | 6 | 0 |
| **Total GPIO** | **34 of 39** | **8 dedicated** |
| **Spare GPIO** | **5** | — |

✅ Fits comfortably.

---

## 5. Module Hierarchy

```
bmw_top
├── clk_gen                          // PLL / HFOSC → system clock
│
├── spi_master_w5500                 // SB_SPI0 hard IP wrapper for W5500
│   ├── w5500_socket_ctrl            // Socket open/listen/accept/close FSM
│   └── w5500_rx_tx                  // Read RX buffer → byte stream, byte stream → TX buffer
│
├── spi_master_atecc                 // SB_SPI1 hard IP wrapper for ATECC508A
│   ├── atecc_wake_sleep             // Wake/sleep sequencing
│   ├── atecc_cmd                    // Command builder (Read, GenKey, ECDH, SHA, Random)
│   └── atecc_crc16                  // CRC-16 for command/response packets
│
├── qspi_flash_ctrl                  // QSPI flash read controller
│   └── flash_addr_map               // Address decoder: templates, static, config regions
│
├── sram_ctrl                        // AS6C6256 bus controller
│   ├── sram_arbiter                 // Round-robin access: route table, sessions, scratch
│   └── sram_addr_decode             // Region map within 32 KB
│
├── http_parser                      // HTTP/1.0 request parser FSM
│   ├── method_detect                // GET/POST/PUT/DELETE/PATCH → 3-bit method code
│   ├── path_extract                 // Extract URI path bytes → path buffer
│   ├── header_scan                  // Extract Content-Length, Cookie, Content-Type
│   └── body_pass                    // Stream POST body bytes (if any)
│
├── router                           // Route lookup engine
│   ├── path_hash                    // FNV-1a hash of path bytes
│   └── route_table                  // BRAM-backed hash → handler_id + flags
│
├── handler_dispatch                 // Handler state machine selector
│   ├── handler_static               // Serve static file from flash (stream-through)
│   ├── handler_template             // Template render with token substitution
│   ├── handler_api_read             // Read entity from SRAM → JSON-ish response
│   ├── handler_api_write            // Parse body → write entity to SRAM
│   └── handler_auth                 // Cookie validate via ATECC508A HMAC
│
├── template_engine                  // Streaming {{token}} replacer
│   ├── token_scanner                // Detect {{ and }} delimiters in byte stream
│   ├── token_lookup                 // Match token name → value source (SRAM addr or register)
│   └── token_emitter                // Splice replacement bytes into output stream
│
├── response_framer                  // HTTP response builder
│   ├── status_line                  // HTTP/1.0 200 OK\r\n (from status code register)
│   ├── header_emitter               // Content-Type, Content-Length, Set-Cookie headers
│   └── body_streamer                // Pipe rendered bytes to W5500 TX
│
├── session_mgr                      // Session state in SRAM
│   ├── session_lookup               // Cookie value → SRAM address
│   ├── session_validate             // Expiry check, HMAC verify via ATECC508A
│   └── session_create               // Allocate new session slot, get random from ATECC508A
│
└── led_status                       // Debug: blink pattern for state (boot/listen/active/error)
```

---

## 6. LUT Budget Estimates

Estimates based on comparable open-source iCE40 designs (picosoc, iCEBreaker
examples, and TinyFPGA projects).

| Module | Est. LUTs | Est. BRAM (Kbit) | Notes |
|--------|-----------|-------------------|-------|
| `clk_gen` | 10 | 0 | PLL config only |
| `spi_master_w5500` | 180 | 0 | SB_SPI + register FSM |
| `w5500_socket_ctrl` | 250 | 0 | Socket lifecycle FSM |
| `w5500_rx_tx` | 200 | 8 | 1 BRAM block for RX staging |
| `spi_master_atecc` | 150 | 0 | SB_SPI + command sequencer |
| `atecc_cmd` | 200 | 0 | Command packet builder + response parser |
| `atecc_crc16` | 40 | 0 | Combinational CRC |
| `qspi_flash_ctrl` | 200 | 0 | QSPI state machine |
| `flash_addr_map` | 30 | 0 | Address decode logic |
| `sram_ctrl` | 150 | 0 | Bus timing + tristate |
| `sram_arbiter` | 80 | 0 | Round-robin mux |
| `http_parser` | 350 | 8 | Path buffer in 1 BRAM block |
| `router` | 150 | 8 | Route table (16 entries × 64-bit) in 1 BRAM |
| `handler_dispatch` | 100 | 0 | Mux/select logic |
| `handler_static` | 120 | 0 | Flash read → TX pipe |
| `handler_template` | 180 | 0 | Token-aware stream splitter |
| `handler_api_read` | 200 | 0 | SRAM → ASCII hex/decimal emitter |
| `handler_api_write` | 250 | 0 | ASCII parser → SRAM writer |
| `handler_auth` | 100 | 0 | ATECC508A HMAC dispatch |
| `template_engine` | 300 | 8 | Token match buffer in 1 BRAM |
| `response_framer` | 200 | 0 | Header/status line emitter |
| `session_mgr` | 250 | 8 | Session slot index in BRAM |
| `led_status` | 20 | 0 | Blink FSM |
| **Total** | **~3,760** | **40 Kbit (5 blocks)** | |
| **Available** | **5,280** | **120 Kbit (15 blocks)** | |
| **Margin** | **~29%** | **~67%** | |

✅ Fits with comfortable margin for debug logic, additional handlers, or
a small soft-core co-processor if needed later.

---

## 7. Memory Map

### 7.1 AS6C6256 SRAM (32 KB)

| Region | Address Range | Size | Purpose |
|--------|--------------|------|---------|
| Route table | `0x0000–0x01FF` | 512 B | 16 routes × 32 bytes (hash, handler_id, flags, path prefix) |
| Session slots | `0x0200–0x11FF` | 4 KB | 64 sessions × 64 bytes (cookie hash, user_id, expiry, flags) |
| Entity store | `0x1200–0x71FF` | 24 KB | Key-value entity records (fixed 64-byte slots = 384 records) |
| Scratch / stack | `0x7200–0x7FFF` | 3.5 KB | Request parse buffer, template token scratch, temp values |

### 7.2 QSPI Flash (16 MB)

| Region | Address Range | Size | Purpose |
|--------|--------------|------|---------|
| Config | `0x000000–0x000FFF` | 4 KB | System config (routes, entity defs, boot flags) |
| Templates | `0x001000–0x0FFFFF` | ~1 MB | HTML template pages with `{{token}}` placeholders |
| Static assets | `0x100000–0x7FFFFF` | ~7 MB | CSS, JS, images, fonts |
| Entity schema | `0x800000–0x80FFFF` | 64 KB | Field definitions per entity type |
| Firmware bitstream | `0xF00000–0xFFFFFF` | 1 MB | iCE40 bitstream for self-reconfiguration |

---

## 8. Request Lifecycle (Hardware)

```
                    W5500                    FPGA                         External
                  ┌────────┐         ┌─────────────────┐
  TCP SYN ──────►│ Socket  │──INT──►│ w5500_socket_ctrl│
                 │ Accept  │        │  read RX buffer  │
                 └────────┘        └────────┬──────────┘
                                            │ raw HTTP bytes
                                            ▼
                                   ┌─────────────────┐
                                   │   http_parser    │
                                   │ method + path +  │
                                   │ headers → regs   │
                                   └────────┬──────────┘
                                            │ path bytes
                                            ▼
                                   ┌─────────────────┐
                                   │     router       │
                                   │ FNV-1a(path) →   │
                                   │ handler_id       │◄──── SRAM route table
                                   └────────┬──────────┘
                                            │ handler_id
                                            ▼
                                   ┌─────────────────┐
                                   │ handler_dispatch │
                                   │  select handler  │
                                   └───┬────┬────┬────┘
                                       │    │    │
                          ┌────────────┘    │    └────────────┐
                          ▼                 ▼                 ▼
                   ┌────────────┐  ┌──────────────┐  ┌──────────────┐
                   │  handler_  │  │  handler_    │  │  handler_    │
                   │  static    │  │  template    │  │  api_read    │
                   │  (flash→TX)│  │  (flash+SRAM)│  │  (SRAM→JSON) │
                   └─────┬──────┘  └──────┬───────┘  └──────┬───────┘
                         │                │                  │
                         ▼                ▼                  ▼
                   ┌──────────────────────────────────────────────┐
                   │             response_framer                  │
                   │  status line + headers + body bytes          │
                   └─────────────────────┬────────────────────────┘
                                         │ response bytes
                                         ▼
                                ┌─────────────────┐
                                │  w5500_rx_tx    │
                                │  write TX buffer│──────► W5500 ──► TCP client
                                └─────────────────┘
```

**Latency estimate:** At 48 MHz, a minimal GET returning a short template page:
- W5500 RX read: ~20 μs (SPI transfer)
- HTTP parse: ~2–5 μs (streaming FSM)
- Route lookup: 1 clock cycle (BRAM)
- Template stream from flash: ~50–100 μs (QSPI @ 80 MHz, 4 KB page)
- Response frame + W5500 TX: ~30 μs

**Total: ~100–160 μs per request** end-to-end (TCP read through TCP write).
The SPI I/O dominates — the FPGA's own processing (parse, route, token
replace) completes in ~2–10 μs at 48 MHz.

For comparison, BareMetalWeb's software stack takes ~0.5–2 ms for the full
request lifecycle (TCP stack + Kestrel + routing + render + response), with
worst-case spikes of 10–100+ ms during GC pauses or thread contention.
The FPGA is **~5–15× faster** end-to-end on average and **~100–1000×
faster** on worst-case latency (fully deterministic, zero jitter).

---

## 9. ATECC508A Integration

The ATECC508A provides hardware-backed security without consuming FPGA LUTs
for cryptographic operations:

| Operation | ATECC508A Command | Use Case |
|-----------|-------------------|----------|
| Session HMAC | `MAC` (slot key) | Cookie authentication — HMAC-SHA256 computed in hardware |
| Key derivation | `DeriveKey` | Per-session encryption keys derived from slot master |
| Random | `Random` | Session ID generation, nonces |
| ECDH | `ECDH` | Future: TLS key exchange if on-chip TLS is added |
| ECDSA Sign | `Sign` | Attestation — prove device identity to control plane |
| Slot Read | `Read` | Hardware-bound IKM for HKDF (matches existing BareMetalWeb pattern) |

The ATECC508A runs on SB_SPI1 at ≤5 MHz. Typical command round-trip is
5–50 ms depending on operation (crypto ops like ECDSA take longest).
Auth checks are done once per session creation, not per request.

---

## 10. Comparison: Hardware vs Software Engine

| Metric | BareMetalWeb (.NET) | iCE40 Engine |
|--------|---------------------|--------------|
| Processing latency (compute only) | 0.1–0.15 ms (render) | **0.002–0.01 ms (FSMs at 48 MHz)** |
| Full request-to-response | 0.5–2 ms (TCP + Kestrel + render) | **0.1–0.16 ms (SPI I/O dominated)** |
| Worst-case latency | 10–100+ ms (GC, thread contention) | **0.16 ms (deterministic, zero jitter)** |
| Concurrent connections | Thousands (Kestrel) | 8 (W5500 sockets) |
| Power | ~5 W (RPi) / ~15 W (x64) | **~50 mW** |
| Storage | Unlimited (filesystem) | 16 MB flash + 32 KB SRAM |
| Entity records | Millions | ~384 (SRAM) or thousands (flash-backed) |
| Template complexity | Full loop/conditional | `{{token}}` replacement only |
| TLS | Built-in (Kestrel) | External or ATECC508A-assisted |
| Auth | Full (session, MFA, API keys) | Session cookies (HMAC via ATECC508A) |
| Cost (BOM) | $35+ (RPi) | **~$8–12** (FPGA + peripherals) |
| Toolchain | .NET 10 SDK | yosys → nextpnr → icepack (fully open source) |

---

## 11. Limitations & Trade-offs

1. **No TLS termination on-chip.** Use a reverse proxy (nginx on a companion
   device) or rely on ATECC508A-assisted TLS in a future revision.

2. **HTTP/1.0 only.** No chunked transfer, no keep-alive, no HTTP/2.
   Each request opens and closes a W5500 socket.

3. **8 concurrent connections max** (W5500 hardware limit). Fine for
   embedded/IoT dashboards, not for public internet traffic.

4. **No dynamic template loops.** `{{Loop%%key}}` and `{{For%%i|...}}`
   would require a loop counter FSM and SRAM-backed iteration state — possible
   but expensive (~300–400 extra LUTs). First version does flat token
   replacement only.

5. **Entity storage is tiny.** 384 records in SRAM. For larger datasets,
   entities could be stored in flash (read-mostly) with SRAM as a write-back
   cache, but flash write endurance (~100K cycles) limits update frequency.

6. **No AI/intelligence engine.** The BitNet b1.58 inference engine requires
   compute far beyond iCE40 capacity.

---

## 12. Future Expansion Path

| Upgrade | Impact |
|---------|--------|
| **iCE40UP5K → ECP5** | 25K–85K LUTs. Room for a PicoRV32 soft core running C firmware alongside the hardware pipeline. |
| **Add SDRAM** | Replace AS6C6256 with 8 MB+ SDRAM for thousands of entity records and full session management. |
| **W5500 → LAN8720A + lwIP soft core** | Raw Ethernet PHY + software TCP stack on a soft core — more sockets, keep-alive, HTTP/1.1. |
| **On-chip TLS** | ATECC508A handles ECDH key exchange; symmetric AES-GCM in ~800 LUTs on the FPGA. |
| **Template loops** | Add `{{Loop}}` / `{{For}}` FSMs using SRAM-backed loop state — ~400 LUTs. |
| **Cluster mode** | Multiple iCE40 boards + control plane protocol over UART/SPI between nodes. |

---

## 13. Open Source Toolchain

The entire build flow uses the open-source iCE40 toolchain:

```bash
# Synthesise
yosys -p "synth_ice40 -top bmw_top -json bmw.json" src/*.v

# Place and route
nextpnr-ice40 --up5k --package sg48 --json bmw.json --pcf bmw.pcf --asc bmw.asc

# Pack bitstream
icepack bmw.asc bmw.bin

# Program
iceprog bmw.bin
```

No proprietary tools required.
