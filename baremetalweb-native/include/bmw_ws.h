#ifndef BMW_WS_H
#define BMW_WS_H

#include "bmw_module.h"
#include "bmw_event_loop.h"

/*
 * WebSocket Module - binary frame protocol for /bmw/ws
 *
 * Frame format (BareMetal.Communications compatible):
 *   [opcode<<2 : uint16 LE][entityId : uint32 LE]  = 6 bytes header
 *   Optional: [json_len : uint24 LE][json_payload...]
 *
 * Opcodes:
 *   0x01 = SCHEMA_REQUEST
 *   0x02 = SCHEMA_RESPONSE
 *   0x03 = LIST_REQUEST
 *   0x04 = LIST_RESPONSE
 *   0x05 = GET_REQUEST
 *   0x06 = GET_RESPONSE
 *   0x07 = CREATE_REQUEST
 *   0x08 = CREATE_RESPONSE
 *   0x09 = UPDATE_REQUEST
 *   0x0A = UPDATE_RESPONSE
 *   0x0B = DELETE_REQUEST
 *   0x0C = DELETE_RESPONSE
 *   0x0F = ERROR
 *
 * Also serves:
 *   /bmw/ws          - WebSocket upgrade
 *   /bmw/routes      - route table JSON
 *   /bmw/protocol    - protocol capabilities
 *   /bmw/wal/stream  - WAL change stream (SSE or WS)
 */

#define BMW_WS_MAX_CLIENTS    4
#define BMW_WS_BUF_SIZE       1024
#define BMW_WS_FRAME_HDR_SIZE 6

/* WebSocket opcodes (RFC 6455) */
#define WS_OP_CONTINUATION 0x00
#define WS_OP_TEXT         0x01
#define WS_OP_BINARY       0x02
#define WS_OP_CLOSE        0x08
#define WS_OP_PING         0x09
#define WS_OP_PONG         0x0A

/* BMW binary frame opcodes */
typedef enum {
    BMW_WS_OP_SCHEMA_REQ  = 0x01,
    BMW_WS_OP_SCHEMA_RESP = 0x02,
    BMW_WS_OP_LIST_REQ    = 0x03,
    BMW_WS_OP_LIST_RESP   = 0x04,
    BMW_WS_OP_GET_REQ     = 0x05,
    BMW_WS_OP_GET_RESP    = 0x06,
    BMW_WS_OP_CREATE_REQ  = 0x07,
    BMW_WS_OP_CREATE_RESP = 0x08,
    BMW_WS_OP_UPDATE_REQ  = 0x09,
    BMW_WS_OP_UPDATE_RESP = 0x0A,
    BMW_WS_OP_DELETE_REQ  = 0x0B,
    BMW_WS_OP_DELETE_RESP = 0x0C,
    BMW_WS_OP_ERROR       = 0x0F
} bmw_ws_opcode_t;

typedef struct {
    uint16_t opcode_shifted; /* opcode << 2 */
    uint32_t entity_id;
} bmw_ws_frame_hdr_t;

bmw_module_t *bmw_ws_module_create(void);

#endif /* BMW_WS_H */
