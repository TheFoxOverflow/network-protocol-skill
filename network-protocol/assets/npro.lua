-- npro.lua — a Wireshark/tshark dissector for the NPRO framed protocol implemented in
-- assets/framed_protocol.py.
--
-- Wire format (big-endian), 12-byte header then payload:
--   magic   4 bytes  "NPRO"
--   version 1 byte
--   type    1 byte   (1 HELLO, 2 HELLO_ACK, 3 DATA, 4 PING, 5 PONG, 6 BYE, 7 ERROR)
--   flags   2 bytes  (reserved, 0)
--   length  4 bytes  payload length, NOT including the header
--   payload length bytes
--
-- Install: copy to your Wireshark "Personal Lua Plugins" folder
--   (Help -> About Wireshark -> Folders), then Analyze -> Reload Lua Plugins.
-- Use: it binds to TCP port 9000 below; for any other port use Decode As -> NPRO,
--   or switch on the heuristic registration at the bottom.
--
-- The important lesson this dissector teaches: TCP is a byte stream, so one frame may
-- span several segments and several frames may share one segment (golden rule 1). A
-- correct dissector therefore asks Wireshark for more bytes via pinfo.desegment_* when a
-- frame is incomplete — the same "buffer until you have a whole message" discipline the
-- application parser must follow. A dissector that assumes one segment = one message has
-- exactly the bug references/pitfalls.md §1.1 describes.

local npro = Proto("npro", "NPRO framed protocol")

local MSG_TYPES = {
    [1] = "HELLO",
    [2] = "HELLO_ACK",
    [3] = "DATA",
    [4] = "PING",
    [5] = "PONG",
    [6] = "BYE",
    [7] = "ERROR",
}

local f_magic   = ProtoField.string("npro.magic",   "Magic")
local f_version = ProtoField.uint8 ("npro.version", "Version", base.DEC)
local f_type    = ProtoField.uint8 ("npro.type",    "Type",    base.DEC, MSG_TYPES)
local f_flags   = ProtoField.uint16("npro.flags",   "Flags",   base.HEX)
local f_length  = ProtoField.uint32("npro.length",  "Payload length", base.DEC)
local f_payload = ProtoField.bytes ("npro.payload", "Payload")

npro.fields = { f_magic, f_version, f_type, f_flags, f_length, f_payload }

local HEADER_LEN = 12
local MAGIC = "NPRO"

-- Dissect exactly one frame starting at `offset`. Returns the number of bytes consumed,
-- or 0 after requesting desegmentation (more bytes needed).
local function dissect_one(tvb, pinfo, tree, offset)
    local available = tvb:len() - offset

    -- Not even a full header yet: ask for at least one more segment.
    if available < HEADER_LEN then
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        pinfo.desegment_offset = offset
        return 0
    end

    local length = tvb(offset + 8, 4):uint()
    local total = HEADER_LEN + length

    -- Header present but body incomplete: ask for exactly the missing bytes.
    if available < total then
        pinfo.desegment_len = total - available
        pinfo.desegment_offset = offset
        return 0
    end

    local subtree = tree:add(npro, tvb(offset, total))
    subtree:add(f_magic,   tvb(offset,      4))
    subtree:add(f_version, tvb(offset + 4,  1))
    subtree:add(f_type,    tvb(offset + 5,  1))
    subtree:add(f_flags,   tvb(offset + 6,  2))
    subtree:add(f_length,  tvb(offset + 8,  4))
    if length > 0 then
        subtree:add(f_payload, tvb(offset + 12, length))
    end

    local tnum = tvb(offset + 5, 1):uint()
    local tname = MSG_TYPES[tnum] or string.format("0x%02x", tnum)
    subtree:append_text(string.format("  [%s, len=%d]", tname, length))
    return total, tname
end

function npro.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = npro.name
    local offset = 0
    local n = tvb:len()
    local summary = {}

    while offset < n do
        -- Guard against mis-dissecting non-NPRO bytes on a Decode-As'd port: if the magic
        -- doesn't match here, stop rather than emit garbage fields.
        if (tvb:len() - offset) >= 4 and tvb(offset, 4):string() ~= MAGIC then
            break
        end

        local consumed, tname = dissect_one(tvb, pinfo, tree, offset)
        if consumed == 0 then
            return        -- desegmentation requested; Wireshark will call us again
        end
        summary[#summary + 1] = tname
        offset = offset + consumed
    end

    if #summary > 0 then
        pinfo.cols.info = "NPRO: " .. table.concat(summary, ", ")
    end
    return offset
end

-- Port-based binding. Change 9000 to your port, or use Decode As -> NPRO at runtime.
DissectorTable.get("tcp.port"):add(9000, npro)

-- Heuristic alternative (more robust than a fixed port): recognize the magic on any TCP
-- stream. Uncomment to enable.
--
-- local function npro_heuristic(tvb, pinfo, tree)
--     if tvb:len() < HEADER_LEN then return false end
--     if tvb(0, 4):string() ~= MAGIC then return false end
--     npro.dissector(tvb, pinfo, tree)
--     return true
-- end
-- npro:register_heuristic("tcp", npro_heuristic)
