-- static_binary_parser.lua
-- Reads sample from default path (no context file required):
--   examples/data/sample.exe
-- Produces one JSON string with:
--   metadata, import_table, import_diagnostics

local DEFAULT_SAMPLE_PATH = "examples/data/sample.exe"

local function trim(s)
    if s == nil then
        return ""
    end
    s = string.gsub(s, "\r", "")
    s = string.gsub(s, "\n", "")
    return s
end

local function json_escape(s)
    if s == nil then
        return ""
    end
    s = string.gsub(s, "\\", "\\\\")
    s = string.gsub(s, '"', '\\"')
    return s
end

local function jstr(s)
    return '"' .. json_escape(s or "") .. '"'
end

local function jbool(v)
    if v then
        return "true"
    end
    return "false"
end

local function hx(v, width)
    return string.format("0x%0" .. tostring(width) .. "X", v or 0)
end

local sample_path = DEFAULT_SAMPLE_PATH
local data, read_err = mutant.read_file(sample_path)
if not data then
    return '{"metadata":{"format":"unknown","magic_hex":"","byte_length":0,"pe_offset":0,"pe_signature":"","machine":"","sections":0,"timestamp":0,"characteristics":"","optional_magic":"","entry_rva":0,"section_table":[]},"import_table":[],"import_diagnostics":{"pe_ok":false,"pe_offset":0,"import_directory_rva":"0x00000000","import_directory_raw":"0x00000000","data_directory_base":"0x00000000","pointer_size":0,"descriptors_seen":0,"descriptors_with_name":0,"descriptors_with_thunks":0,"error":"sample_read_failed"}}'
end

local size = #data

local function u8(p)
    if p < 1 or p > size then
        return 0
    end
    return string.byte(data, p) or 0
end

local function u16(p)
    return u8(p) + (u8(p + 1) * 256)
end

local function u32(p)
    return u8(p) + (u8(p + 1) * 256) + (u8(p + 2) * 65536) + (u8(p + 3) * 16777216)
end

local function u64(p)
    local lo = u32(p)
    local hi = u32(p + 4)
    return lo + (hi * 4294967296)
end

local function cstr(p, maxn)
    local s = ""
    local lim = maxn or 256
    for i = 0, lim - 1 do
        local b = u8(p + i)
        if b == 0 then
            break
        end
        s = s .. string.char(b)
    end
    return s
end

local function sec_name(p)
    return cstr(p, 8)
end

local format = "unknown"
local b1, b2, b3, b4 = u8(1), u8(2), u8(3), u8(4)
if b1 == 77 and b2 == 90 then
    format = "pe_like"
end
if b1 == 127 and b2 == 69 and b3 == 76 and b4 == 70 then
    format = "elf_like"
end

local magic_hex = string.format("%02X%02X%02X%02X", b1, b2, b3, b4)

local pe_ok = false
local pe_offset = 0
local pe_signature = ""
local machine = ""
local sections = 0
local timestamp = 0
local characteristics = ""
local optional_magic = ""
local entry_rva = 0
local ptr_size = 0
local dd_base = 0
local import_rva = 0
local import_raw = 0

local section_table = {}
local import_table = {}

local descriptors_seen = 0
local descriptors_with_name = 0
local descriptors_with_thunks = 0

local max_sections = 0
local sec_base = 0

local function rva_to_raw_offset(rva)
    for i = 0, max_sections - 1 do
        local sp = sec_base + (i * 40)
        local vsize = u32(sp + 8)
        local vaddr = u32(sp + 12)
        local raw_size = u32(sp + 16)
        local raw_ptr = u32(sp + 20)

        local lim = vsize
        if raw_size > lim then
            lim = raw_size
        end

        if rva >= vaddr and rva < (vaddr + lim) then
            return raw_ptr + (rva - vaddr)
        end
    end
    return 0
end

local function rva_to_pos(rva)
    local raw = rva_to_raw_offset(rva)
    if raw == 0 then
        return 0
    end
    -- Lua strings are 1-based; PE RVAs/raw offsets are 0-based.
    return raw + 1
end

if format == "pe_like" and size >= 64 then
    pe_offset = u32(61)

    local sig1, sig2, sig3, sig4 = u8(pe_offset + 1), u8(pe_offset + 2), u8(pe_offset + 3), u8(pe_offset + 4)
    pe_signature = string.format("%02X%02X%02X%02X", sig1, sig2, sig3, sig4)

    if sig1 == 80 and sig2 == 69 then
        pe_ok = true

        local fh = pe_offset + 5
        sections = u16(fh + 2)
        if sections > 128 then
            sections = 128
        end

        machine = hx(u16(fh), 4)
        timestamp = u32(fh + 4)
        characteristics = hx(u16(fh + 18), 4)

        local size_opt = u16(fh + 16)
        local oh = fh + 20

        local oh_magic = u16(oh)
        optional_magic = hx(oh_magic, 4)
        entry_rva = u32(oh + 16)

        if oh_magic == 0x20B then
            ptr_size = 8
            dd_base = oh + 112
        else
            ptr_size = 4
            dd_base = oh + 96
        end

        sec_base = oh + size_opt
        max_sections = sections

        for i = 0, max_sections - 1 do
            local sp = sec_base + (i * 40)
            if sp + 39 <= size then
                local nm = sec_name(sp)
                local vsize = u32(sp + 8)
                local vaddr = u32(sp + 12)
                local raw_size = u32(sp + 16)
                local raw_ptr = u32(sp + 20)
                local sch = u32(sp + 36)

                table.insert(section_table, {
                    index = i,
                    name = nm,
                    virtual_size = vsize,
                    virtual_address = hx(vaddr, 8),
                    raw_size = raw_size,
                    raw_ptr = hx(raw_ptr, 8),
                    characteristics = hx(sch, 8),
                })
            end
        end

        import_rva = u32(dd_base + 8)
        import_raw = rva_to_raw_offset(import_rva)
        local import_pos = rva_to_pos(import_rva)

        if import_rva > 0 and import_pos > 0 then
            for di = 0, 512 do
            local d = import_pos + (di * 20)
                local oft = u32(d)
                local name_rva = u32(d + 12)
                local ft = u32(d + 16)

                if oft == 0 and name_rva == 0 and ft == 0 then
                    break
                end

                descriptors_seen = descriptors_seen + 1

                local dll = ""
                if name_rva > 0 then
                    dll = cstr(rva_to_pos(name_rva), 256)
                    if dll ~= "" then
                        descriptors_with_name = descriptors_with_name + 1
                    end
                end

                local thunk_rva = oft
                if thunk_rva == 0 then
                    thunk_rva = ft
                end

                local thunk_raw = rva_to_pos(thunk_rva)
                local fnc = 0
                local ordinal_count = 0
                local fn_names = {}
                local fn_details = {}

                if thunk_raw > 0 then
                    descriptors_with_thunks = descriptors_with_thunks + 1

                    for ti = 0, 8192 do
                        local slot = thunk_raw + (ti * ptr_size)
                        local thunk_entry_rva = thunk_rva + (ti * ptr_size)

                        if ptr_size == 8 then
                            local lo = u32(slot)
                            local hi = u32(slot + 4)

                            if lo == 0 and hi == 0 then
                                break
                            end

                            fnc = fnc + 1

                            if hi >= 0x80000000 then
                                local ord = lo % 65536
                                ordinal_count = ordinal_count + 1
                                table.insert(fn_details, {
                                    by_ordinal = true,
                                    ordinal = ord,
                                    hint = 0,
                                    name = "",
                                    thunk_rva = hx(thunk_entry_rva, 8),
                                })
                            else
                                local ibn_rva = lo
                                local ibn_pos = rva_to_pos(ibn_rva)
                                if ibn_pos > 0 then
                                    local hint = u16(ibn_pos)
                                    local fname = cstr(ibn_pos + 2, 256)
                                    if fname ~= "" then
                                        table.insert(fn_names, fname)
                                    end
                                    table.insert(fn_details, {
                                        by_ordinal = false,
                                        ordinal = 0,
                                        hint = hint,
                                        name = fname,
                                        thunk_rva = hx(thunk_entry_rva, 8),
                                    })
                                end
                            end
                        else
                            local value = u32(slot)

                            if value == 0 then
                                break
                            end

                            fnc = fnc + 1

                            if value >= 0x80000000 then
                                local ord = value % 65536
                                ordinal_count = ordinal_count + 1
                                table.insert(fn_details, {
                                    by_ordinal = true,
                                    ordinal = ord,
                                    hint = 0,
                                    name = "",
                                    thunk_rva = hx(thunk_entry_rva, 8),
                                })
                            else
                                local ibn_pos = rva_to_pos(value)
                                if ibn_pos > 0 then
                                    local hint = u16(ibn_pos)
                                    local fname = cstr(ibn_pos + 2, 256)
                                    if fname ~= "" then
                                        table.insert(fn_names, fname)
                                    end
                                    table.insert(fn_details, {
                                        by_ordinal = false,
                                        ordinal = 0,
                                        hint = hint,
                                        name = fname,
                                        thunk_rva = hx(thunk_entry_rva, 8),
                                    })
                                end
                            end
                        end
                    end
                end

                if dll ~= "" or fnc > 0 then
                    table.insert(import_table, {
                        dll = dll,
                        function_count = fnc,
                        ordinal_count = ordinal_count,
                        functions = fn_names,
                        function_details = fn_details,
                    })
                end
            end
        end
    end
end

local sec_parts = {}
for _, s in ipairs(section_table) do
    local one = "{"
        .. '"index":' .. tostring(s.index) .. ","
        .. '"name":' .. jstr(s.name) .. ","
        .. '"virtual_size":' .. tostring(s.virtual_size) .. ","
        .. '"virtual_address":' .. jstr(s.virtual_address) .. ","
        .. '"raw_size":' .. tostring(s.raw_size) .. ","
        .. '"raw_ptr":' .. jstr(s.raw_ptr) .. ","
        .. '"characteristics":' .. jstr(s.characteristics)
        .. "}"
    table.insert(sec_parts, one)
end

local import_parts = {}
for _, imp in ipairs(import_table) do
    local fn_parts = {}
    for _, fn_name in ipairs(imp.functions or {}) do
        table.insert(fn_parts, jstr(fn_name))
    end

    local detail_parts = {}
    for _, det in ipairs(imp.function_details or {}) do
        local item = "{"
            .. '"name":' .. jstr(det.name or "") .. ","
            .. '"by_ordinal":' .. jbool(det.by_ordinal) .. ","
            .. '"ordinal":' .. tostring(det.ordinal or 0) .. ","
            .. '"hint":' .. tostring(det.hint or 0) .. ","
            .. '"thunk_rva":' .. jstr(det.thunk_rva or "0x00000000")
            .. "}"
        table.insert(detail_parts, item)
    end

    local one = "{"
        .. '"dll":' .. jstr(imp.dll) .. ","
        .. '"function_count":' .. tostring(imp.function_count) .. ","
        .. '"ordinal_count":' .. tostring(imp.ordinal_count or 0) .. ","
        .. '"functions":[' .. table.concat(fn_parts, ",") .. "],"
        .. '"function_details":[' .. table.concat(detail_parts, ",") .. "]"
        .. "}"
    table.insert(import_parts, one)
end

local metadata_json = "{"
    .. '"format":' .. jstr(format) .. ","
    .. '"magic_hex":' .. jstr(magic_hex) .. ","
    .. '"byte_length":' .. tostring(size) .. ","
    .. '"pe_offset":' .. tostring(pe_offset) .. ","
    .. '"pe_signature":' .. jstr(pe_signature) .. ","
    .. '"machine":' .. jstr(machine) .. ","
    .. '"sections":' .. tostring(sections) .. ","
    .. '"timestamp":' .. tostring(timestamp) .. ","
    .. '"characteristics":' .. jstr(characteristics) .. ","
    .. '"optional_magic":' .. jstr(optional_magic) .. ","
    .. '"entry_rva":' .. tostring(entry_rva) .. ","
    .. '"section_table":[' .. table.concat(sec_parts, ",") .. "]"
    .. "}"

local diagnostics_json = "{"
    .. '"pe_ok":' .. jbool(pe_ok) .. ","
    .. '"pe_offset":' .. tostring(pe_offset) .. ","
    .. '"import_directory_rva":' .. jstr(hx(import_rva, 8)) .. ","
    .. '"import_directory_raw":' .. jstr(hx(import_raw, 8)) .. ","
    .. '"data_directory_base":' .. jstr(hx(dd_base, 8)) .. ","
    .. '"pointer_size":' .. tostring(ptr_size) .. ","
    .. '"descriptors_seen":' .. tostring(descriptors_seen) .. ","
    .. '"descriptors_with_name":' .. tostring(descriptors_with_name) .. ","
    .. '"descriptors_with_thunks":' .. tostring(descriptors_with_thunks)
    .. "}"

local out = "{"
    .. '"metadata":' .. metadata_json .. ","
    .. '"import_table":[' .. table.concat(import_parts, ",") .. "],"
    .. '"import_diagnostics":' .. diagnostics_json
    .. "}"

return out
