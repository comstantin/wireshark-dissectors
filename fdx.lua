local proto_fdx = Proto.new("fdx", "FDX Protocol")

--- --- Fields --- ---
-- These are the fields defined in fdx protocol
-- They will also be searchable in the display filter
-- FDX Datagram Header
--- fdxSignature
--- fdxMajorVersion
--- fdxMinorVersion
--- numberOfCommands
--- seqNrOrDgramLen
--- fdxProtocolFlags: Byte Order --> Little Endian = 0 or Big Endian = 1
--- reserved
-- FDX Datagram Payload is dynamic
--- next fields are dynamic and dependent on each particular packet

-- ##############################################
-- FDX Header
-- ##############################################
local field_fdxSignature =      ProtoField.uint64("fdx.Signature", "FDX Signature", base.HEX)
local field_fdxMajorVersion =   ProtoField.uint8("fdx.MajorVersion", "FDX Major Version", base.HEX)
local field_fdxMinorVersion =   ProtoField.uint8("fdx.MinorVersion", "FDX Minor Version", base.HEX)
local field_numberOfCommands =  ProtoField.uint16("fdx.numberOfCommands", "Number Of Commands", base.DEC)
local field_seqNrOrDgramLen =   ProtoField.uint16("fdx.seqNrOrDgramLen", "Datagram sequence number", base.DEC)
local field_fdxProtocolFlags =  ProtoField.uint8("fdx.ProtocolFlags", "Protocol Flags", base.HEX)
local field_reserved =          ProtoField.uint8("fdx.reserved", "Reserved", base.HEX)

-- ##############################################
-- Command 4 Bytes
-- ##############################################
local field_command4Bytes_commandSize = ProtoField.uint16("fdx.CommandFielCommandSize", "Command Size", base.HEX)
local field_command4Bytes_commandCode = ProtoField.uint16("fdx.CommandFielCommandCode", "Command Code", base.HEX)

-- ##############################################
-- Command 6 Bytes - 3 Fields
-- ##############################################
local field_command6Bytes_commandSize = ProtoField.uint16("fdx.CommandFielCommandSize", "Command Size", base.HEX)
local field_command6Bytes_commandCode = ProtoField.uint16("fdx.CommandFielCommandCode", "Command Code", base.HEX)
local field_command6Bytes_groupID =     ProtoField.uint16("fdx.CommandFieldGroupID", "Group ID", base.DEC)

-- ##############################################
-- Command 8 Bytes - 3 Fields
-- ##############################################
local field_command_8Bytes_3Fields_commandSize = ProtoField.uint16("fdx.CommandFielCommandSize", "Command Size", base.HEX)
local field_command_8Bytes_3Fields_commandCode = ProtoField.uint16("fdx.CommandFielCommandCode", "Command Code", base.HEX)
local field_command_8Bytes_3Fields_canoeKeyCode = ProtoField.uint32("fdx.CommandFielCanoeKeyCode", "Canoe Key Code", base.HEX)

-- ##############################################
-- Command 8 Bytes - 4 Fields
-- ##############################################
local field_command_8Bytes_4Fields_commandSize =    ProtoField.uint16("fdx.CommandFielCommandSize", "Command Size", base.HEX)
local field_command_8Bytes_4Fields_commandCode =    ProtoField.uint16("fdx.CommandFielCommandCode", "Command Code", base.HEX)
local field_command_8Bytes_4Fields_groupID =        ProtoField.uint16("fdx.CommandFieldGroupID", "Group ID", base.HEX)
local field_command_8Bytes_4Fields_dataErrorCode =  ProtoField.uint16("fdx.CommandFielDataErrorCode", "Data Error Code", base.HEX)
local field_command_8Bytes_4Fields_receivedSeqNr =  ProtoField.uint16("fdx.CommandFielReceivedSeqNr", "Received Sequence Number", base.HEX)
local field_command_8Bytes_4Fields_expectedSeqNr =  ProtoField.uint16("fdx.CommandFielExpectedSeqNr", "Expected Sequence Number", base.HEX)

-- ##############################################
-- Command 8 Bytes + DataSize - 5 Fields
-- ##############################################
local field_command_8Bytes_5Fields_commandSize = ProtoField.uint16("fdx.CommandFielCommandSize", "Command Size", base.HEX)
local field_command_8Bytes_5Fields_commandCode = ProtoField.uint16("fdx.CommandFielCommandCode", "Command Code", base.HEX)
local field_command_8Bytes_5Fields_groupID =     ProtoField.uint16("fdx.CommandFieldGroupID", "Group ID", base.HEX)
local field_command_8Bytes_5Fields_dataSize =    ProtoField.uint16("fdx.CommandFieldDataSize", "Data Size", base.HEX)
local field_command_8Bytes_5Fields_dataBytes =   ProtoField.uint8("fdx.CommandFielddDataBytes", "Data Bytes", base.HEX)

-- ##############################################
-- Command 16 Bytes - 5 Fields
-- ##############################################
local field_command_16Bytes_5Fields_commandSize =       ProtoField.uint16("fdx.CommandSize", "Command Size", base.HEX)
local field_command_16Bytes_5Fields_commandCode =       ProtoField.uint16("fdx.CommandCode", "Command Code", base.HEX)
local field_command_16Bytes_5Fields_measurementState =  ProtoField.uint8("fdx.CommandFieldMeasurementState", "Measurement State", base.HEX)
local field_command_16Bytes_5Fields_reserved_bytes =    ProtoField.uint24("fdx.CommandFieldReserved_bytes", "Reserved Bytes", base.HEX)
local field_command_16Bytes_5Fields_timestamps =        ProtoField.absolute_time("fdx.CommandFieldTimestamps", "Time Stamps", base.ABSOLUTE_TIME) -- hex does not work for INT

-- ##############################################
-- FDX Generated Fields
-- ##############################################
-- Generated fields are fields derived from information found in the packet
-- In this case, we want to display a string representation of the FDX command code
generated_fdx_command = ProtoField.string("fdx.Command", "FDX Command")

-- attach/register all fields (normal and generated) to fdx protocol
proto_fdx.fields = {
    field_fdxSignature,
    field_fdxMajorVersion,
    field_fdxMinorVersion,
    field_numberOfCommands,
    field_seqNrOrDgramLen,
    field_fdxProtocolFlags,
    field_reserved,
    field_command4Bytes_commandSize,
    field_command4Bytes_commandCode,
    field_command6Bytes_commandSize,
    field_command6Bytes_commandCode,
    field_command6Bytes_groupID,
    field_command_8Bytes_3Fields_commandSize,
    field_command_8Bytes_3Fields_commandCode,
    field_command_8Bytes_3Fields_canoeKeyCode,
    field_command_8Bytes_4Fields_commandSize,
    field_command_8Bytes_4Fields_commandCode,
    field_command_8Bytes_4Fields_groupID,
    field_command_8Bytes_4Fields_dataErrorCode,
    field_command_8Bytes_4Fields_receivedSeqNr,
    field_command_8Bytes_4Fields_expectedSeqNr,
    field_command_8Bytes_5Fields_commandSize,
    field_command_8Bytes_5Fields_commandCode,
    field_command_8Bytes_5Fields_groupID,
    field_command_8Bytes_5Fields_dataSize,
    field_command_8Bytes_5Fields_dataBytes,
    field_command_16Bytes_5Fields_commandSize,
    field_command_16Bytes_5Fields_commandCode,
    field_command_16Bytes_5Fields_measurementState,
    field_command_16Bytes_5Fields_reserved_bytes,
    field_command_16Bytes_5Fields_timestamps,
    generated_fdx_command
}

-- Build the FDX command code <-> FDX command table
local commands = {
    [0x0001] = "Start",
    [0x0002] = "Stop",
    [0x0003] = "Key Command",
    [0x0005] = "DataExchange",
    [0x0006] = "DataRequest",
    [0x0007] = "DataError",
    [0x0008] = "FreeRunningRequest",
    [0x0009] = "FreeRunningCancel",
    [0x0004] = "Status",
    [0x000A] = "Status Request",
    [0x000B] = "Sequence Number",
    [0x0011] = "Increment Time",
    [0x000C] = "Function Call",
    [0x000D] = "Function Call Error"
}

-- the `dissector()` method is called by Wireshark when parsing fdx packets
--- `buffer` holds the UDP payload, all the bytes from one fdx protocol packet
--- `tree` is the structure we see when inspecting/dissecting one particular packet
function proto_fdx.dissector(buffer, pinfo, tree)
    -- Changing the value in the protocol column (the Wireshark pane that displays 
    -- a list of packets) 
    pinfo.cols.protocol = "FDX"

    -- We label the entire UDP payload as being associated with our protocol
    local subtree = tree:add( proto_fdx, buffer(), " FDX Protocol" )
    local headerSubtree = subtree:add(proto_fdx, buffer(), "FDX Header")
    local payloadSubtree = subtree:add(proto_fdx, buffer(), "FDX Payload")
    -- local commandSubtree = subtree:add(payloadSubtree, buffer(), "FDX Command")

    -- ##############################################
    -- DATAGRAM HEADER
    -- ##############################################

    -- FDX Signature
    local fdxSignature_pos = 0
    local fdxSignature_len = 8
    -- `fdxSignature_buffer` holds the range of bytes
    local fdxSignature_buffer = buffer(fdxSignature_pos, fdxSignature_len)
    -- with `add()`, we're associating the range of bytes from `buffer` 
    -- with our field we declared earlier
    -- this means:
    -- (1) the values is now searchable in the display filter
    --    (e.g.we can filter a list of packets with fdx.Signature == "CANoeFDX")
    -- (2) Wireshark will create an entry in the packet inspection tree,
    --      highlight which part of the packet we're referencing 
    --      and show a label with our field name and value
    headerSubtree:add(field_fdxSignature, fdxSignature_buffer)

    -- FDX Major Version
    local fdxMajorVersion_pos = fdxSignature_pos + fdxSignature_len
    local fdxMajorVersion_len = 1
    local fdxMajorVersion_buffer = buffer(fdxMajorVersion_pos, fdxMajorVersion_len)
    headerSubtree:add(field_fdxMajorVersion, fdxMajorVersion_buffer)

    -- FDX Minor Version
    local fdxMinorVersion_pos = fdxMajorVersion_pos + fdxMajorVersion_len
    local fdxMinorVersion_len = 1
    local fdxMinorVersion_buffer = buffer(fdxMinorVersion_pos, fdxMinorVersion_len)
    headerSubtree:add(field_fdxMinorVersion, fdxMinorVersion_buffer)

    -- Number of Commands
    local numberOfCommands_pos = fdxMinorVersion_pos + fdxMinorVersion_len
    local numberOfCommands_len = 2
    local numberOfCommands_buffer = buffer(numberOfCommands_pos, numberOfCommands_len)
    headerSubtree:add(field_numberOfCommands, numberOfCommands_buffer, numberOfCommands_buffer:le_uint())

    -- Sequence Number
    local seqNrOrDgramLen_pos = numberOfCommands_pos + numberOfCommands_len
    local seqNrOrDgramLen_len = 2
    local seqNrOrDgramLen_buffer = buffer(seqNrOrDgramLen_pos, seqNrOrDgramLen_len)
    headerSubtree:add(field_seqNrOrDgramLen, seqNrOrDgramLen_buffer, seqNrOrDgramLen_buffer:le_uint())

    -- Protocol Flags
    local fdxProtocolFlags_pos = seqNrOrDgramLen_pos + seqNrOrDgramLen_len
    local fdxProtocolFlags_len = 1
    local fdxProtocolFlags_buffer = buffer(fdxProtocolFlags_pos, fdxProtocolFlags_len)
    headerSubtree:add(field_fdxProtocolFlags, fdxProtocolFlags_buffer)

    -- Reserved
    local reserved_pos = fdxProtocolFlags_pos + fdxProtocolFlags_len
    local reserved_len = 1
    local reserved_buffer = buffer(reserved_pos, reserved_len)
    headerSubtree:add(field_reserved, reserved_buffer)

    -- ##############################################
    -- State variables init
    -- ##############################################

    -- Start at the first byte after the fixed-size fields
    local command_offset = reserved_pos + reserved_len

    local number_of_commands
    local groupID
    local command_size 
    local command_code
    local command_name

    -- Keep track of the number of commands processed
    local command_counter = 0 
    
    -- Extract the number of commands from the dissection tree
    if numberOfCommands_buffer then
        number_of_commands = numberOfCommands_buffer:le_uint()
        pinfo.cols.info:append(", number_of_commands: "..tostring(number_of_commands))
    else
        number_of_commands = 0
    end

    -- ##############################################
    -- Process the commands in the payload
    -- ##############################################
    while command_counter < number_of_commands do
        -- Extract the command size and code
        command_size = buffer(command_offset, 2):le_uint()
        command_code = buffer(command_offset+2, 2):le_uint()
        command_name = "[" .. commands[command_code] .. "]"
        -- Process the remaining fields in the command based on the command code
        if command_code == 0x0001 or command_code == 0x0200 or command_code == 0x0A00 then 
            -- Command Size 4 Bytes (Start, Stop and Status Request)
            payloadSubtree:add(generated_fdx_command, command_name)
            payloadSubtree:add(field_command4Bytes_commandSize, command_size)
            payloadSubtree:add(field_command4Bytes_commandCode, command_code)
            command_offset = command_offset + 4 -- Increment the offset by 6 bytes
        elseif command_code == 0x0006 or command_code == 0x0900 then
            -- Command Size 6 Bytes (DataRequest)
            groupID = buffer(command_offset+4, 2):uint()
            payloadSubtree:add(generated_fdx_command, command_name)
            payloadSubtree:add(field_command6Bytes_commandSize, command_size)
            payloadSubtree:add(field_command6Bytes_commandCode, command_code)
            payloadSubtree:add(field_command6Bytes_groupID, groupID) 
            command_offset = command_offset + 6 -- Increment the offset by 6 bytes
        elseif command_code == 0x0003 then
            -- Command Size 8 Bytes - 3 Fields (Key)
            local canoeKeyCode = buffer(command_offset+4, 4):uint()
            payloadSubtree:add(generated_fdx_command, command_name)
            payloadSubtree:add(field_command_8Bytes_3Fields_commandSize, command_size)
            payloadSubtree:add(field_command_8Bytes_3Fields_commandCode, command_code)
            payloadSubtree:add(field_command_8Bytes_3Fields_canoeKeyCode, canoeKeyCode)
            command_offset = command_offset + 8 -- Increment the offset by 8 bytes
        elseif command_code == 0x0007 then
            -- Command Size 8 Bytes - 4 Fields (DataError)
            groupID = buffer(command_offset+4, 2):uint()
            local dataErrorCode = buffer(command_offset+6, 2):uint()
            payloadSubtree:add(generated_fdx_command, command_name)
            payloadSubtree:add(field_command_8Bytes_4Fields_commandSize, command_size)
            payloadSubtree:add(field_command_8Bytes_4Fields_commandCode, command_code)
            payloadSubtree:add(field_command_8Bytes_4Fields_groupID, groupID)
            payloadSubtree:add(field_command_8Bytes_4Fields_dataErrorCode, dataErrorCode)
            command_offset = command_offset + 8 -- Increment the offset by 8 bytes
        elseif command_code == 0x000B then
            -- Command Size 8 Bytes - 4 Fields (Sequence Number)
            local receivedSeqNr = buffer(command_offset+4, 2):uint()
            local expectedSeqNr = buffer(command_offset+6, 2):uint()
            payloadSubtree:add(generated_fdx_command, command_name)
            payloadSubtree:add(field_command_8Bytes_4Fields_commandSize, command_size)
            payloadSubtree:add(field_command_8Bytes_4Fields_commandCode, command_code)
            payloadSubtree:add(field_command_8Bytes_4Fields_receivedSeqNr, receivedSeqNr)
            payloadSubtree:add(field_command_8Bytes_4Fields_expectedSeqNr, expectedSeqNr)
            command_offset = command_offset + 8 -- Increment the offset by 8 bytes
        elseif command_code == 0x0005 then
            -- Command Size 8 Bytes + DataSize - 5 Fields (DataExchange)
            group_id = buffer(command_offset+4, 2):uint()
            local data_size = buffer(command_offset+6, 2):uint()
            payloadSubtree:add(generated_fdx_command, command_name)
            payloadSubtree:add(field_command_8Bytes_5Fields_commandSize, command_size)
            payloadSubtree:add(field_command_8Bytes_5Fields_commandCode, command_code)
            payloadSubtree:add(field_command_8Bytes_5Fields_groupID, group_id)
            payloadSubtree:add(field_command_8Bytes_5Fields_dataSize, data_size)
 
            -- Extract and add the data bytes to the dissection tree
            local data_size_for_calc = buffer(command_offset+6, 2):le_uint()
            for i=0,data_size_for_calc-1 do
                payloadSubtree:add(field_command_8Bytes_5Fields_dataBytes, buffer(command_offset+8+i, 1))
            end
    
            -- Increment the offset by 8 + data_size bytes
            command_offset = command_offset + 8 + data_size_for_calc
        
        elseif command_code == 0x0004 then
            -- Command Size 16 Bytes - 5 Fields (Status)
            local measurementState = buffer(command_offset+4, 1):uint()
            local reserved_bytes = buffer(command_offset+5, 3):uint()
            local timestamps = buffer(command_offset+8, 8)
            -- local nsecs = math.fmod(time, 1) * 1e9
            -- local nsecs = NSTime.new(secs, 0)
            payloadSubtree:add(generated_fdx_command, command_name)
            payloadSubtree:add(field_command_16Bytes_5Fields_commandSize, command_size)
            payloadSubtree:add(field_command_16Bytes_5Fields_commandCode, command_code) 
            payloadSubtree:add(field_command_16Bytes_5Fields_measurementState, measurementState)
            payloadSubtree:add(field_command_16Bytes_5Fields_reserved_bytes, reserved_bytes)
            payloadSubtree:add(field_command_16Bytes_5Fields_timestamps, timestamps)
            command_offset = command_offset + 16 -- Increment the offset by 16 bytes
      
        else
            -- Unknown command size and code
            -- Add a warning message to the dissection tree
            payloadSubtree:add_expert_info(PI_PROTOCOL, PI_WARN, "Unknown command size and code")
            -- Advance the offset by the command size
            command_offset = command_offset + command_size
        end

        -- NOT IMPLEMENTED YET
        --  "FreeRunningRequest"	16 Bytes	        0x0008
        --  "Increment Time"	    16 Bytes	        0x0011
        --  "Function Call"	        10 Bytes + dataSize	0x000C
        --  "Function Call Error"	10 Bytes	        0x000D
    
        -- Increment the command counter
        command_counter = command_counter + 1
    
        -- Check if there are more commands to process
        if command_counter < number_of_commands then
            -- There are more commands, so go back to the beginning of the loop
            goto process_commands
        else
            -- There are no more commands, so exit the loop
            break
        end
    
        -- Label for the beginning of the loop
        ::process_commands::
    end
end

--we register fdx protocol on UDP port 2810
udp_table = DissectorTable.get("udp.port"):add(2810, proto_fdx)