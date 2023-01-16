# Vector FDX Wireshark Dissector

## Motivation

## Getting started
To enable the FDX Protocol plugin, copy the fdx.lua file to the following path: C:\Users\your_name\AppData\Roaming\Wireshark\plugins.
This will allow you to access the FDX Protocol plugin and take advantage of its features.
## Description
This project aims to create a dissector for the FDX Protocol in Wireshark using the Lua programming language. The dissector function is not shown in this readme, but fdx.lua will be responsible for extracting the fields from the packet data and adding them to the packet dissection tree in Wireshark.

The first section of the code defines the fields that are used by the FDX Protocol. These fields include the FDX signature, version, number of commands, sequence number, protocol flags, and various fields related to the dynamic command payload. The fields are defined using the ProtoField object, which allows them to be added to the dissection tree and made searchable in the display filter.

The second section of the code defines several fields related to different types of the FDX commands, such as 4-byte, 6-byte, and 8-byte commands. These fields are used to extract specific pieces of information from the command payload, such as the command size, code, and group ID.

Additionally, the code defines a generated field called FDX Command, which is a string representation of the FDX command code. This field is not directly extracted from the packet data, but is instead derived from information found in the packet.

Finally, the code attaches or registers all of the defined fields to the FDX Protocol using the proto_fdx.fields table. This allows Wireshark to use the fields when dissecting FDX Protocol packets, making the process of packet analysis more efficient and accurate.

## Open points

### Not yet implemented: 
- Big-Indian Byte Order
- Commands
  - FreeRunningRequest:   16 bytes (0x0008)
  - Increment Time:       16 bytes (0x0011)
  - Function Call:        10 bytes plus data size (0x000C)
  - Function Call Error:  10 bytes (0x000D)