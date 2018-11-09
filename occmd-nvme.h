#undef CMD_INC_FILE
#define CMD_INC_FILE occmd-nvme

#if !defined(OCCMD_NVME) || defined(CMD_HEADER_MULTI_READ)
#define OCCMD_NVME

#include "cmd.h"

PLUGIN(NAME("occmd", "Open-channel device command through SPDK extensions"),
	COMMAND_LIST(
		ENTRY("geometry", "Print device geometry info", ocssd_geometry)
		ENTRY("chunkinfo", "Print specific chunk info", ocssd_chunkinfo)
		ENTRY("write_pm", "Write persistent memory", ocssd_write_pm)
		ENTRY("read_pm", "Read persistent memory", ocssd_read_pm)
		ENTRY("erase_chunk", "Erase specific chunk", ocssd_erase_chunk)
//		ENTRY("erase_super_chunk", "Erase specific super chunk", ocssd_erase_super_chunk)
		ENTRY("write_page", "Write one 4KB page", ocssd_write_page)
		ENTRY("read_page", "Read one 4KB page", ocssd_read_page)
		ENTRY("write_chunk", "Write one chunk", ocssd_write_chunk)
		ENTRY("read_chunk", "Read one chunk", ocssd_read_chunk)
		ENTRY("write_chunk_strip", "Write chunks across punits", ocssd_write_chunk_strip)
		ENTRY("read_chunk_strip", "Read  chunks across punits", ocssd_read_chunk_strip)
//		ENTRY("send_parity_init", "Print specific chunk info", ocssd_chunkinfo)
//		ENTRY("send_parity_out", "Print specific chunk info", ocssd_chunkinfo)
//		ENTRY("error_injection", "Print specific chunk info", ocssd_chunkinfo)
	)
);

#endif

#include "define_cmd.h"
