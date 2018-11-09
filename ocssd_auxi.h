
/** \file
 * OCSSD AUXI
 */

#ifndef OCSSD_AUXI_H
#define OCSSD_AUXI_H

#include "spdk/nvme_ocssd_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OCSSD_DEV_NAME_LEN 32
#define OCSSD_DEV_MAX_LUNS 128

struct ocssd_dev_lba_num {
	uint64_t grp;
	uint64_t pu;
	uint64_t chunk;
	uint64_t sector;

	uint64_t sbytes;	///< # Bytes per SECTOR
	uint64_t sbytes_oob;	///< # Bytes per SECTOR in OOB
};

struct ocssd_dev_lba_offset {
	uint64_t grp;
	uint64_t pu;
	uint64_t chunk;
	uint64_t sector;
};

struct ocssd_dev_lba_mask {
	uint64_t grp;
	uint64_t pu;
	uint64_t chunk;
	uint64_t sector;
};

struct ocssd_dev {
	char name[OCSSD_DEV_NAME_LEN];	///< Device name e.g. "nvme0n1"
	int nsid;			///< NVME namespace identifier
	struct spdk_ocssd_geometry_data geo_data;
	struct spdk_nvme_ns_data	ns_data;
	struct ocssd_dev_lba_offset lba_off;	///< Sector address format offset
	struct ocssd_dev_lba_mask lba_mask;	///< Sector address format mask
	struct ocssd_dev_lba_num lba_num;
};

struct ocssd_blk {
	int grp;
	int pu;
	int chunk;

	struct spdk_ocssd_chunk_information_entry ci;
};

struct ocssd_sblk {
	struct ocssd_dev *dev;
	int 	nblk;
	struct ocssd_blk blks[OCSSD_DEV_MAX_LUNS];

	bool checked;
	bool aligned;
	int sector_offset;

	uint32_t clba;
};

static inline uint64_t
_ocssd_dev_gen_chunk_info_idx(struct ocssd_dev_lba_num *lba_num,
		int grp, int pu, int chunk)
{
	uint64_t idx = 0;

	idx = grp * lba_num->pu * lba_num->chunk;
	idx += pu * lba_num->chunk;
	idx += chunk;

	return idx;
}

static inline uint64_t
ocssd_dev_gen_chunk_info_idx(struct ocssd_dev_lba_num *lba_num,
		int pu_idx, int chunk_idx)
{
	int grp = pu_idx % lba_num->pu;
	int pu = pu_idx / lba_num->pu;

	return _ocssd_dev_gen_chunk_info_idx(lba_num, grp, pu, chunk_idx);
}

static inline uint64_t
ocssd_dev_gen_chunk_info_offset(struct ocssd_dev_lba_num *lba_num,
		int grp, int pu, int chunk)
{

	return _ocssd_dev_gen_chunk_info_idx(lba_num, grp, pu, chunk)
			* sizeof(struct spdk_ocssd_chunk_information_entry);
}

void print_ocssd_geometry(struct spdk_ocssd_geometry_data *geometry_data);
void print_ocssd_chunk_info(struct spdk_ocssd_chunk_information_entry *chk_info, int chk_num);

void ocssd_dev_init(struct ocssd_dev *dev, int nsid,
		struct spdk_nvme_ns_data *ns_data,
		struct spdk_ocssd_geometry_data *geo_data);

void ocssd_sblk_construct(struct ocssd_dev *dev, struct ocssd_sblk *sblk,
		int lun_start, int lun_end, int chunk_idx,
		struct spdk_ocssd_chunk_information_entry *chks_info_array);

#ifdef __cplusplus
}
#endif

#endif // OCSSD_AUXI_H
