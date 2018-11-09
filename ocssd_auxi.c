

#include "spdk/nvme_ocssd_spec.h"
#include "ocssd_auxi.h"

void
print_ocssd_geometry(struct spdk_ocssd_geometry_data *geometry_data)
{
	printf("Namespace OCSSD Geometry\n");
	printf("=======================\n");

	if (geometry_data->mjr < 2) {
		printf("Open-Channel Spec version is less than 2.0\n");
		printf("OC version:             maj:%d\n", geometry_data->mjr);
		return;
	}

	printf("OC version:                     maj:%d min:%d\n", geometry_data->mjr, geometry_data->mnr);
	printf("LBA format:\n");
	printf("  Group bits:                   %d\n", geometry_data->lbaf.grp_len);
	printf("  PU bits:                      %d\n", geometry_data->lbaf.pu_len);
	printf("  Chunk bits:                   %d\n", geometry_data->lbaf.chk_len);
	printf("  Logical block bits:           %d\n", geometry_data->lbaf.lbk_len);

	printf("Media and Controller Capabilities:\n");
	printf("  Namespace supports Vector Chunk Copy:                 %s\n",
	       geometry_data->mccap.vec_chk_cpy ? "Supported" : "Not Supported");
	printf("  Namespace supports multiple resets a free chunk:      %s\n",
	       geometry_data->mccap.multi_reset ? "Supported" : "Not Supported");

	printf("Wear-level Index Delta Threshold:                       %d\n", geometry_data->wit);
	printf("Groups (channels):              %d\n", geometry_data->num_grp);
	printf("PUs (LUNs) per group:           %d\n", geometry_data->num_pu);
	printf("Chunks per LUN:                 %d\n", geometry_data->num_chk);
	printf("Logical blks per chunk:         %d\n", geometry_data->clba);
	printf("MIN write size:                 %d\n", geometry_data->ws_min);
	printf("OPT write size:                 %d\n", geometry_data->ws_opt);
	printf("Cache min write size:           %d\n", geometry_data->mw_cunits);
	printf("Max open chunks:                %d\n", geometry_data->maxoc);
	printf("Max open chunks per PU:         %d\n", geometry_data->maxocpu);
	printf("\n");
}

void
print_ocssd_chunk_info(struct spdk_ocssd_chunk_information_entry *chk_info, int chk_num)
{
	int i;
	char *cs_str, *ct_str;

	printf("OCSSD Chunk Info Glance\n");
	printf("======================\n");

	for (i = 0; i < chk_num; i++) {
		cs_str = chk_info[i].cs.free ? "Free" :
				chk_info[i].cs.closed ? "Closed" :
				chk_info[i].cs.open ? "Open" :
				chk_info[i].cs.offline ? "Offline" :
				chk_info[i].cs.reserved & 0x1 ? "Vacant" : "Unknown";
		ct_str = chk_info[i].ct.seq_write ? "Sequential Write" :
			 chk_info[i].ct.rnd_write ? "Random Write" : "Unknown";

		printf("------------\n");
		printf("Chunk index:                    %d\n", i);
		printf("Chunk state:                    %s(0x%x)\n", cs_str, *(uint8_t *) & (chk_info[i].cs));
		printf("Chunk type (write mode):        %s\n", ct_str);
		printf("Chunk type (size_deviate):      %s\n", chk_info[i].ct.size_deviate ? "Yes" : "No");
		printf("Wear-level Index:               %d\n", chk_info[i].wli);
		printf("Starting LBA:                   0x%lx\n", chk_info[i].slba);
		printf("Number of blocks in chunk:      %ld\n", chk_info[i].cnlb);
		printf("Write Pointer:                  0x%lx\n", chk_info[i].wp);
	}
}

void
ocssd_dev_init(struct ocssd_dev *dev, int nsid,
		struct spdk_nvme_ns_data *ns_data,
		struct spdk_ocssd_geometry_data *geo_data)
{
	dev->nsid = nsid;

	dev->ns_data = *ns_data;
	dev->geo_data = *geo_data;

	dev->lba_num.grp = dev->geo_data.num_grp;
	dev->lba_num.pu = dev->geo_data.num_pu;
	dev->lba_num.chunk = dev->geo_data.num_chk;
	dev->lba_num.sector = dev->geo_data.clba;
	dev->lba_num.sbytes = 1 << dev->ns_data.lbaf[dev->ns_data.flbas.format & 0xf].lbads;
	dev->lba_num.sbytes_oob = dev->ns_data.lbaf[dev->ns_data.flbas.format & 0xf].ms;

	dev->lba_off.sector = 0;
	dev->lba_off.chunk = dev->geo_data.lbaf.lbk_len;
	dev->lba_off.pu = dev->lba_off.chunk + dev->geo_data.lbaf.chk_len;
	dev->lba_off.grp = dev->lba_off.pu + dev->geo_data.lbaf.pu_len;

	dev->lba_mask.sector = 0;
}

void
ocssd_sblk_construct(struct ocssd_dev *dev, struct ocssd_sblk *sblk,
		int lun_start, int lun_end, int chunk_idx,
		struct spdk_ocssd_chunk_information_entry *chks_info_array)
{
	int i;
	int lun_index;

	sblk->dev = dev;
	sblk->nblk = lun_end - lun_start + 1;

	for (lun_index = lun_start, i = 0; i < sblk->nblk; lun_index++, i++) {
		sblk->blks[i].grp = lun_index % dev->lba_num.grp;
		sblk->blks[i].pu = lun_index / dev->lba_num.grp;
		sblk->blks[i].chunk = chunk_idx;

		sblk->blks[i].ci = chks_info_array[i];
	}
}

