#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/fs.h>
#include <inttypes.h>
#include <asm/byteorder.h>

#include "linux/nvme_ioctl.h"

#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "json.h"
#include "plugin.h"

#include "argconfig.h"
#include "suffix.h"

#define CREATE_CMD
#include "occmd-nvme.h"

#include "spdk/ocssd_cmd.h"
#include "ocssd_auxi.h"


#ifndef PAGESIZE
#define PAGESIZE 0x1000
#endif
#define MAX_REQ_NUM 256
#define MAX_SBLK_NUM 256

struct spdk_bdev_target *bt = NULL;
struct spdk_bdev_aio_ctx ctx[1];
struct spdk_bdev_aio_req reqs[MAX_REQ_NUM];
struct spdk_bdev_aio_req *reqs_submit[MAX_REQ_NUM];
struct spdk_bdev_aio_req *reqs_gotten[MAX_REQ_NUM];

struct ocssd_dev dev[1];
struct ocssd_sblk sblk[MAX_SBLK_NUM];

char *dev_name;
int nsid = 1;

static int ocssd_aio_env_prepare(char *conffile, char *dev_name)
{
	int rc;

	rc = spdk_env_setup(conffile);
	if (rc) {
		fprintf(stderr, "failed to setup SPDK env\n");
		return rc;
	}

	rc = spdk_bt_open(dev_name, &bt);
	if (rc) {
		fprintf(stderr, "Failed to open bt (%s)\n", dev_name);
		spdk_env_unset();
		return rc;
	}

	rc = spdk_bdev_aio_ctx_setup(ctx, bt);
	if (rc) {
		fprintf(stderr, "failed to setup SPDK ctx\n");
		spdk_bt_close(bt);
		spdk_env_unset();
	}

	return rc;
}

static void ocssd_aio_env_release(void)
{
	spdk_bdev_aio_ctx_destroy(ctx);
	spdk_bt_close(bt);
	spdk_env_unset();
}

static int ocssd_aio_req_batch_sync(struct spdk_bdev_aio_req *req[], int nr)
{
	int rc;

	rc = spdk_bdev_aio_ctx_submit(ctx, nr, req);
	if (rc < 0) {
		fprintf(stderr, "Failed to submit req to SPDK\n");
		rc = -EIO;
		return rc;
	}

	rc = spdk_bdev_aio_ctx_get_reqs(ctx, nr, nr, reqs_gotten, NULL);
	if (rc != nr) {
		fprintf(stderr, "Failed to get req from SPDK (rc is %d)\n", rc);
		rc = -EIO;
	}

	return rc;
}

static int ocssd_dev_prepare(struct ocssd_dev *dev)
{
	struct spdk_ocssd_geometry_data *geo_data = NULL;
	struct spdk_nvme_ns_data *ns_data = NULL;
	struct spdk_bdev_aio_req *reqs_submit[2];
	int rc;

	/* Prepare to constrct basic info for OCSSD dev */
	geo_data = spdk_dma_malloc(sizeof(*geo_data), 0x1000, NULL);
	if (geo_data == NULL) {
		return -ENOMEM;
	}

	ns_data = spdk_dma_malloc(sizeof(*ns_data), 0x1000, NULL);
	if (ns_data == NULL) {
		spdk_dma_free(ns_data);
		return -ENOMEM;
	}

	reqs_submit[0] = &reqs[0];
	spdk_ocssd_req_prep_geometry(reqs_submit[0], geo_data, nsid);
	reqs_submit[1] = &reqs[1];
	spdk_ocssd_req_prep_nsdata(reqs_submit[1], ns_data, nsid);

	rc = ocssd_aio_req_batch_sync(reqs_submit, 2);
	if (rc != 2) {
        fprintf(stderr, "Failed to get req (rc = %d)\n", rc);
		goto err;
	}

	rc = spdk_bdev_aio_ret_check(&reqs_gotten[0]->ret) != 0
			|| spdk_bdev_aio_ret_check(&reqs_gotten[1]->ret) != 0;
	if (rc) {
        fprintf(stderr, "Error result in reqs\n");
        goto err;
    }

	ocssd_dev_init(dev, nsid, ns_data, geo_data);

err:
	spdk_dma_free(ns_data);
	spdk_dma_free(geo_data);
	return rc;
}

static int check_arg_dev(int argc, char **argv)
{
	if (optind >= argc) {
		errno = EINVAL;
		perror(argv[0]);
		return -EINVAL;
	}
	return 0;
}

static int get_dev_name(int argc, char **argv)
{
	int ret;

	ret = check_arg_dev(argc, argv);
	if (ret)
		return ret;

	dev_name = (char *)argv[optind];
	return 0;
}

static int ocssd_geometry(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Print device geometry info";
	char *conffile = "SPDK configure file path";
	int rc;
	struct spdk_ocssd_geometry_data *geo_data = NULL;

	struct config {
		char *conffile;
	};
	struct config cfg = {
		.conffile = "",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"conffile",  'c', "FILE", CFG_STRING,   &cfg.conffile,         required_argument, conffile},
		{NULL}
	};

	rc = argconfig_parse(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (!rc) {
		rc = get_dev_name(argc, argv);
	}
	if (rc) {
		argconfig_print_help(desc, command_line_options);
		exit(rc);
	}

	rc = ocssd_aio_env_prepare(cfg.conffile, dev_name);
	if (rc) {
		fprintf(stderr, "failed to setup SPDK env\n");
		return rc;
	}

	geo_data = spdk_dma_malloc(sizeof(*geo_data), 0x1000, NULL);
	if (geo_data == NULL) {
		return -ENOMEM;
	}

	reqs_submit[0] = &reqs[0];
	spdk_ocssd_req_prep_geometry(reqs_submit[0], geo_data, nsid);

	rc = ocssd_aio_req_batch_sync(reqs_submit, 1);
	if (rc != 1) {
        fprintf(stderr, "Failed to get req (rc = %d)\n", rc);
		goto out;
	}
	rc = spdk_bdev_aio_ret_check(&reqs_gotten[0]->ret) != 0;
	if (rc) {
        fprintf(stderr, "Error result in reqs\n");
        rc = -EIO;
        goto out;
    }

	print_ocssd_geometry(geo_data);

out:
	spdk_dma_free(geo_data);
	ocssd_aio_env_release();
	return rc;
}

/* Calculate chunk offset */
static int ocssd_dev_chunkinfo_get(int punit_idx, int chunk_idx, int chunk_num,
		struct spdk_ocssd_chunk_information_entry **_chunkinfos)
{
	int rc;
	uint64_t chunk_info_offset;
	struct spdk_ocssd_chunk_information_entry *chunkinfos = NULL;
	int grp = punit_idx % dev->lba_num.grp;
	int pu = punit_idx / dev->lba_num.grp;

	chunk_info_offset = ocssd_dev_gen_chunk_info_offset(&dev->lba_num,
			grp, pu, chunk_idx);

	printf("Punit, Chunk, Chunk_num are %d %d %d\n", punit_idx, chunk_idx, chunk_num);
	chunkinfos = spdk_dma_malloc(sizeof(*chunkinfos) * chunk_num, 0x1000, NULL);
	if (chunkinfos == NULL) {
		rc = -ENOMEM;
		return rc;
	}

	reqs_submit[0] = &reqs[0];
	spdk_ocssd_req_prep_chunkinfo(reqs_submit[0], chunk_info_offset, chunk_num, chunkinfos, dev->nsid);

	rc = ocssd_aio_req_batch_sync(reqs_submit, 1);
	if (rc != 1) {
        fprintf(stderr, "Failed to get req (rc = %d)\n", rc);
		spdk_dma_free(chunkinfos);
		return -EIO;
	}

	rc = spdk_bdev_aio_ret_check(&reqs_gotten[0]->ret) != 0;
	if (rc) {
		spdk_dma_free(chunkinfos);
        return -EIO;
    }

	*_chunkinfos = chunkinfos;
	return 0;
}

static int ocssd_chunkinfo(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Print device chunk info";
	char *conffile = "SPDK configure file path";
	char *punit_idx = "Index of PUnit";
	char *chunk_idx = "Start index of chunk";
	char *chunk_num = "Number of chunks";
	int rc;
	struct spdk_ocssd_chunk_information_entry *chunkinfos = NULL;

	struct config {
		char *conffile;
		int punit_idx;
		int chunk_idx;
		int chunk_num;
	};
	struct config cfg = {
		.conffile = "",
		.punit_idx = 0,
		.chunk_idx = 0,
		.chunk_num = 1,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"conffile",  'c', "FILE", CFG_STRING,   &cfg.conffile,         required_argument, conffile},
		{"punit_idx",  'p', "NUM", CFG_POSITIVE,   &cfg.punit_idx,         required_argument, punit_idx},
		{"chunk_idx",  'k', "NUM", CFG_POSITIVE,   &cfg.chunk_idx,         required_argument, chunk_idx},
		{"chunk_num",  'n', "NUM", CFG_POSITIVE,   &cfg.chunk_num,         required_argument, chunk_num},
		{NULL}
	};

	rc = argconfig_parse(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (!rc) {
		rc = get_dev_name(argc, argv);
	}
	if (rc) {
		argconfig_print_help(desc, command_line_options);
		exit(rc);
	}

	rc = ocssd_aio_env_prepare(cfg.conffile, dev_name);
	if (rc) {
		fprintf(stderr, "failed to setup SPDK env\n");
		return rc;
	}

	rc = ocssd_dev_prepare(dev);
	if(rc) {
		return rc;
	}

	/* Calculate chunk offset */
	rc = ocssd_dev_chunkinfo_get(cfg.punit_idx, cfg.chunk_idx, cfg.chunk_num, &chunkinfos);
	if (rc == 0) {
		print_ocssd_chunk_info(chunkinfos, cfg.chunk_num);
		spdk_dma_free(chunkinfos);
	}

	ocssd_aio_env_release();
	return rc;
}

static int ocssd_rw_pm(int argc, char **argv, char *command, char *desc, bool is_read)
{
	char *conffile = "SPDK configure file path";
	char *length = "Assign data length base on page(4KB)";
	char *offset = "Assign data offset base on page(4KB)";
	char *data = "Data file";
	int rc;
	int dfd;
	int flags = !is_read ? O_RDONLY : O_WRONLY | O_CREAT;
	int mode = S_IRUSR | S_IWUSR |S_IRGRP | S_IWGRP| S_IROTH;
	char *data_buffer = NULL;

	struct config {
		char *conffile;
		int length;
		int offset;
		char *data;
	};
	struct config cfg = {
		.conffile = "",
		.length = 0,
		.offset = 0,
		.data = "",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"conffile",  'c', "FILE", CFG_STRING,   &cfg.conffile,         required_argument, conffile},
		{"length",  'l', "NUM", CFG_POSITIVE,   &cfg.length,         required_argument, length},
		{"offset",  'o', "NUM", CFG_POSITIVE,   &cfg.offset,         required_argument, offset},
		{"data",    'f', "FILE", CFG_STRING,      &cfg.data,              required_argument, data},
		{NULL}
	};

	rc = argconfig_parse(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (!rc) {
		rc = get_dev_name(argc, argv);
	}
	if (rc) {
		argconfig_print_help(desc, command_line_options);
		exit(rc);
	}

	dfd = !is_read ? STDIN_FILENO : STDOUT_FILENO;
	if (strlen(cfg.data)){
		dfd = open(cfg.data, flags, mode);
		if (dfd < 0) {
			perror(cfg.data);
			return EINVAL;
		}
	}

	if (!cfg.length)	{
		fprintf(stderr, "length not provided\n");
		return EINVAL;
	}

	cfg.length *= PAGESIZE;
	cfg.offset *= PAGESIZE;

	rc = ocssd_aio_env_prepare(cfg.conffile, dev_name);
	if (rc) {
		fprintf(stderr, "failed to setup SPDK env\n");
		return rc;
	}

	data_buffer = spdk_dma_malloc(cfg.length, PAGESIZE, NULL);
	if (data_buffer == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	if (is_read && read(dfd, (void *)data_buffer, cfg.length) < 0) {
		fprintf(stderr, "failed to read data buffer from input file\n");
		rc = EINVAL;
		goto out;
	}

	reqs_submit[0] = &reqs[0];
	spdk_ocssd_req_prep_pm_rw(reqs_submit[0],
			data_buffer, cfg.length, cfg.offset,
			0, is_read);

	rc = ocssd_aio_req_batch_sync(reqs_submit, 1);
	if (rc != 1) {
        fprintf(stderr, "Failed to get req (rc = %d)\n", rc);
		goto out;
	}
	rc = spdk_bdev_aio_ret_check(&reqs_gotten[0]->ret) != 0;
	if (rc) {
        rc = -EIO;
        goto out;
    }

	if (!is_read && write(dfd, (void *)data_buffer, cfg.length) < 0) {
		fprintf(stderr, "failed to write buffer to output file\n");
		rc = EINVAL;
		goto out;
	}

	fprintf(stderr, "%s: Success\n", command);


out:
	spdk_dma_free(data_buffer);
	ocssd_aio_env_release();
	return rc;
}

static int ocssd_read_pm(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char *desc = "Read persistent memory";

	return ocssd_rw_pm(argc, argv, "read pm", desc, true);
}

static int ocssd_write_pm(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char *desc = "Write persistent memory";

	return ocssd_rw_pm(argc, argv, "write pm", desc, false);
}

static int ocssd_erase_chunk(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Erase specific chunk";
	char *conffile = "SPDK configure file path";
	char *punit_idx = "Index of PUnit";
	char *chunk_idx = "Start index of chunk";
	char *chunk_num = "Number of chunks";
	int rc, i;
	struct spdk_ocssd_chunk_information_entry *chunkinfos = NULL;

	struct config {
		char *conffile;
		int punit_idx;
		int chunk_idx;
		int chunk_num;
	};
	struct config cfg = {
		.conffile = "",
		.punit_idx = 0,
		.chunk_idx = 0,
		.chunk_num = 1,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"conffile",  'c', "FILE", CFG_STRING,   &cfg.conffile,         required_argument, conffile},
		{"punit_idx",  'p', "NUM", CFG_POSITIVE,   &cfg.punit_idx,         required_argument, punit_idx},
		{"chunk_idx",  'k', "NUM", CFG_POSITIVE,   &cfg.chunk_idx,         required_argument, chunk_idx},
		{"chunk_num",  'n', "NUM", CFG_POSITIVE,   &cfg.chunk_num,         required_argument, chunk_num},
		{NULL}
	};

	rc = argconfig_parse(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (!rc) {
		rc = get_dev_name(argc, argv);
	}
	if (rc) {
		argconfig_print_help(desc, command_line_options);
		exit(rc);
	}

	rc = ocssd_aio_env_prepare(cfg.conffile, dev_name);
	if (rc) {
		fprintf(stderr, "failed to setup SPDK env\n");
		return rc;
	}

	rc = ocssd_dev_prepare(dev);
	if(rc) {
		return rc;
	}

	rc = ocssd_dev_chunkinfo_get(cfg.punit_idx, cfg.chunk_idx, cfg.chunk_num, &chunkinfos);
	if (rc != 0) {
		spdk_dma_free(chunkinfos);
		goto out;
	}

	print_ocssd_chunk_info(chunkinfos, cfg.chunk_num);
	for (i = 0; i < cfg.chunk_num; i++) {
		ocssd_sblk_construct(dev, &sblk[i], cfg.punit_idx, cfg.punit_idx, cfg.chunk_idx, &chunkinfos[i]);

		reqs_submit[i] = &reqs[i];
		spdk_ocssd_req_prep_chunk_reset(reqs_submit[i], sblk[i].blks[0].ci.slba, 0);
	}

	rc = ocssd_aio_req_batch_sync(reqs_submit, i);
	if (rc != i) {
        fprintf(stderr, "Failed to get req (rc = %d)\n", rc);
		spdk_dma_free(chunkinfos);
		goto out;
	}

	rc = 0;
	for (i = 0; i < cfg.chunk_num; i++) {
		rc += spdk_bdev_aio_ret_check(&reqs_gotten[i]->ret) != 0;
	}

	if (rc == 0) {
		fprintf(stdout, "%s: Success\n", "erase_chunk");
	} else {
        fprintf(stderr, "Failed to erase chunks\n");
	}

	spdk_dma_free(chunkinfos);
	rc = ocssd_dev_chunkinfo_get(cfg.punit_idx, cfg.chunk_idx, cfg.chunk_num, &chunkinfos);
	if (rc != 0) {
		spdk_dma_free(chunkinfos);
		goto out;
	}

	print_ocssd_chunk_info(chunkinfos, cfg.chunk_num);
	spdk_dma_free(chunkinfos);

out:
	ocssd_aio_env_release();
	return rc;
}

static int ocssd_rw_chunk(int argc, char **argv, char *command, char *desc, bool is_read)
{
	char *conffile = "SPDK configure file path";
	char *punit_idx = "Index of PUnit";
	char *chunk_idx = "Start index of chunk";
	char *data = "Data file";
	int rc;
	int dfd;
	int flags = !is_read ? O_RDONLY : O_WRONLY | O_CREAT;
	int mode = S_IRUSR | S_IWUSR |S_IRGRP | S_IWGRP| S_IROTH;
	char *data_buffer = NULL;
	int i, j, l;
	uint64_t cnlb;
	struct spdk_ocssd_chunk_information_entry *chunkinfos;

	struct config {
		char *conffile;
		int punit_idx;
		int chunk_idx;
		char *data;
	};
	struct config cfg = {
		.conffile = "",
		.punit_idx = 0,
		.chunk_idx = 0,
		.data = "",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"conffile",  'c', "FILE", CFG_STRING,   &cfg.conffile,         required_argument, conffile},
		{"punit_idx",  'p', "NUM", CFG_POSITIVE,   &cfg.punit_idx,         required_argument, punit_idx},
		{"chunk_idx",  'k', "NUM", CFG_POSITIVE,   &cfg.chunk_idx,         required_argument, chunk_idx},
		{"data",    'f', "FILE", CFG_STRING,      &cfg.data,              required_argument, data},
		{NULL}
	};

	rc = argconfig_parse(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (!rc) {
		rc = get_dev_name(argc, argv);
	}
	if (rc) {
		argconfig_print_help(desc, command_line_options);
		exit(rc);
	}

	rc = ocssd_aio_env_prepare(cfg.conffile, dev_name);
	if (rc) {
		fprintf(stderr, "failed to setup SPDK env\n");
		return rc;
	}

	dfd = !is_read ? STDIN_FILENO : STDOUT_FILENO;
	if (strlen(cfg.data)){
		dfd = open(cfg.data, flags, mode);
		if (dfd < 0) {
			perror(cfg.data);
			return EINVAL;
		}
	}

	rc = ocssd_dev_prepare(dev);
	if(rc) {
		return rc;
	}

	printf("Punit, Chunk, Chunk_num are %d %d %d\n", cfg.punit_idx, cfg.chunk_idx, 1);

	rc = ocssd_dev_chunkinfo_get(cfg.punit_idx, cfg.chunk_idx, 1, &chunkinfos);
	if (rc != 0) {
		spdk_dma_free(chunkinfos);
		goto out;
	}

	print_ocssd_chunk_info(chunkinfos, 1);
	ocssd_sblk_construct(dev, &sblk[0], cfg.punit_idx, cfg.punit_idx, cfg.chunk_idx, &chunkinfos[0]);

	/* check chunk is in free state */
	if (!is_read && sblk[0].blks[0].ci.cs.free != 1) {
        fprintf(stderr, "Chunk is not in free state\n");
        rc = -EIO;
        goto out;
	}

	cnlb = dev->geo_data.clba;
	data_buffer = spdk_dma_malloc(cnlb * PAGESIZE, PAGESIZE, NULL);
	if (data_buffer == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	if (!is_read && read(dfd, (void *)data_buffer, cnlb * PAGESIZE) < 0) {
		fprintf(stderr, "failed to read data buffer from input file\n");
		rc = -EINVAL;
		goto out;
	}

	for (i = 0; i < MAX_REQ_NUM; i++) {
		reqs_submit[i] = &reqs[i];
	}
	for (i = 0; i < cnlb; i += MAX_REQ_NUM) {
		for (j = 0; j < MAX_REQ_NUM && i + j < cnlb; j++) {
			uint64_t ppa = sblk[0].blks[0].ci.slba + (i + j);
			void *page_bufer = data_buffer + (i + j) * PAGESIZE;

			spdk_ocssd_req_prep_rw(reqs_submit[j], ppa, 0, page_bufer, PAGESIZE, NULL, 0, 0, is_read, dev->nsid);
		}
		rc = ocssd_aio_req_batch_sync(reqs_submit, MAX_REQ_NUM);
		if (rc != MAX_REQ_NUM) {
	        fprintf(stderr, "Failed to get req (rc = %d)\n", rc);
			goto out;
		}

		rc = 0;
		for (l = 0; l < j; l++) {
			rc += spdk_bdev_aio_ret_check(&reqs_gotten[l]->ret) != 0;
		}

		if (rc != 0) {
	        fprintf(stderr, "Failed to Read/Write data into chunk\n");
	        goto out;
		}
	}

	if (is_read && write(dfd, (void *)data_buffer, cnlb * PAGESIZE) < 0) {
		fprintf(stderr, "failed to write buffer to output file\n");
		rc = EINVAL;
		goto out;
	}

	rc = 0;
	fprintf(stdout, "%s: Success\n", command);

out:
	if(dfd > 0) {
		close(dfd);
	}
	spdk_dma_free(chunkinfos);
	spdk_dma_free(data_buffer);
	ocssd_aio_env_release();
	return rc;
}

static int ocssd_read_chunk(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char *desc = "Read one chunk";

	return ocssd_rw_chunk(argc, argv, "read", desc, 1);
}

static int ocssd_write_chunk(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char *desc = "Write one chunk";

	return ocssd_rw_chunk(argc, argv, "write", desc, 0);
}

static int ocssd_rw_page(int argc, char **argv, char *command, char *desc, bool is_read)
{
	char *conffile = "SPDK configure file path";
	char *punit_idx = "Index of PUnit";
	char *chunk_idx = "Start index of chunk";
	char *page_offset = "Offset of the start page in chunk";
	char *page_num = "Number of page to write";
	char *batch_num = "Number for requests submitted as a batch";
	char *data = "Data file";
	int rc;
	int dfd = 0;;
	int flags = is_read ? O_WRONLY | O_CREAT : O_RDONLY;
	int mode = S_IRUSR | S_IWUSR |S_IRGRP | S_IWGRP| S_IROTH;
	char *data_buffer = NULL;
	int i, j, l;
	struct spdk_ocssd_chunk_information_entry *chunkinfos;

	struct config {
		char *conffile;
		int punit_idx;
		int chunk_idx;
		int page_offset;
		int page_num;
		int batch_num;
		char *data;
	};
	struct config cfg = {
		.conffile = "",
		.punit_idx = 0,
		.chunk_idx = 0,
		.page_offset = 0,
		.page_num = 1,
		.batch_num = 1,
		.data = "",
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"conffile",  'c', "FILE", CFG_STRING,   &cfg.conffile,         required_argument, conffile},
		{"punit_idx",  'p', "NUM", CFG_POSITIVE,   &cfg.punit_idx,         required_argument, punit_idx},
		{"chunk_idx",  'k', "NUM", CFG_POSITIVE,   &cfg.chunk_idx,         required_argument, chunk_idx},
		{"page_offset",  'o', "NUM", CFG_POSITIVE,   &cfg.page_offset,         required_argument, page_offset},
		{"page_num",  'n', "NUM", CFG_POSITIVE,   &cfg.page_num,         required_argument, page_num},
		{"batch_num",  'b', "NUM", CFG_POSITIVE,   &cfg.batch_num,         required_argument, batch_num},
		{"data",    'f', "FILE", CFG_STRING,      &cfg.data,              required_argument, data},
		{NULL}
	};

	rc = argconfig_parse(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (!rc) {
		rc = get_dev_name(argc, argv);
	}
	if (rc) {
		argconfig_print_help(desc, command_line_options);
		exit(rc);
	}

	rc = ocssd_aio_env_prepare(cfg.conffile, dev_name);
	if (rc) {
		fprintf(stderr, "failed to setup SPDK env\n");
		return rc;
	}

	dfd = is_read ? STDOUT_FILENO : STDIN_FILENO;
	if (strlen(cfg.data)){
		dfd = open(cfg.data, flags, mode);
		if (dfd < 0) {
			perror(cfg.data);
			return EINVAL;
		}
	}

	rc = ocssd_dev_prepare(dev);
	if(rc) {
		return rc;
	}

	printf("Punit, Chunk, Page_off, Page_num are %d %d %d %d\n", cfg.punit_idx, cfg.chunk_idx, cfg.page_offset, cfg.page_num);
	rc = ocssd_dev_chunkinfo_get(cfg.punit_idx, cfg.chunk_idx, 1, &chunkinfos);
	if (rc != 0) {
		goto out;
	}

	print_ocssd_chunk_info(chunkinfos, 1);
	ocssd_sblk_construct(dev, &sblk[0], cfg.punit_idx, cfg.punit_idx, cfg.chunk_idx, &chunkinfos[0]);

	if (!is_read) {
		/* check chunk is in open state */
		if (sblk[0].blks[0].ci.cs.open != 1 && sblk[0].blks[0].ci.cs.free != 1) {
	        fprintf(stderr, "Chunk is not in open state\n");
	        rc = -EIO;
	        goto out;
		}

		/* check page_offset and page_num */
		if (cfg.page_offset != sblk[0].blks[0].ci.wp) {
	        fprintf(stderr, "Invalid page offset\n");
	        rc = -EINVAL;
	        goto out;
		}
	}

	if (cfg.page_offset < 0 || cfg.page_num < 1 || cfg.page_num + cfg.page_offset > dev->geo_data.clba) {
        fprintf(stderr, "Invalid page offset or num\n");
        rc = -EINVAL;
        goto out;
	}

	data_buffer = spdk_dma_malloc(cfg.page_num * PAGESIZE, PAGESIZE, NULL);
	if (data_buffer == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	if (!is_read && read(dfd, (void *)data_buffer, cfg.page_num * PAGESIZE) < 0) {
		fprintf(stderr, "failed to read data buffer from input file\n");
		rc = -EINVAL;
		goto out;
	}

	for (i = 0; i < cfg.batch_num; i++) {
		reqs_submit[i] = &reqs[i];
	}


	for (i = 0; i < cfg.page_num; i += cfg.batch_num) {
		for (j = 0; j < cfg.batch_num && i + j < cfg.page_num; j++) {
			uint64_t ppa = sblk[0].blks[0].ci.slba + (i + j) + cfg.page_offset;
			void *page_bufer = data_buffer + (i + j) * PAGESIZE;

			spdk_ocssd_req_prep_rw(reqs_submit[j], ppa, 0, page_bufer, PAGESIZE, NULL, 0, 0, is_read, dev->nsid);
		}
		rc = ocssd_aio_req_batch_sync(reqs_submit, j);
		if (rc != j) {
	        fprintf(stderr, "Failed to get req (rc = %d)\n", rc);
			goto out;
		}

		rc = 0;
		for (l = 0; l < j; l++) {
			rc += spdk_bdev_aio_ret_check(&reqs_gotten[l]->ret) != 0;
		}

		if (rc != 0) {
	        fprintf(stderr, "Failed to Read/Write data into chunk\n");
	        goto out;
		}
	}

	if (is_read && write(dfd, (void *)data_buffer, cfg.page_num * PAGESIZE) < 0) {
		fprintf(stderr, "failed to write buffer to output file\n");
		rc = EINVAL;
		goto out;
	}

out:
	if(dfd > 0) {
		close(dfd);
	}
	spdk_dma_free(chunkinfos);
	spdk_dma_free(data_buffer);
	ocssd_aio_env_release();
	return rc;
}

static int ocssd_read_page(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char *desc = "Read one page";

	return ocssd_rw_page(argc, argv, "read", desc, true);
}

static int ocssd_write_page(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char *desc = "Write one page";

	return ocssd_rw_page(argc, argv, "write", desc, false);
}

static int ocssd_rw_chunk_strip(int argc, char **argv, char *command, char *desc, bool is_read)
{
	char *conffile = "SPDK configure file path";
	char *punit_idx_s = "Start index of PUnit";
	char *punit_idx_e = "End index of PUnit";
	char *chunk_idx = "Start index of chunk";
	char *batch_num = "Number for requests submitted as a batch";
	int rc;
	char *data_buffer = NULL;
	int i, j, l, k;
	uint64_t cnlb;
	struct spdk_ocssd_chunk_information_entry *chunkinfos = NULL;
	struct spdk_ocssd_chunk_information_entry *chunkinfos_re = NULL;
	uint64_t ticks_user[2] = {0};
	uint64_t hz;

	struct config {
		char *conffile;
		int punit_idx_s;
		int punit_idx_e;
		int batch_num;
		int chunk_idx;
	};
	struct config cfg = {
		.conffile = "",
		.punit_idx_s = 0,
		.punit_idx_e = 15,
		.batch_num = 32,
		.chunk_idx = 0,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"conffile",  'c', "FILE", CFG_STRING,   &cfg.conffile,         required_argument, conffile},
		{"punit_idx_s",  's', "NUM", CFG_POSITIVE,   &cfg.punit_idx_s,         required_argument, punit_idx_s},
		{"punit_idx_e",  'e', "NUM", CFG_POSITIVE,   &cfg.punit_idx_e,         required_argument, punit_idx_e},
		{"chunk_idx",  'k', "NUM", CFG_POSITIVE,   &cfg.chunk_idx,         required_argument, chunk_idx},
		{"batch_num",  'b', "NUM", CFG_POSITIVE,   &cfg.batch_num,         required_argument, batch_num},
		{NULL}
	};

	rc = argconfig_parse(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (!rc) {
		rc = get_dev_name(argc, argv);
	}
	if (rc) {
		argconfig_print_help(desc, command_line_options);
		exit(rc);
	}

	rc = ocssd_aio_env_prepare(cfg.conffile, dev_name);
	if (rc) {
		fprintf(stderr, "failed to setup SPDK env\n");
		return rc;
	}

	rc = ocssd_dev_prepare(dev);
	if(rc) {
		return rc;
	}

	printf("Punit (%d-%d), Chunk, Chunk_num are %d %d\n", cfg.punit_idx_s, cfg.punit_idx_e, cfg.chunk_idx, 1);
	/* Check correctness of Punits */
	if (cfg.punit_idx_s < 0 || cfg.punit_idx_s > cfg.punit_idx_e
			|| cfg.punit_idx_e >= dev->geo_data.num_pu * dev->geo_data.num_grp) {
        fprintf(stderr, "Invalid Punits idx\n");
        return -EINVAL;
	}

	chunkinfos_re = malloc(sizeof(*chunkinfos_re) * (cfg.punit_idx_e - cfg.punit_idx_s + 1));
	if (!chunkinfos_re) {
		rc = -ENOMEM;
		goto out;
	}
	for (i = 0; i < cfg.punit_idx_e - cfg.punit_idx_s + 1; i++) {
		rc = ocssd_dev_chunkinfo_get(cfg.punit_idx_s + i, cfg.chunk_idx, 1, &chunkinfos);
		if (rc != 0) {
			goto out;
		}
		memcpy(&chunkinfos_re[i], &chunkinfos[0], sizeof(*chunkinfos_re));
		spdk_dma_free(chunkinfos);
	}

	print_ocssd_chunk_info(chunkinfos_re, cfg.punit_idx_e - cfg.punit_idx_s + 1);
	ocssd_sblk_construct(dev, &sblk[0], cfg.punit_idx_s, cfg.punit_idx_e, cfg.chunk_idx, chunkinfos_re);

	for (i = 0; i < cfg.punit_idx_e - cfg.punit_idx_s + 1; i++) {
		/* check chunk is in free state */
		if (!is_read && sblk[0].blks[i].ci.cs.free != 1) {
	        fprintf(stderr, "Chunk is not in free state\n");
	        rc = -EIO;
	        goto out;
		}
	}

	cnlb = dev->geo_data.clba;
	data_buffer = spdk_dma_malloc(cnlb * PAGESIZE, PAGESIZE, NULL);
	if (data_buffer == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	for (i = 0; i < cfg.batch_num; i++) {
		reqs_submit[i] = &reqs[i];
	}

	ticks_user[0] =  spdk_get_ticks();
	for (i = 0; i < cnlb; i += cfg.batch_num) {
		for (k = 0; k < cfg.punit_idx_e - cfg.punit_idx_s + 1; k++) {
			for (j = 0; j < cfg.batch_num && i + j < cnlb; j++) {
				uint64_t ppa = sblk[0].blks[k].ci.slba + (i + j);
				void *page_bufer = data_buffer + (i + j) * PAGESIZE;

				spdk_ocssd_req_prep_rw(reqs_submit[j], ppa, 0, page_bufer, PAGESIZE, NULL, 0, 0, is_read, dev->nsid);
			}
			rc = ocssd_aio_req_batch_sync(reqs_submit, j);
			if (rc != j) {
		        fprintf(stderr, "Failed to get req (rc = %d)\n", rc);
				goto out;
			}

			rc = 0;
			for (l = 0; l < j; l++) {
				rc += spdk_bdev_aio_ret_check(&reqs_gotten[l]->ret) != 0;
			}

			if (rc != 0) {
		        fprintf(stderr, "Failed to Read/Write data into chunk\n");
		        goto out;
			}
		}
	}
	ticks_user[1] =  spdk_get_ticks();
	hz = spdk_get_ticks_hz();
	printf("Total time cost is %lu msec\n", (ticks_user[1] - ticks_user[0]) / (hz / 1000));

	rc = 0;
	fprintf(stdout, "%s: Success\n", command);

out:
	free(chunkinfos_re);
	spdk_dma_free(data_buffer);
	ocssd_aio_env_release();
	return rc;
}

static int ocssd_read_chunk_strip(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char *desc = "Read one chunk strip";

	return ocssd_rw_chunk_strip(argc, argv, "read", desc, 1);
}

static int ocssd_write_chunk_strip(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char *desc = "Write one chunk strip";

	return ocssd_rw_chunk_strip(argc, argv, "write", desc, 0);
}

