/*
 * Copyright 2022-2025 NXP
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef IMX_SIGNER_H
#define IMX_SIGNER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <libgen.h>
#include <stdbool.h>
#include <unistd.h>

/************************
        Command line arguments
************************/
/* Valid short command line option letters. */
const char* const short_opt = "hfdi:o:c:";

/* Valid long command line options. */
const struct option long_opt[] =
{
    {"image", required_argument,  0, 'i'},
    {"cfg-file", required_argument,  0, 'c'},
    {"offset", required_argument,  0, 'o'},
    {"debug", no_argument,  0, 'd'},
    {"fdt-debug", no_argument,  0, 'f'},
    {"help", no_argument, 0, 'h'},
    {NULL, 0, NULL, 0}
};

/* Option descriptions */
const char* desc_opt[] =
{
    "Input image to be signed",
    "Input config file to prepare CSF/YAML config (See csf_ahab.cfg.sample/csf_hab.cfg.sample/spsdk_ahab.cfg.sample for details)",
    "(Optional) Offset to the start of image",
    "(Optional) Enable debug information",
    "(Optional) FDT debug information",
    "This text",
    NULL
};

#define FREE(x)             do { \
                                if(NULL != x) { \
                                    free(x); \
                                    x = NULL; \
                                } \
                            } while(0)

#define FCLOSE(x)           do { \
                                if(NULL != x) { \
                                    fclose(x); \
                                    x = NULL; \
                                } \
                            } while(0)

#define DEBUG(fmt, ...)     do { \
                                if (1 == g_debug) { \
                                    printf("%s:%s:%d: " fmt, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
                                } \
                            } while(0)

#define ASSERT(x, y)        do { \
                                if (NULL == x) { \
                                    fprintf(stderr, "ERROR: ASSERT failed at %s:%d\n", __FUNCTION__, __LINE__); \
                                    return y; \
                                } \
                            } while(0)

#define BASE_HEX                    16UL
#define FILENAME_MAX_LEN            100UL
#define SYS_CMD_LEN                 400UL

#define IV_MAX_LEN                  32
#define HASH_MAX_LEN                64
#define MAX_NUM_IMGS                8
#define MAX_NUM_OF_CONTAINER        4

#define IVT_HEADER_TAG              0xD1
#define IVT_HEADER_TAG_B0           0x87
#define IVT_HEADER_TAG_MSG          0x89


#define IMAGE_TYPE_MASK             0xF

#define CONTAINER_ALIGNMENT         0x400

#define ALIGN(x,a)                  __ALIGN_MASK((x),(__typeof__(x))(a)-1)
#define __ALIGN_MASK(x,mask)        (((x)+(mask))&~(mask))

typedef enum SOC_TYPE {
    NONE = 0,
    QX,
    QM,
    DXL,
    ULP,
} soc_type_t;

typedef enum PCKS_TOKEN {
    PCKS11_EN = 1,
    TOKEN_EN,
    USRPIN = 4,
    TYPE_CERT = 8,
} pkcs11token_type_t;

#define E_OK 0
#define E_FAILURE 1

#define ASCENDING 0
#define DESCENDING 1

/* offset of the FIT images relative to IVT offset */
#define FIT_IMAGES_OFFSET 0x2000

/* [IVT] + CSF size. In case of SPL is CSF size */
#define IVT_CSF_SIZE 0x2000

typedef struct {
    uint8_t tag;
    uint16_t length;
    uint8_t version;
} __attribute__((packed)) ivt_header_t;

typedef struct {
    ivt_header_t ivt_hdr;
    uint32_t entry;
    uint32_t reserved1;
    uint32_t dcd;
    uint32_t boot_data;
    uint32_t self_addr;
    uint32_t csf_addr;
    uint32_t reserved2;
} __attribute__((packed)) ivt_t;

typedef struct {
    uint32_t start;
    uint32_t length;
    uint32_t plugin_flag;
} __attribute__((packed)) boot_data_t;


typedef struct {
    uint8_t version;
    uint16_t length;
    uint8_t tag;
    uint16_t srk_table_offset;
    uint16_t cert_offset;
    uint16_t blob_offset;
    uint16_t signature_offset;
    uint32_t reserved;
} __attribute__((packed)) sig_blk_hdr_t;

typedef struct {
    char type;
    char core_id;
    char hash_type;
    bool encrypted;
    uint16_t boot_flags;
} img_flags_t;

typedef struct {
    uint32_t offset;
    uint32_t size;
    uint64_t dst;
    uint64_t entry;
    uint32_t hab_flags;
    uint32_t meta;
    uint8_t hash[HASH_MAX_LEN];
    uint8_t iv[IV_MAX_LEN];
} __attribute__((packed)) boot_img_t;

typedef struct {
    uint8_t version;
    uint16_t length;
    uint8_t tag;
    uint32_t flags;
    uint16_t sw_version;
    uint8_t fuse_version;
    uint8_t num_images;
    uint16_t sig_blk_offset;
    uint16_t reserved;
    boot_img_t img[MAX_NUM_IMGS];
    sig_blk_hdr_t sig_blk_hdr;
    uint32_t sigblk_size;
    uint32_t padding;
} __attribute__((packed)) flash_header_v3_t;

/*   Global Variables   */
static bool g_debug = 0;
static char *g_cfgfilename = NULL;
extern uint32_t g_image_offset;
static char *g_sig_tool_path = NULL;
static char *g_sig_data_path = NULL;

const char *g_user_pin = "USR_PIN";
const char *g_token = "CST-HSM-DEMO";

unsigned char g_ivt_v1_mask[] = {0xFF,0xFF,0xFF,0xF0};
unsigned char g_ivt_v1[] = {0xD1,0x00,0x20,0x41};


unsigned char g_ivt_v3_mask[] = {0xff, 0x00, 0x00, 0xff};
/* array contains tag_b0, tag_msg*/
unsigned char g_ivt_v3_ahab_array[2][4] = {{0x00 ,0x00, 0x00, 0x87},/*tag_b0*/
                                           {0x00 ,0x00, 0x00, 0x89}};/*tag_msg*/
#define TAG_B0 0x87
#define TAG_MSG 0x89
#define TAG_SIG_BLK 0x90
#define AHAB_1K_ALIGN 0x400

/*
 * header tag check happens at every 0x400 offset inside the image as per NXP
 * BSP boot image architecture
 */
#define HAB_IVT_SEARCH_STEP  0x400
#define AHAB_IVT_SEARCH_STEP 0x400
/*
 * Length is the size of the container header, up through, and
 * including the signature block. A valid image must have the length at least this
 * value
 */
#define AHAB_CONTAINER_MIN_LENGTH (sizeof(((flash_header_v3_t *)(0))->version) + \
	sizeof(((flash_header_v3_t *)(0))->length) + \
	sizeof(((flash_header_v3_t *)(0))->tag) + \
	sizeof(((flash_header_v3_t *)(0))->flags) + \
	sizeof(((flash_header_v3_t *)(0))->sw_version) + \
	sizeof(((flash_header_v3_t *)(0))->fuse_version)  + \
	sizeof(((flash_header_v3_t *)(0))->num_images)  + \
	sizeof(((flash_header_v3_t *)(0))->sig_blk_offset)  + \
	sizeof(((flash_header_v3_t *)(0))->reserved)  + \
    sizeof(boot_img_t))

/* Message Container length should be exactly 0x48 */
#define AHAB_MSG_CONTAINER_LENGTH 0x48

#define HDMI_IMAGE_FLAG_MASK                (0x0002)    /* bit 1 is HDMI image indicator   */

#define IS_AHAB_IMAGE(buf, size, ahab_array, ivt_v3_mask, off)                      \
({                                                                                  \
    int num_cntr_tags = sizeof(ahab_array)/sizeof(ahab_array[0]);                   \
    unsigned char (*p)[sizeof(ahab_array[0])] = ahab_array;                         \
    bool is_valid = false;                                                          \
                                                                                    \
    do {                                                                            \
        off = search_pattern(buf, *p++, size, sizeof(ahab_array[0]),                \
                             ASCENDING, g_image_offset, ivt_v3_mask,                \
                             AHAB_IVT_SEARCH_STEP);                                 \
        if (off < size) {                                                           \
            flash_header_v3_t *hdr_v3 = (flash_header_v3_t *)(buf + off);           \
            sig_blk_hdr_t *sig_blk_hdr =                                            \
                        (sig_blk_hdr_t *)(buf + off + hdr_v3->sig_blk_offset);      \
            if (hdr_v3->tag == TAG_B0) {                                            \
            /* Strengthen AHAB header search with following:                        \
             *  - Minimum length of container                                       \
             *  - Reserved fields                                                   \
             *  - Signature block header tag and version                            \
             *  - Version                                                           \
             */                                                                     \
                if (hdr_v3->length >= AHAB_CONTAINER_MIN_LENGTH                     \
                    && (!hdr_v3->reserved)                                          \
                    && sig_blk_hdr->tag == TAG_SIG_BLK                              \
                    && (!sig_blk_hdr->version)                                      \
                    && (!sig_blk_hdr->reserved))                                    \
                    is_valid = true;                                                \
            } else  if (hdr_v3->tag == TAG_MSG) {                                   \
                if (hdr_v3->length == AHAB_MSG_CONTAINER_LENGTH)                    \
                    is_valid = true;                                                \
            }                                                                       \
                                                                                    \
            break;                                                                  \
        }                                                                           \
    }  while(--num_cntr_tags);                                                      \
    (size > off && is_valid);                                                       \
})                                                                                  \

#define IS_FIT_IMAGE(buf, off)                                                    \
({                                                                                \
     bool is_valid = false;                                                       \
     if (off >= 0x1000) {                                                          \
         fdt_header_t *fit_img = (fdt_header_t *)(buf + off - 0x1000);            \
         ivt_t *ivt = (ivt_t *)(buf + off);                                       \
                                                                                  \
         if ((be32_to_cpu(fit_img->magic) == FDT_MAGIC) &&                        \
             (ivt->self_addr >= ivt->entry) && (ivt->csf_addr > ivt->entry) &&    \
             (ivt->csf_addr > ivt->self_addr) && (!ivt->reserved1) &&             \
             (!ivt->reserved2)) {                                                 \
             is_valid = true;                                                     \
         }                                                                        \
     }                                                                            \
     (is_valid);                                                                  \
 })                                                                               \

#define IS_HAB_IMAGE(buf, size, ivt_v1, ivt_v1_mask, off, pos)                    \
({                                                                                \
     off =  search_pattern(buf, ivt_v1, size, sizeof(ivt_v1) / sizeof(ivt_v1[0]), \
                           ASCENDING, pos, ivt_v1_mask,                \
                           HAB_IVT_SEARCH_STEP);                                  \
     bool is_valid = false;                                                       \
     ivt_t *ivt = (ivt_t *)(buf + off);                                           \
                                                                                  \
     if (off < size) {                                                            \
         /* Strengthen HAB header search with following:                          \
          * - CSF address is always greater than ENTRY and SELF address           \
          * - Reserved fields                                                     \
          */                                                                      \
         if ((ivt->csf_addr > ivt->entry) && (ivt->csf_addr > ivt->self_addr) &&  \
             (!ivt->reserved1) && (!ivt->reserved2))                              \
             is_valid = true;                                                     \
     }                                                                            \
     (size > off && is_valid);                                                    \
})                                                                                \

/* Function prototypes */
int copy_files(char *ifname, char *ofname);
long int get_file_size(FILE *fp, char *input_file);
unsigned char *alloc_buffer(FILE *fp, char *input_file);

#endif /* IMX_SIGNER_H */
