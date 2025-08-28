/*
 * Copyright 2022-2025 NXP
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <limits.h>

#include <imx_signer.h>
#include <cfg_parser.h>
#include <mkimage_helper.h>
#include <fdt.h>

#define RSIZE   256

uint32_t g_image_offset = 0;
unsigned long g_ivt_off_cve = 0x0;
unsigned long g_ivt_search_step = 0;
int g_last_img_idx = 0;

//const char *g_path_pkcs11 = "PKCS11_MODULE_PATH";
const char *g_user_pin = "USR_PIN";
const char *g_token = "CST-HSM-DEMO";

typedef struct {
    int cntr_num;
    uint32_t cntr_offset;
    uint32_t sig_offset;
} __attribute__((packed)) csf_params_t;

image_block_t g_images[NUM_IMGS];

/*
 * @brief      Search for pattern in buffer
 *
 * @param[in]   buff     : Input buffer to search into
 * @param[in]   pattern  : Input pattern
 * @param[in]   buff_len : Input buffer length
 * @param[in]   patt_len : Input pattern length
 * @param[in]   pos      : Position where to start the search from
 * @param[in]   order    : Search order from @pos: ascending or descending
 * @param[in]   mask     : Mask bytes in @pattern
 * @param[in]   step     : Use step bytes to increment from position for the next
 *                         search iteration.
 *
 * @retval      Return offset in buffer for the pattern. If pattern not found,
 *                 return buff_len + 1.
 */
unsigned long search_pattern(const unsigned char *buff, unsigned char *pattern,
                 size_t buff_len, size_t patt_len, unsigned short order,
                             unsigned long pos, unsigned char *mask, unsigned long step)
{
    unsigned long off;
    short found = 0;
    char temp[patt_len];

    buff += pos;
    memset(temp, 0, patt_len);
    if (mask) {
        for (int j = 0; j < patt_len; j++)
            pattern[j] = pattern[j] & mask[j];
    }

    /*search in ascending order */
    if (order == ASCENDING) {
        /* no search optimization */
        for (off = pos; off < (buff_len - patt_len + 1); off += step) {
            if (mask) {/*  some values can be masked, e.g. length inside IVT tag */
                memcpy(temp, buff, patt_len);
                for (int j = 0; j < patt_len; j++) {
                    temp[j] = temp[j] & mask[j];
                }
                if (!memcmp(pattern, temp, patt_len)) {
                    found = 1;
                    break;
                }
            } else {
                if (!memcmp(pattern, buff, patt_len)) {
                    found = 1;
                    break;
                }
            }
            buff += step;
        }
    } else {/*search in descending order */
        for (off = pos; off >= (patt_len - 1) ;off -= step) {
            if (mask) {
                memcpy(temp, (buff - patt_len + 1), patt_len);
                for (int j = 0; j < patt_len; j++) {
                    temp[j] = temp[j] & mask[j];
                }
                if (!memcmp(pattern, temp, patt_len)) {
                    found = 1;
                    off = off - patt_len + 1;
                    break;
                }
            } else {
                if (!memcmp(pattern, (buff - patt_len + 1),
                        patt_len)) {
                    found = 1;
                    off = off - patt_len + 1;
                    break;
                }
            }
            buff -= step;
        }
    }

    if (!found)
        off = buff_len + 1;

    return off;
}

/*
 * @brief       Find SPSDK tool from the g_sig_tool_path
 *
 * @param[in,out] spsdk_path : Empty array to the spsdk path gets filled with
 *                            g_sig_tool_path and spsdk binary location
 *
 * @retval      -E_FAILURE : Failure
 *               E_OK      : Success
 */
static int find_spsdk_tool(char *spsdk_path)
{
    ASSERT(spsdk_path, -1);

    if (strlen(spsdk_path)) {
        DEBUG("INFO: Emptying path to search tool...\n");
        memset(spsdk_path, 0, SYS_CMD_LEN);
    }

    /* Build SPSDK path */
#if defined(__linux__) || defined(_WIN32) || defined(_WIN64)
    if (0 > (snprintf(spsdk_path, SYS_CMD_LEN, "%s/spsdk", g_sig_tool_path))) {
        fprintf(stderr, "ERROR: System command build unsuccessful. Exiting.\n");
        return -E_FAILURE;
    }
#else
    #error Unsupported OS
#endif

    /* Check if the SPSDK binary exists */
    if (access(spsdk_path, X_OK)) {
        DEBUG("SPSDK tool is not found at %s\n", spsdk_path);
        return -E_FAILURE;
    }

    if (strlen(spsdk_path)) {
        DEBUG("INFO: Emptying path to search tool...\n");
        memset(spsdk_path, 0, SYS_CMD_LEN);
    }

    /* Build SPSDK nxpimage path */
#if defined(__linux__) || defined(_WIN32) || defined(_WIN64)
    if (0 > (snprintf(spsdk_path, SYS_CMD_LEN, "%s/nxpimage", g_sig_tool_path))) {
        fprintf(stderr, "ERROR: System command build unsuccessful. Exiting.\n");
        return -E_FAILURE;
    }
#else
    #error Unsupported OS
#endif

    /* Check if the SPSDK binary exists */
    if (access(spsdk_path, X_OK)) {
        DEBUG("SPSDK nxpimage tool is not found at %s\n", spsdk_path);
        return -E_FAILURE;
    }

    return E_OK;
}

/*
 * @brief       Find CST tool from the g_sig_tool_path
 *
 * @param[in,out] cst_path : Empty array to the cst path gets filled with
 *                          g_sig_tool_path and cst binary location
 *
 * @retval      -E_FAILURE : Failure
 *               E_OK      : Success
 */
static int find_cst_tool(char *cst_path)
{

    ASSERT(cst_path, -1);

    if (strlen(cst_path)) {
        DEBUG("WARNING: Emptying path to search tool...\n");
        memset(cst_path, 0, SYS_CMD_LEN);
    }

    /* Build CST path */
#if defined(__linux__)
    if (0 > (snprintf(cst_path, SYS_CMD_LEN, "%s/linux64/bin/cst", g_sig_tool_path))) {
        fprintf(stderr, "ERROR: System command build unsuccessful. Exiting.\n");
        return -E_FAILURE;
    }
#elif defined(_WIN32) || defined(_WIN64)
    if (0 > (snprintf(cst_path, SYS_CMD_LEN, "%s/mingw32/bin/cst.exe", g_sig_tool_path))) {
        fprintf(stderr, "ERROR: System command build unsuccessful. Exiting.\n");
        return -E_FAILURE;
    }
#else
    #error Unsupported OS
#endif

    /* Check if the CST binary exists */
    if (access(cst_path, X_OK)) {
        DEBUG("CST tool is not found at %s\n", cst_path);
        return -E_FAILURE;
    }
    
    return E_OK;
}

/*
 * @brief       Common function to call SPSPDK nxpimage to sign the generated 
 *              YAML config file
 *
 * @param[in]   cfgname : Input YAML config filename
 * @param[in]   ifname  : Input binary filename
 * @param[out]  ofname  : Output signed filename
 *
 * @retval      -E_FAILURE : Failure
 *               E_OK      : Success
 */
int sign_yaml_config(char *cfgname, char *ifname, char *ofname)
{
    ASSERT(cfgname, -1);
    ASSERT(ifname, -1);
    ASSERT(ofname, -1);

    char sys_cmd[SYS_CMD_LEN] = {0};
    char spsdk_extra_param[10] = {0};

    /* Add debug info to the tool output */
    if (g_debug)
        strncpy(spsdk_extra_param, "-v", 3);

    /* Find if tool exists and capture path */
    if (!find_spsdk_tool(&sys_cmd[0])) {
        if (0 > (snprintf(sys_cmd + strlen(sys_cmd), (SYS_CMD_LEN - strlen(sys_cmd)), " %s ahab sign --force -c %s -b %s -o %s", spsdk_extra_param, cfgname, ifname, ofname))) {
            fprintf(stderr, "ERROR: System command build unsuccessful. Exiting.\n");
            return -E_FAILURE;
        }
    } else {
        fprintf(stderr, "ERROR: SPSDK Tool not found. Exiting.\n");
        return -E_FAILURE;
    }

    /* Execute command */
    printf("Executing command: %s\n", sys_cmd);
    return(system(sys_cmd));
}

/*
 * @brief       Common function to call CST to sign the generated CSF file
 *
 * @param[in]   cfgname : Input CSF config filename
 * @param[out]  ofname  : Output signed filename
 *
 * @retval      -E_FAILURE : Failure
 *               E_OK      : Success
 */
int sign_csf(char *cfgname, char *ofname)
{
    ASSERT(cfgname, -1);
    ASSERT(ofname, -1);

    char sys_cmd[SYS_CMD_LEN] = {0};
    char cst_extra_param[10] = {0};
    char cst_extra_token[10] = {0};

    /* Add debug info to the tool output */
    if (g_debug) {
        strncpy(cst_extra_param, "--verbose", 10);
    }
    strncpy(cst_extra_token, "-b pkcs11", 10);
    /* Find if tool exists and capture path */
    if (!find_cst_tool(&sys_cmd[0])) {
        if (0 > (snprintf(sys_cmd + strlen(sys_cmd), (SYS_CMD_LEN - strlen(sys_cmd)), " %s %s --i %s --o %s", cst_extra_param, cst_extra_token, cfgname, ofname))) {
            fprintf(stderr, "ERROR: System command build unsuccessful. Exiting.\n");
            return -E_FAILURE;
        }
    } else {
        fprintf(stderr, "ERROR: CST Tool not found. Exiting.\n");
        return -E_FAILURE;
    }

    /* Execute command */
    printf("Executing command: %s\n", sys_cmd);
    return(system(sys_cmd));
}

/*
 * @brief       Clone input file to output file
 *
 * @param[in]   ifname  : Input file
 * @param[out]  ofname  : Output file
 *
 * @retval     -E_FAILURE : Success
 *              E_OK      : Failure
 */
int copy_files(char *ifname, char *ofname)
{
    ASSERT(ifname, -1);
    ASSERT(ofname, -1);

    long int ifname_size = 0;
    unsigned char *buf = NULL;
    size_t result_size = 0;
    
    /* Open input file */
    FILE *fp_ifname = fopen(ifname, "rb");
    if (NULL == fp_ifname) {
        fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", ifname, strerror(errno));
        goto err;
    }
    
    ifname_size = get_file_size(fp_ifname, ifname);
    if (0 > ifname_size) {
        fprintf(stderr, "ERROR: Invalid file size %ld of file: %s\n", ifname_size, ifname);
        goto err;
    }

    /* Open output file */
    FILE *fp_ofname = fopen(ofname, "wb");
    if (NULL == fp_ofname) {
        fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", ofname, strerror(errno));
        goto err;
    }

    /* Allocate memory to the buffer */
    buf = malloc(ifname_size);
    if (NULL == buf || 0 == buf) {
        fprintf(stderr, "ERROR: Error allocating memory; %s\n", strerror(errno));
        goto err;
    }

    /* Copy input file to output file */
    result_size = fread(buf, 1, ifname_size, fp_ifname);
    if (result_size != ifname_size) {
        fprintf(stderr, "ERROR: File read error; %s\n", strerror(errno));
        goto err;
    } else {
        result_size = fwrite(buf, 1, ifname_size, fp_ofname);
        if (result_size != ifname_size) {
            fprintf(stderr, "ERROR: File write error; %s\n", strerror(errno));
            goto err;
        }
    }

    /* Cleanup */
    FREE(buf);
    FCLOSE(fp_ifname);
    FCLOSE(fp_ofname);
    return E_OK;

err:
    FREE(buf);
    FCLOSE(fp_ifname);
    FCLOSE(fp_ofname);
    return -E_FAILURE;
}

/*
 * @brief       Create CSF source file for IVT type v1
 *
 * @param[in]   blocks     : Data blocks that will be authenticated
 *              idx        : CSF file has a standard naming csf_image%d.txt
 *                           idx represents the index of the CSF file and will
 *                           be appended in the name
 * @param[out]  ofname     : The name of the generated CSF source file
 *
 * @retval      -E_FAILURE      : Failure
 *               E_OK           : Success
 */
static int create_csf_file_v1(image_block_t *blocks, int idx, char *ofname)
{
    char csf_filename[100UL] = {0};
    char rvalue[RSIZE] = {0};
    bool fast_auth = false;

    if (0 > (snprintf(csf_filename, sizeof(csf_filename), "csf_image%d.txt", idx))) {
        fprintf(stderr, "ERROR: Cannot populate CSF file name.\n");
        return -E_FAILURE;
    }

    /* Create CSF file with CSF parameters */
    FILE *fp_csf_file = fopen(csf_filename, "w");
    if (NULL == fp_csf_file ) {
        fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", csf_filename, strerror(errno));
        return -E_FAILURE;
    }

    /* Open CSF config file */
    FILE *fp_cfg = fopen(g_cfgfilename, "r");
    if (NULL == fp_cfg) {
       fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", g_cfgfilename, strerror(errno));
       FCLOSE(fp_csf_file);
       return -E_FAILURE;
    }

    /* Populate CSF file with appropriate parameters */
    /* Header */
    fprintf(fp_csf_file, "[Header]\n");

    cfg_parser(fp_cfg, rvalue, RSIZE, "header_version");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tVersion = 4.3\n");
    else
        fprintf(fp_csf_file, "\tVersion = %s\n", rvalue);


    fprintf(fp_csf_file, "\tHash Algorithm = sha256\n");

    cfg_parser(fp_cfg, rvalue, RSIZE, "header_eng");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tEngine = ANY\n");
    else
        fprintf(fp_csf_file, "\tEngine = %s\n", rvalue);

    cfg_parser(fp_cfg, rvalue, RSIZE, "header_eng_config");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tEngine Configuration = 0\n");
    else
        fprintf(fp_csf_file, "\tEngine Configuration = %s\n", rvalue);

    fprintf(fp_csf_file, "\tCertificate Format = X509\n");

    fprintf(fp_csf_file, "\tSignature Format = CMS\n");

    /* Install SRK */
    fprintf(fp_csf_file, "[Install SRK]\n");
    cfg_parser(fp_cfg, rvalue, RSIZE, "srktable_file");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tFile = \"%s/crts/SRK_1_2_3_4_table.bin\"\n", g_sig_tool_path);
    else
        fprintf(fp_csf_file, "\tFile = \"%s/crts/%s\"\n", g_sig_tool_path, rvalue);

    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_source_index");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tSource index = 0\n");
    else
        fprintf(fp_csf_file, "\tSource index = %s\n", rvalue);

    /* Choose between fast authentication and normal authentication */
    cfg_parser(fp_cfg, rvalue, RSIZE, "nocak_file");
    if ('\0' != rvalue[0]) {
        /* Prepare fast authentication parameters */
        fast_auth = true;
        /* Install NOCAK */
        fprintf(fp_csf_file, "[Install NOCAK]\n");
        fprintf(fp_csf_file, "\tFile = \"%s/crts/%s\"\n", g_sig_tool_path, rvalue);
    } else {
        /* Prepare normal authentication parameters */
        /* Install CSFK */
        fprintf(fp_csf_file, "[Install CSFK]\n");
        cfg_parser(fp_cfg, rvalue, RSIZE, "csfk_file");
        if ('\0' == rvalue[0])
            fprintf(fp_csf_file, "\tFile = \"%s/crts/CSF1_1_sha256_2048_65537_v3_usr_crt.pem\"\n", g_sig_tool_path);
        else{
            DEBUG("Install csfk is %s.\n",rvalue);
            uint8_t Interact_token = 0;
            uint8_t counter = 0;
            for (int i = 0; rvalue[i] != '\0' ; i++) {
                if (!strncmp(&rvalue[i], "pkcs11", 6)) {
                    Interact_token |= 0x01;
                    DEBUG("PKCS11 Found %d.\n",i);
                    for (int i = 0; rvalue[i] != '\0' ; i++) {
                        if (!strncmp(&rvalue[i], "token", 5)) {
                            DEBUG("Token word Found.\n");
                            Interact_token |= 0x02;
                            break;
                        }
                    }
                    break;
                }
            }
            if(!Interact_token) {
                DEBUG("Interact_token NOT enabled.\n");
                fprintf(fp_csf_file, "\tFile = \"%s/crts/%s\"\n", g_sig_data_path, rvalue);
            }
            else if(Interact_token & 0x02) {    
                DEBUG("Token defined.\n");
                fprintf(fp_csf_file, "\tFile = \"%s\"\n", rvalue);
            }
            else if(Interact_token & 0x01) {   
                fprintf(fp_csf_file, "\tFile = \"");
                for (counter = 0; rvalue[counter] != '\0' ; counter++) {
                        if (!strncmp(&rvalue[counter], "object", 6)) {
                            DEBUG("found it in %d \n",counter);
                            break;
                        }
                }

                char *tokenvalue = getenv(g_token);
                if (!tokenvalue) {
                    DEBUG("Environment variable %s is defined with value: %s\n", g_token, tokenvalue);
                    //fprintf(fp_csf_file, "pkcs11:token=%s;%s;",tokenvalue,&rvalue[counter]);
                    fprintf(fp_csf_file, "pkcs11:token=CST-HSM-DEMO;%s",&rvalue[counter]);
                } else
                    DEBUG("Token Enviroment Variable is not defined.\n");

                char *pinValue = getenv(g_user_pin);
                if (pinValue) {
                    for (int i = 0; rvalue[i] != '\0' ; i++) {
                        if (!strncmp(&rvalue[i], "pin-value", 9)) {
                            DEBUG("User PIN word Found.\n");
                            Interact_token |= 0x04;
                            break;
                        }
                    }
                    if(!(Interact_token & 0x04)){
                        DEBUG("Environment variable %s is defined with value: %s\n", g_user_pin, pinValue);
                        fprintf(fp_csf_file, "pin-value=%s",pinValue);
                    }
                } else 
                    DEBUG("Pin User is not defined.\n");
                fprintf(fp_csf_file, "\"\n");   
            }  
        }
    }

    fprintf(fp_csf_file, "[Authenticate CSF]\n");

    /* Unlock */
#define NUM_ENGINES         4
#define NUM_FEATURES        10
#define MAX_ENGINE_LEN      6  // OCOTP
#define MAX_FEATURE_LEN     13 // FIELD RETURN

    char *key = NULL;
    int i = 0;
    char engines[NUM_ENGINES][MAX_ENGINE_LEN] = { };
    char features[NUM_FEATURES][MAX_FEATURE_LEN] = { };
    char uid[100] = { };
    /* Engines */
    cfg_parser(fp_cfg, rvalue, RSIZE, "unlock_engine");
    if ('\0' != rvalue[0]) {
        for (key = strtok(rvalue, ","); key != NULL; key = strtok(NULL, ",")) {
            strncpy((char *)engines[i++], key, MAX_ENGINE_LEN - 1);
        }

        key = NULL;
        i = 0;
        /* Features */
        cfg_parser(fp_cfg, rvalue, RSIZE, "unlock_features");
        if ('\0' != rvalue[0]) {
            for (key = strtok(rvalue, ","); key != NULL; key = strtok(NULL, ",")) {
                strncpy((char *)features[i++], key, MAX_FEATURE_LEN - 1);
            }
        }
        /* UID */
        cfg_parser(fp_cfg, rvalue, RSIZE, "unlock_uid");
        if ('\0' != rvalue[0])
            strncpy(uid, rvalue, sizeof(uid)/sizeof(uid[0]));

    }


#define PRINT_UNLOCK_CMD  do { \
                            fprintf(fp_csf_file, "[Unlock]\n"); \
                            fprintf(fp_csf_file, "\tEngine = %s\n", engines[i]); \
                            fprintf(fp_csf_file, "\tFeatures = %s\n", features[j]); \
                          } while(0)

    /* Parse engines and features*/
    if (strlen(engines[0]) && strlen(features[0])) {
        for (int i = 0; i < NUM_ENGINES; i++) {
            if (!strncmp(engines[i], "SRTC", 4)) {
                fprintf(fp_csf_file, "[Unlock]\n");
                fprintf(fp_csf_file, "\tEngine = %s\n", engines[i]);
                continue;
            } else if (!strncmp(engines[i], "CAAM", 4)) {
                for (int j = 0; j < NUM_FEATURES; j++) {
                    if (!strncmp(features[j], "MID", 3) || \
                        !strncmp(features[j], "RNG", 3) || \
                        !strncmp(features[j], "MFG", 3)) {
                        PRINT_UNLOCK_CMD;
                    }
                }
            } else if (!strncmp(engines[i], "SNVS", 4)) {
                for (int j = 0; j < NUM_FEATURES; j++) {
                    if (!strncmp(features[j], "LP SWR", 6) || \
                        !strncmp(features[j], "ZMK WRITE", 9)) {
                        PRINT_UNLOCK_CMD;
                    }
                }
            } else if (!strncmp(engines[i], "OCOTP", 5)) {
                for (int j = 0; j < NUM_FEATURES; j++) {
                    if ((!strncmp(features[j], "FIELD RETURN", 12) || \
                         !strncmp(features[j], "SCS", 3) || \
                         !strncmp(features[j], "JTAG", 4)) \
                      && strlen(uid) > 0) {
                        PRINT_UNLOCK_CMD;
                        fprintf(fp_csf_file, "\tUID = %s\n", uid);
                    } else if (!strncmp(features[j], "SRK REVOKE", 10)) {
                        PRINT_UNLOCK_CMD;
                    }
                }
            }
        }
    }

    /* Choose between fast authentication and normal authentication */
    if (!fast_auth) {
        /* Install Key */
        fprintf(fp_csf_file, "[Install Key]\n");
        cfg_parser(fp_cfg, rvalue, RSIZE, "img_verification_index");
        if ('\0' == rvalue[0])
            fprintf(fp_csf_file, "\tVerification index = 0\n");
        else
            fprintf(fp_csf_file, "\tVerification index = %s\n", rvalue);

        cfg_parser(fp_cfg, rvalue, RSIZE, "img_target_index");
        if ('\0' == rvalue[0])
            fprintf(fp_csf_file, "\tTarget index = 0\n");
        else
            fprintf(fp_csf_file, "\tTarget index = %s\n", rvalue);

        cfg_parser(fp_cfg, rvalue, RSIZE, "img_file");
        if ('\0' == rvalue[0])
            fprintf(fp_csf_file, "\tFile = \"%s/crts/IMG1_1_sha256_2048_65537_v3_usr_crt.pem\"\n", g_sig_tool_path);
        else{
            DEBUG("The string is %s.\n",rvalue);
            uint8_t Interact_token = 0;
            uint8_t counter = 0;
            for (int i = 0; rvalue[i] != '\0' ; i++) {
                if (!strncmp(&rvalue[i], "pkcs11", 6)) {
                    Interact_token |= 0x01;
                    DEBUG("PKCS11 Found %d.\n",i);
                    for (int i = 0; rvalue[i] != '\0' ; i++) {
                        if (!strncmp(&rvalue[i], "token", 5)) {
                            DEBUG("Token word Found.\n");
                            Interact_token |= 0x02;
                            break;
                        }
                    }
                    break;
                }
            }
            if(!Interact_token) {
                DEBUG("Interact_token NOT enabled.\n");
                fprintf(fp_csf_file, "\tFile = \"%s/crts/%s\"\n", g_sig_data_path, rvalue);
            }
            else if(Interact_token & 0x02) {    
                DEBUG("Token defined.\n");
                fprintf(fp_csf_file, "\tFile = \"%s\"\n", rvalue);
            }
            else if(Interact_token & 0x01) {   
                fprintf(fp_csf_file, "\tFile = \"");
                for (counter = 0; rvalue[counter] != '\0' ; counter++) {
                        if (!strncmp(&rvalue[counter], "object", 6)) {
                            DEBUG("found it in %d \n",counter);
                            break;
                        }
                }
                char *tokenvalue = getenv(g_token);
                if (!tokenvalue) {
                    DEBUG("Environment variable %s is defined with value: %s\n", g_token, tokenvalue);
                    //fprintf(fp_csf_file, "pkcs11:token=%s;%s;",tokenvalue,&rvalue[counter]);
                    fprintf(fp_csf_file, "pkcs11:token=CST-HSM-DEMO;%s;",&rvalue[counter]);
                }
                else
                    DEBUG("Token Enviroment Variable is not defined.\n");

                char *pinValue = getenv(g_user_pin);
                if (pinValue) {
                    for (int i = 0; rvalue[i] != '\0' ; i++) {
                        if (!strncmp(&rvalue[i], "pin-value", 9)) {
                            DEBUG("User PIN word Found.\n");
                            Interact_token |= 0x04;
                            break;
                        }
                    }
                    if(!(Interact_token & 0x04)){
                        DEBUG("Environment variable %s is defined with value: %s\n", g_user_pin, pinValue);
                        fprintf(fp_csf_file, "pin-value=%s",pinValue);
                    }
                } else 
                    DEBUG("Pin User is not defined.\n");

                fprintf(fp_csf_file, "\"\n");   
            }  
        }
    }

    /* Authenticate Data */
    fprintf(fp_csf_file, "[Authenticate Data]\n");

    /* Choose between fast authentication and normal authentication */
    if (!fast_auth) {
        cfg_parser(fp_cfg, rvalue, RSIZE, "auth_verification_index");
        if ('\0' == rvalue[0])
            fprintf(fp_csf_file, "\tVerification index = 2\n");
        else
            fprintf(fp_csf_file, "\tVerification index = %s\n", rvalue);
    } else {
        fprintf(fp_csf_file, "\tVerification index = 0\n");
    }

    fprintf(fp_csf_file, "\tBlocks = ");

    for (int cnt = 0; cnt < NUM_IMGS; cnt++) {
        if (!blocks[cnt].valid)
            continue;

        if (cnt) {
                fprintf(fp_csf_file, "\t         ");
        }

        fprintf(fp_csf_file, "0x%08lX 0x%08lX 0x%08lX \"%s\"",
                blocks[cnt].load_addr,
                blocks[cnt].offset,
                blocks[cnt].size, ofname);

            if (cnt != (NUM_IMGS - 1) && blocks[cnt + 1].valid)
                fprintf(fp_csf_file, ", \\");

            fprintf(fp_csf_file, "\n");
    }


    printf("INFO: %s generated\n", csf_filename);

    FCLOSE(fp_csf_file);
    FCLOSE(fp_cfg);
    return E_OK;
}


/*
 * @brief       Create CSF file for IVT type v3
 *
 * @param[in]   csf_filename    : CSF filename to be populated
 *              ifname          : Input filename
 *              csf_param       : CSF parameters config file
 *
 * @retval     -E_FAILURE       : Failure
 *              E_OK            : Success
 */
static int create_csf_file_v3(char *csf_filename, char *ifname, csf_params_t *csf_param)
{
    ASSERT(csf_filename, -1);
    ASSERT(ifname, -1);
    ASSERT(csf_param, -1);

    char rvalue[RSIZE] = {0};

    /* Create CSF file with CSF parameters */
    FILE *fp_csf_file = fopen(csf_filename, "w");
    if (NULL == fp_csf_file ) {
        fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", csf_filename, strerror(errno));
        return -E_FAILURE;
    }

    /* Open CSF config file */
    FILE *fp_cfg = fopen(g_cfgfilename, "r");
    if (NULL == fp_cfg) {
        fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", g_cfgfilename, strerror(errno));
        FCLOSE(fp_csf_file);
        return -E_FAILURE;
    }

    /* Populate CSF file with appropriate parameters */
    /* Header */
    fprintf(fp_csf_file, "[Header]\n");

    fprintf(fp_csf_file, "\tTarget = AHAB\n");

    cfg_parser(fp_cfg, rvalue, RSIZE,"header_version");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tVersion = 1.0\n");
    else
        fprintf(fp_csf_file, "\tVersion = %s\n", rvalue);

    /* Install SRK */
    fprintf(fp_csf_file, "[Install SRK]\n");

    cfg_parser(fp_cfg, rvalue, RSIZE, "srktable_file");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tFile = \"%s/crts/SRK_1_2_3_4_table.bin\"\n", g_sig_tool_path);
    else
        fprintf(fp_csf_file, "\tFile = \"%s/crts/%s\"\n", g_sig_tool_path, rvalue);

    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_source");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tSource = \"%s/crts/SRK1_sha256_prime256v1_v3_ca_crt.pem\"\n", g_sig_tool_path);
    else
        fprintf(fp_csf_file, "\tSource = \"%s/crts/%s\"\n", g_sig_data_path, rvalue);

    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_source_index");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tSource index = 0\n");
    else
        fprintf(fp_csf_file, "\tSource index = %s\n", rvalue);

    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_source_set");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tSource set = OEM\n");
    else
        fprintf(fp_csf_file, "\tSource set = %s\n", rvalue);

    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_revocations");
    if ('\0' == rvalue[0])
        fprintf(fp_csf_file, "\tRevocations = 0x0\n");
    else
        fprintf(fp_csf_file, "\tRevocations = %s\n", rvalue);

    /* Install SGK */
    /* Add SGK info only if its value is populated in config file */
    cfg_parser(fp_cfg, rvalue, RSIZE, "sgk_file");
    if ('\0' != rvalue[0]) {
        fprintf(fp_csf_file, "[Install Certificate]\n");

        fprintf(fp_csf_file, "\tFile = \"%s/crts/%s\"\n", g_sig_tool_path, rvalue);

        cfg_parser(fp_cfg, rvalue, RSIZE, "sgk_permissions");
        if ('\0' == rvalue[0])
            fprintf(fp_csf_file, "\tPermissions = 0x1\n");
        else
            fprintf(fp_csf_file, "\tPermissions = %s\n", rvalue);
    }

    /* Authenticate Data */
    fprintf(fp_csf_file, "[Authenticate Data]\n");

    fprintf(fp_csf_file, "\tFile = \"%s\"\n", ifname);

    fprintf(fp_csf_file, "\tOffsets = 0x%08X\t0x%08X\n", csf_param->cntr_offset,
    csf_param->sig_offset);

    /* DONE */

    printf("INFO: %s generated\n", csf_filename);

    FCLOSE(fp_csf_file);
    FCLOSE(fp_cfg);
    return E_OK;
}

/*
 * @brief       Create YAML config file for IVT type v3
 *
 * @param[in]   yaml_filename   : YAML config filename to be populated
 *
 * @retval     -E_FAILURE       : Failure
 *              E_OK            : Success
 */
static int create_spsdk_yaml_file(char *yaml_filename)
{
    ASSERT(yaml_filename, -1);

    char rvalue[RSIZE] = {0};

    /* Create YAML file with config parameters */
    FILE *fp_yaml_file = fopen(yaml_filename, "w");
    if (NULL == fp_yaml_file ) {
        fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", yaml_filename, strerror(errno));
        return -E_FAILURE;
    }

    /* Open nxpimage config file */
    FILE *fp_cfg = fopen(g_cfgfilename, "r");
    if (NULL == fp_cfg) {
        fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", g_cfgfilename, strerror(errno));
        FCLOSE(fp_yaml_file);
        return -E_FAILURE;
    }

    /* Populate YAML config file with appropriate parameters */

    /* SoC Family */
    cfg_parser(fp_cfg, rvalue, RSIZE, "family");
    if ('\0' == rvalue[0])
        fprintf(fp_yaml_file, "family: mimx9352\n");
    else
        fprintf(fp_yaml_file, "family: %s\n", rvalue);

    /* SRK Set (NXP/OEM) */
    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_set");
    if ('\0' == rvalue[0])
        fprintf(fp_yaml_file, "srk_set: oem\n");
    else
        fprintf(fp_yaml_file, "srk_set: %s\n", rvalue);

    /* Used SRK ID */
    cfg_parser(fp_cfg, rvalue, RSIZE, "used_srk_id");
    if ('\0' == rvalue[0])
        fprintf(fp_yaml_file, "used_srk_id: 0\n");
    else
        fprintf(fp_yaml_file, "used_srk_id: %s\n", rvalue);

    /* SRK revoke mask */
    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_revoke_mask");
    if ('\0' == rvalue[0])
        fprintf(fp_yaml_file, "srk_revoke_mask: '0x00'\n");
    else
        fprintf(fp_yaml_file, "srk_revoke_mask: '%s'\n", rvalue);

    /* GDET configuration */
    cfg_parser(fp_cfg, rvalue, RSIZE, "gdet_runtime_behavior");
    if ('\0' == rvalue[0])
        fprintf(fp_yaml_file, "gdet_runtime_behavior: disabled\n");
    else
        fprintf(fp_yaml_file, "gdet_runtime_behavior: %s\n", rvalue);

    /* Fuse Version */
    cfg_parser(fp_cfg, rvalue, RSIZE, "fuse_version");
    if ('\0' == rvalue[0])
        fprintf(fp_yaml_file, "fuse_version: 0\n");
    else
        fprintf(fp_yaml_file, "fuse_version: %s\n", rvalue);

    /* Sofware Version */
    cfg_parser(fp_cfg, rvalue, RSIZE, "sw_version");
    if ('\0' == rvalue[0])
        fprintf(fp_yaml_file, "sw_version: 0\n");
    else
        fprintf(fp_yaml_file, "sw_version: %s\n", rvalue);

    /* Signature Provider to send password as a file along with the priv key */
    cfg_parser(fp_cfg, rvalue, RSIZE, "signature_provider");
    if ('\0' == rvalue[0])
        fprintf(fp_yaml_file, "signature_provider: type=file;file_path=%s/keys/SRK1_sha256_prime256v1_v3_ca_key.pem;password=%s/keys/key_pass.txt\n", g_sig_tool_path, g_sig_tool_path);
    else
        fprintf(fp_yaml_file, "signature_provider: type=file;file_path=%s/keys/%s;password=%s/keys/key_pass.txt\n", g_sig_data_path, rvalue, g_sig_data_path);

    /* SRK Table */
    fprintf(fp_yaml_file, "srk_table:\n");
    cfg_parser(fp_cfg, rvalue, RSIZE, "flag_ca");
    if ('\0' == rvalue[0])
        fprintf(fp_yaml_file, "  flag_ca: true\n");
    else
        fprintf(fp_yaml_file, "  flag_ca: %s\n", rvalue);

    /* SRK Array to build SRK Table */
    fprintf(fp_yaml_file, "  srk_array:\n");
    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_array_0");
    if ('\0' == rvalue[0])
        fprintf(fp_yaml_file, "    - %s/crts/SRK1_sha256_prime256v1_v3_ca_crt.pem\n", g_sig_tool_path);
    else
        fprintf(fp_yaml_file, "    - %s/crts/%s\n", g_sig_data_path, rvalue);

    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_array_1");
    if ('\0' == rvalue[0])
        fprintf(fp_yaml_file, "    - %s/crts/SRK2_sha256_prime256v1_v3_ca_crt.pem\n", g_sig_tool_path);
    else
        fprintf(fp_yaml_file, "    - %s/crts/%s\n", g_sig_data_path, rvalue);

    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_array_2");
    if ('\0' == rvalue[0])
        fprintf(fp_yaml_file, "    - %s/crts/SRK3_sha256_prime256v1_v3_ca_crt.pem\n", g_sig_tool_path);
    else
        fprintf(fp_yaml_file, "    - %s/crts/%s\n", g_sig_data_path, rvalue);

    cfg_parser(fp_cfg, rvalue, RSIZE, "srk_array_3");
    if ('\0' == rvalue[0])
        fprintf(fp_yaml_file, "    - %s/crts/SRK4_sha256_prime256v1_v3_ca_crt.pem\n", g_sig_tool_path);
    else
        fprintf(fp_yaml_file, "    - %s/crts/%s\n", g_sig_data_path, rvalue);

    /* DONE */

    printf("INFO: %s generated\n", yaml_filename);

    FCLOSE(fp_yaml_file);
    FCLOSE(fp_cfg);
    return E_OK;
}

/*
 * @brief       Sign image of IVT type v3
 *
 * @param[in]   ifname_full : Input filename
 * @param[out]  ofname      : Ouput filename
 *
 * @retval       E_OK           : Success
 *              -E_FAILURE      : Failure
 */
static int sign_container_spsdk(char *ifname_full, char *ofname)
{

    char *yaml_config_filename = NULL;
    yaml_config_filename = calloc(FILENAME_MAX_LEN, sizeof(char));
    if (NULL == yaml_config_filename) {
        fprintf(stderr, "ERROR: Error allocating memory; %s\n", strerror(errno));
        goto err;
    }

    /* Prepare YAML config filename */
    if (0 > (snprintf(yaml_config_filename, FILENAME_MAX_LEN, "nxpimage_config.yaml"))) {
        fprintf(stderr, "ERROR: YAML filename build unsuccessful. Exiting.\n");
        goto err;
    }

    DEBUG("nxpimage YAML config filename = %s\n", yaml_config_filename);

    /* Create YAML config file */
    if (create_spsdk_yaml_file(yaml_config_filename)) {
        fprintf(stderr, "ERROR: Failed to create YAML config file properly: %s\n", yaml_config_filename);
        goto err;
    }

    DEBUG("nxpimage YAML config filename created = %s\n", yaml_config_filename);

    if (sign_yaml_config(yaml_config_filename, ifname_full, ofname)) {
        fprintf(stderr, "ERROR: Failed to sign the image using: %s\n", yaml_config_filename);
        goto err;
    }

    FREE(yaml_config_filename);

    return E_OK;

err:
    FREE(yaml_config_filename);
    return -E_FAILURE;
}

/*
 * @brief       Sign image of IVT type v3
 *
 * @param[in]   infile_buf  : Input file buffer
 *              infile_size : Input file size
 *              ifname_full : Input filename
 * @param[out]  ofname      : Ouput filename
 *
 * @retval       E_OK           : Success
 *              -E_FAILURE      : Failure
 */
static int sign_container(const uint8_t *infile_buf, long int infile_size, char *ifname_full, char *ofname)
{
    ASSERT(infile_buf, -1);
    ASSERT(ifname_full, -1);
    ASSERT(ofname, -1);

    int cntr_num = 0; /* number of containers in binary */
    uint32_t file_off = 0; /* offset within container binary */
    uint32_t img_array_size = 0; /* number of images in container */
    flash_header_v3_t container_headers[MAX_NUM_OF_CONTAINER];
    flash_header_v3_t app_container_header;
    int app_cntr_off;
    
    csf_params_t csf_param[MAX_NUM_OF_CONTAINER] = {0};
    
    /* initialize region of memory where flash header will be stored */
    memset((void *)container_headers, 0, sizeof(container_headers));
    
    while (cntr_num < MAX_NUM_OF_CONTAINER && \
           ((file_off + g_image_offset) < infile_size)) {

        /* read in next container header up to the image array */
        memcpy((void *)&container_headers[cntr_num], \
                (file_off + g_image_offset + infile_buf), \
                16);
    
        /* check that the current container has a valid tag */
        if (container_headers[cntr_num].tag != IVT_HEADER_TAG_B0 && \
            container_headers[cntr_num].tag != IVT_HEADER_TAG_MSG)
            break;

        /* Validate number of images */
        if (container_headers[cntr_num].num_images > MAX_NUM_IMGS) {
            fprintf(stderr, "ERROR: This container includes %d images, beyond max %d images\n", container_headers[cntr_num].num_images, MAX_NUM_IMGS);
            break;
        /* Message container does not have images */
        } else if (container_headers[cntr_num].tag == IVT_HEADER_TAG_MSG && \
                   0 != container_headers[cntr_num].num_images) {
            fprintf(stderr, "ERROR: Messages cannot contain images\n");
            break;
        }
        
        /* compute the size of the image array */
        img_array_size = container_headers[cntr_num].num_images * sizeof(boot_img_t);
        if (img_array_size) {
            /* read in the full image array */
            memcpy((void *)&container_headers[cntr_num].img, \
                &((flash_header_v3_t *)(file_off + g_image_offset + infile_buf))->img, \
                img_array_size);
    
            /* determine the type of image */
            boot_img_t img = container_headers[cntr_num].img[0];
            img_flags_t img_flags;
            img_flags.type = img.hab_flags & IMAGE_TYPE_MASK;
            DEBUG("Image Flag type: 0x%X\n", img_flags.type);

            /* If container contains signed images provided by NXP like SECO/SENTINEL/V2X, then no need to sign this container. Skip to next one. */
            if (img_flags.type == 0x6 || \
                img_flags.type == 0xB || \
                img_flags.type == 0xC) {
                DEBUG("Container %d already signed\n", cntr_num);
                /* calculate next container offset in binary */
                file_off += ALIGN(container_headers[cntr_num].length, CONTAINER_ALIGNMENT);
                DEBUG("file_off = 0x%08X\n", file_off);

                /* increment current container count */
                cntr_num++;
                continue;
            }
        }

        /* Fill CSF parameters */
        csf_param[cntr_num].cntr_num = cntr_num + 1;
        csf_param[cntr_num].cntr_offset = file_off + g_image_offset;
        csf_param[cntr_num].sig_offset = csf_param[cntr_num].cntr_offset + container_headers[cntr_num].sig_blk_offset;

        /* calculate next container offset in binary */
        file_off += ALIGN(container_headers[cntr_num].length, CONTAINER_ALIGNMENT);
        DEBUG("file_off = 0x%08X\n", file_off);

        /* increment current container count */
        cntr_num++;
    }

    app_cntr_off = search_app_container(container_headers, cntr_num, &app_container_header, infile_buf, infile_size);
    
    if(0 < app_cntr_off) {
        DEBUG("APP container offset = 0x%08X\n", app_cntr_off);
        DEBUG("APP container signature offset = 0x%08X\n", app_cntr_off +  app_container_header.sig_blk_offset);
    
        /* Fill CSF parameters with APP container parameters */
        csf_param[cntr_num].cntr_num = cntr_num + 1;
        csf_param[cntr_num].cntr_offset = app_cntr_off;
        csf_param[cntr_num].sig_offset = csf_param[cntr_num].cntr_offset + app_container_header.sig_blk_offset;
    } else {
        /* Reduce the total containers by 1 if no APP container is found */
        cntr_num--;
    }

    for(int i=0; i<MAX_NUM_OF_CONTAINER; i++) {
        DEBUG("CSF Container:\t Container Number : %d\n", csf_param[i].cntr_num);
        DEBUG("Container Offset : 0x%08X\n", csf_param[i].cntr_offset);
        DEBUG("Signature Offset : 0x%08X\n", csf_param[i].sig_offset);
    }


    /* TODO: Signing logic would be simpler when multiple blocks can be signed in the same CSF file */
    char *csf_filename = NULL;
    char *itemp_fname = "itemp.bin";
    char *otemp_fname = "otemp.bin";

    /* Copy file to be signed to a temporary file */
    if(copy_files(ifname_full, itemp_fname)) {
        fprintf(stderr, "ERROR: Failed to copy files: %s and %s\n", ifname_full, itemp_fname);
        return -E_FAILURE;
    }
    
    /* Create CSF files & sign them */
    for (int i = 0; i <= cntr_num; i++) {
        /* Skip creating CSF for NXP signed images */
        if (0 == csf_param[i].cntr_offset && 0 == csf_param[i].sig_offset)
            continue;

        csf_filename = calloc(FILENAME_MAX_LEN, sizeof(char));
        if (NULL == csf_filename) {
            fprintf(stderr, "ERROR: Error allocating memory; %s\n", strerror(errno));
            goto err;
        }

        /* Prepare CSF filename */
        if (0 > (snprintf(csf_filename, FILENAME_MAX_LEN, "container_%d.csf", i + 1))) {
            fprintf(stderr, "ERROR: CSF filename build unsuccessful. Exiting.\n");
            goto err;
        }

        DEBUG("CSF filename = %s\n", csf_filename);

        /* Create CSF file with input filename */
        if (create_csf_file_v3(csf_filename, itemp_fname, &csf_param[i])) {
            fprintf(stderr, "ERROR: Failed to create CSF file properly: %s\n", csf_filename);
            goto err;
        }
        DEBUG("CSF filename created = %s\n", csf_filename);
                
        if (i != cntr_num) {
            /* Sign into a temp output file */
            if (sign_csf(csf_filename, otemp_fname)) {
                fprintf(stderr, "ERROR: Failed to sign the image using: %s\n", csf_filename);
                goto err;
            }
            /* Remove input temp file */
            if (remove(itemp_fname)) {
                fprintf(stderr, "ERROR: Couldn't remove file: %s; %s\n", itemp_fname, strerror(errno));
                goto err;
            }
            /* Rename output temp file to input temp file to be signed again */
            if (rename(otemp_fname, itemp_fname)) {
                fprintf(stderr, "ERROR: Couldn't rename file: %s to %s; %s\n", otemp_fname, itemp_fname, strerror(errno));
                goto err;
            }
        } else {
            /* If last container is being signed then create final signed image */
            if (sign_csf(csf_filename, ofname)) {
                fprintf(stderr, "ERROR: Failed to sign the image using: %s\n", csf_filename);
                goto err;
            }
            /* Remove input temporary file */
            if (remove(itemp_fname)) {
                fprintf(stderr, "ERROR: Couldn't remove file: %s; %s\n", itemp_fname, strerror(errno));
                goto err;
            }
        }
        
        FREE(csf_filename);
    }

    return E_OK;

err:
    FREE(csf_filename);
    return -E_FAILURE;
}

/*
 * @brief       This function reads the inputs file and returns size
 *
 * @param[in]   fp         - Input file pointer
 *              input_file - Input file name
 *
 * @retval      Return file size
 */
long int get_file_size(FILE *fp, char *input_file)
{
    int ret = -1;

    if (NULL == input_file) {
        fprintf(stderr, "ERROR: Invalid file: %s\n", input_file);
        return -E_FAILURE;
    }

    /* Open file */
    fp = fopen(input_file, "rb");
    if (NULL == fp) {
        fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", input_file, strerror(errno));
        return -E_FAILURE;
    }
    
    /* Seek to the end of file to calculate size */
    if (fseek(fp , 0 , SEEK_END)) {
        errno = ENOENT; 
        fprintf(stderr, "ERROR: Couldn't seek to end of file: %s; %s\n", input_file, strerror(errno));
        FCLOSE(fp);
        return -E_FAILURE;
    }

    /* Get size and go back to start of the file */
    ret = ftell(fp);
    rewind(fp);

    FCLOSE(fp);
    
    return ret;
}

/*
 * @brief       This function allocates buffer with size from input file
 *
 * @param[in]   fp         - Input file pointer
 *              input_file - Input file name
 *
 * @retval      return buffer pointer
 */
unsigned char *alloc_buffer(FILE *fp, char *input_file)
{
    long int file_size = 0;
    unsigned char *buf = NULL;

    file_size = get_file_size(fp, input_file);
    if (0 > file_size) {
        fprintf(stderr, "ERROR: Invalid file size %ld of file: %s\n", file_size, input_file);
        return NULL;
    }
    
    /* Open file */
    fp = fopen(input_file, "rb");
    if (NULL == fp) {
        fprintf(stderr, "ERROR: Couldn't open file: %s; %s\n", input_file, strerror(errno));
        return NULL;
    }
    
    /* Allocate memory to the buffer */
    buf = malloc(file_size);
    if (NULL == buf || 0 == buf) {
        fprintf(stderr, "ERROR: Error allocating memory; %s\n", strerror(errno));
        FCLOSE(fp);
        return NULL;
    }

    /* Copy the file into the buffer */
    size_t result = fread(buf, 1, file_size, fp);
    if (result != file_size) {
        fprintf(stderr, "ERROR: File read error; %s\n", strerror(errno));
        FCLOSE(fp);
        FREE(buf);
        return NULL;
    }
    FCLOSE(fp);

    return buf;
}

/*
 * @brief      Insert CSF data from ifile1 into ifile2 starting at offset
 *
 * @param[in]   ifile1     : Input file that contains the Command Sequence File
 *              offset     : Offset of the CSF in ifile2
 *
 * @param[out]  ifile2     : Output file that contains the flash image.
 *
 * @retval     -E_FAILURE  : Failure
 *              E_OK       : Success
 */
static int insert_csf(char *ifile1, char *ifile2, uint32_t offset)
{
    FILE *fp1 = NULL;
    FILE *fp2 = NULL;
    long int ifile1_size, result_size;
    unsigned char *buf = NULL;

    ifile1_size = get_file_size(fp1, ifile1);
    if (0 > ifile1_size) {
        fprintf(stderr, "ERROR: Invalid file size %ld of file: %s\n", ifile1_size, ifile1);
        goto err;
    }

    /* Allocate memory to the buffer */
    buf = malloc(ifile1_size);
    if (NULL == buf || 0 == buf) {
        fprintf(stderr, "ERROR: Error allocating memory; %s\n", strerror(errno));
        goto err;
    }

    fp1 = fopen(ifile1, "rb");
    fp2 = fopen(ifile2, "r+b");

    if (NULL == fp1 || NULL == fp2) {
        fprintf(stderr, "ERROR: Couldn't open one of the files : %s or %s %s\n",
                ifile1, ifile2, strerror(errno));
       goto err;
    }

    result_size = fread(buf, 1, ifile1_size, fp1);
    /* Copy input file to output file */
    if (result_size != ifile1_size) {
        fprintf(stderr, "ERROR: File read error; %s\n", strerror(errno));
        goto err;
    }


    if (fseek (fp2, offset, SEEK_SET)) {
        fprintf(stderr, "ERROR: Cannot set pointer to %x offset; %s\n",offset, strerror(errno));
        goto err;
    }

    result_size = fwrite(buf, 1, ifile1_size, fp2);
    if (result_size != ifile1_size) {
        fprintf(stderr, "ERROR: File write error; %s\n", strerror(errno));
        goto err;
    }

    FCLOSE(fp1);
    FCLOSE(fp2);
    FREE(buf);
    return E_OK;

err:
    FCLOSE(fp1);
    FCLOSE(fp2);
    FREE(buf);
    return -E_FAILURE;
}



/*
 * @brief      Concatenate two files and put the result in the first file
 *
 * @param[in]   ifile1     : Input file1
 *              ifile2     : Input file2
 *
 * @retval     -E_FAILURE  : Failure
 *              E_OK       : Success
 */
int concat_files(char *ifname1, char *ifname2)
{
    char tmp_file[100UL] = {0};
    FILE *fp1 = NULL;
    FILE *fp2 = NULL;
    FILE *fp3 = NULL;
    unsigned char *buf = NULL;
    long int ifile1_size, ifile2_size, result_size;

    if (0 > (snprintf(tmp_file, sizeof(tmp_file), "temp.bin"))) {
        fprintf(stderr, "ERROR: Cannot populate temp file name.\n");
        return -E_FAILURE;
    }

    ifile1_size = get_file_size(fp1, ifname1);

    if (0 > ifile1_size) {
        fprintf(stderr, "ERROR: Invalid file size %ld of file: %s\n", ifile1_size, ifname1);
        goto err;
    }

    ifile2_size = get_file_size(fp2, ifname2);
    if (0 > ifile2_size) {
        fprintf(stderr, "ERROR: Invalid file size %ld of file: %s\n", ifile2_size, ifname2);
        goto err;
    }

    if (ifile1_size + ifile2_size >= UINT_MAX) {
        fprintf(stderr, "ERROR: Files too large\n");
        goto err;
    }

    /* Allocate memory to the buffer */
    buf = malloc(ifile1_size);
    if (NULL == buf || 0 == buf) {
        fprintf(stderr, "ERROR: Error allocating memory; %s\n", strerror(errno));
        goto err;
    }

    fp1 = fopen(ifname1, "rb");
    fp2 = fopen(ifname2, "rb");
    fp3 = fopen(tmp_file, "wb");

    if (NULL == fp1 || NULL == fp2 || NULL == fp3) {
        fprintf(stderr, "ERROR: Couldn't open one of the files : %s or %s or %s %s\n",
                ifname1, ifname2, tmp_file, strerror(errno));
       goto err;
    }

    result_size = fread(buf, 1, ifile1_size, fp1);
    /* Copy input file to output file */
    if (result_size != ifile1_size) {
        fprintf(stderr, "ERROR: File read error; %s\n", strerror(errno));
        goto err;
    } else {
        result_size = fwrite(buf, 1, ifile1_size, fp3);
        if (result_size != ifile1_size) {
            fprintf(stderr, "ERROR: File write error; %s\n", strerror(errno));
            goto err;
        }
    }

    FREE(buf);
    /* Allocate memory to the buffer */
    buf = malloc(ifile2_size);
    if (NULL == buf || 0 == buf) {
        fprintf(stderr, "ERROR: Error allocating memory; %s\n", strerror(errno));
        goto err;
    }

    result_size = fread(buf, 1, ifile2_size, fp2);
    /* Copy input file to output file */
    if (result_size != ifile2_size) {
        fprintf(stderr, "ERROR: File read error; %s\n", strerror(errno));
        goto err;
    } else {
        result_size = fwrite(buf, 1, ifile2_size, fp3);
        if (result_size != ifile2_size) {
        fprintf(stderr, "ERROR: File write error; %s\n", strerror(errno));
        goto err;
        }
    }

    FCLOSE(fp1);
    FCLOSE(fp2);
    FCLOSE(fp3);
    FREE(buf);

    /* Remove input temp file */
    if (remove(ifname1)) {
        fprintf(stderr, "ERROR: Couldn't remove file: %s; %s\n", ifname1, strerror(errno));
        goto err;
    }

    /* Rename output temp file to input temp file to be signed again */
    if (rename(tmp_file, ifname1)) {
        fprintf(stderr, "ERROR: Couldn't rename file: %s to %s; %s\n",
                tmp_file, ifname1, strerror(errno));
        goto err;
    }

    return E_OK;
err:
    FCLOSE(fp1);
    FCLOSE(fp2);
    FCLOSE(fp3);
    FREE(buf);
    return -E_FAILURE;
}

/*
 * @brief      Generate CSF file
 *
 * @param[in]   idx        : CSF file has a standard naming csf_image%d.bin
 *                           idx represents the index of the CSF file and will
 *                           be appended in the name
 * @param[out]  csf_file   : The name of the generated CSF file
 *
 * @retval     -E_FAILURE  : Failure
 *              E_OK       : Success
 */
static int generate_csf_v1(int idx, char *csf_file)
{
    char csf_ifilename[100UL] = {0};
    char csf_ofilename[100UL] = {0};

    if (0 > (snprintf(csf_ifilename, sizeof(csf_ifilename), "csf_image%d.txt", idx))) {
        fprintf(stderr, "ERROR: Cannot populate CSF file name.\n");
        goto err;
    }

    if (0 > (snprintf(csf_ofilename, sizeof(csf_ifilename), "csf_image%d.bin", idx))) {
        fprintf(stderr, "ERROR: Cannot populate CSF file name.\n");
        goto err;
    }

    if (access(csf_ifilename, F_OK)) {
        fprintf(stderr, "ERROR: CSF txt file does not exist.\n");
        goto err;
    }

    if (sign_csf(csf_ifilename, csf_ofilename)) {
        fprintf(stderr, "ERROR: Failed to sign the image using: %s\n", csf_ifilename);
        goto err;
    }

    memcpy(csf_file, csf_ofilename, strlen(csf_ofilename));
    return E_OK;

err:
    return -E_FAILURE;
}

/*
 * @brief       Search for the first IVT in the input flash.bin image: compute addr, offset,len
 *              and write them in the CSF file. Then generate CSF binary and
 *              insert its contents in the flash.bin or append it to the flash.bin
 *
 * @param[in]   off         : IVT offset in the flash.bin
 *              infile_buf  : Input file read into memory
 *              loop        : iteration number. It will be used in the CSF source
 *                            file name. E.g csf_file0.txt if loop == 0.
 *              infile_size : size of the flash.bin given as input for signing
 *              ofname        : name of the output signed flash image. E.g signed-flash.bin
 *
 * @retval      -E_FAILURE  : Failure
 *               E_OK       : Success
 *              -ERANGE     : Exit from search loop
 *              -EAGAIN     : Skip signing and continue search loop
 */
static int process_ivt_image(unsigned long off, uint8_t *infile_buf,
                   unsigned long loop, long int infile_size,
                   char *ofname)
{
    char csf_file[100UL] = {0};
    uint32_t csf_offset = 0x0;
    ivt_t *ivt = NULL;
    int err = -E_FAILURE;
    boot_data_t *boot = NULL;

    /* Compare the entry address with self address. For kernel images
     * IVT is placed at the end of the image file. In this case the load
     * address is offset(which is image size) minus the difference between
     * self (where the ivt is ) and entry (the beginning of the image).
     * This difference in case of kernel images is 0. For other images like
     * FDT image the offset is non zero*/
    g_images[0].valid = true;
    ivt = (ivt_t *)(infile_buf + off);

    g_images[0].load_addr = (ivt->self_addr > ivt->entry)
                            ? ivt->entry
                            : ivt->self_addr;
    g_images[0].offset = (ivt->self_addr > ivt->entry)
                         ? (off - (ivt->self_addr - ivt->entry))
                         : off;
    g_images[0].size =  (ivt->self_addr > ivt->entry)
                        ? (ivt->csf_addr - ivt->entry)
                        : (ivt->csf_addr - ivt->self_addr);
    csf_offset =  (ivt->csf_addr - ivt->self_addr) + off;

    /* Check if the image is a HDMI image */
    if (ivt->boot_data) {
        boot = (boot_data_t *)(infile_buf + off +  ivt->boot_data - ivt->self_addr);
        if (boot->plugin_flag == HDMI_IMAGE_FLAG_MASK) {
            DEBUG("HDMI Image at offset %lx... skipping signing\n",
                   off +  ivt->boot_data - ivt->self_addr);
            return -EAGAIN;
        }
    }

    DEBUG("Image[%d] addr 0x%08lx\n",0, g_images[0].load_addr);
    DEBUG("Image[%d] offset  0x%08lx\n",0, g_images[0].offset);
    DEBUG("Image[%d] size 0x%08lx\n",0, g_images[0].size);
    DEBUG("Image[%d] csf_offset 0x%08x\n",0, csf_offset);

    err = create_csf_file_v1(g_images, loop, ofname);
    if (err) {
        errno = EFAULT;
        fprintf(stderr, "ERROR: Couldn't create csf txt file %s\n", strerror(EFAULT));
        return -E_FAILURE;
    }

    err = generate_csf_v1(loop, csf_file);
    if (err) {
        errno = EFAULT;
        fprintf(stderr, "ERROR: Couldn't generate csf bin file %s\n", strerror(EFAULT));
        return -E_FAILURE;
    }

    if (infile_size <= csf_offset) {/* concat csf file with original file and exit while loop*/
        DEBUG("insert CSF at the end of file, at offset  %x in file %s\n", csf_offset, ofname);
        err = concat_files(ofname, csf_file);
        if (err) {
            errno = EFAULT;
            fprintf(stderr, "ERROR: Couldn't concatenate %s with %s %s\n",
                    ofname, csf_file, strerror(EFAULT));
            return -E_FAILURE;
        }

        return -ERANGE;
    } else {
        DEBUG("insert CSF at offset %x in file %s\n", csf_offset, ofname);
        /*insert CSF after  ivt->csf_addr - ivt->self_addr */
        err = insert_csf(csf_file, ofname, csf_offset);
        if (err) {
            errno = EFAULT;
            fprintf(stderr, "ERROR: Couldn't insert CSF sequence at offset %x in file %s %s\n",
                    csf_offset, ofname, strerror(EFAULT));
            return -E_FAILURE;
        }
    }

    return err;
}

/*
 * @brief       Search for the next IVT in the input flash.bin image: compute
 *              addr, offset,len and write them in the CSF file.
 *              Then generate CSF binary and
 *              insert its contents in the flash.bin or append it to the
 *              flash.bin The IVT can be found inside a FIT image.
 *
 * @param[in]   off         : IVT offset in the flash.bin
 *              infile_buf  : Input file read into memory
 *              loop        : iteration number. It will be used in the CSF source
 *                            file name. E.g csf_file1.txt if loop == 1.
 *              infile_size : size of the flash.bin given as input for signing
 *              ofname      : name of the output signed flash image.
 *                              E.g signed-flash.bin
 *
 * @retval      -E_FAILURE  : Failure
 *               E_OK       : Success
 *              -ERANGE     : Exit from search loop
 */
static int process_fdt_images(unsigned long off, uint8_t *infile_buf,
                  unsigned long loop, long int infile_size,
                  char *ofname)
{
    fdt_header_t *fit_img = (fdt_header_t *)(infile_buf + off - 0x1000);
    uint32_t csf_offset = 0x0;
    char csf_file[100UL] = {0};
    ivt_t *ivt;
    int err = -E_FAILURE;

    if (IS_FIT_IMAGE(infile_buf, off)) {
        g_images[0].valid = true;
        ivt = (ivt_t *)(infile_buf + off);

        /* In NXP BSP the FIT image has the following structure:
         *   _____________
         *  |FDT    (FIT) |
         *  |IVT    (FIT) |
         *  |CSF    (FIT) |
         *  |Images (FIT) |
         *  |_____________|
         *
         *  - g_images[0] contains FDT
         *  - starting from (g_images + 1)  is the FIT image composed of:
         *    Image 0 (uboot@1),Image 1 (fdt@1) ,Image 2 (atf@1).
         *  - (g_images + 1) is populated by parsing the standard FIT image
         *    represented by FDT plus Images. All the information related to
         *    FIT is found  in FDT.
         *    IVT + CSF = FIT_IMAGES_OFFSET
         *    Images will start from off(IVT) + FIT_IMAGES_OFFSET.
         */
        g_images[0].load_addr = ivt->entry;
        g_images[0].offset = off - 0x1000;
        g_images[0].size =  ivt->csf_addr - ivt->entry;
        csf_offset = off + ivt->csf_addr - ivt->self_addr;

        DEBUG("Image[%d] addr 0x%08lx\n",0, g_images[0].load_addr);
        DEBUG("Image[%d] offset  0x%08lx\n",0, g_images[0].offset);
        DEBUG("Image[%d] size 0x%08lx\n",0, g_images[0].size);
        DEBUG("Image[%d] csf_offset 0x%08x\n",0, csf_offset);

        /* compute the step for searching the next IVT. The step value
         * is IVT + CSF for the FDT image. Searching will jump over the IVT + CSF
         * and eventually will find the IVT CVE fix over the rest of the FIT images
         */
        g_ivt_search_step = IVT_CSF_SIZE;
        /*
         * g_images + 1 contains all the Images from FIT:
         * Image 0 (uboot@1),Image 1 (fdt@1) ,Image 2 (atf@1)
         */
        err = parse_fdt(fit_img, &g_images[1]);
        if (err) {
            errno = EFAULT;
            fprintf(stderr, "Could not parse FIT image %s\n", strerror(EFAULT));
            return -E_FAILURE;
        }

        /* adjusting block load addresses & offsets */
        for (int idx = 1; idx < NUM_IMGS; idx++) {
            if (!g_images[idx].valid)
                continue;

            /*
             * (g_images + 1) is populated by parsing the standard FIT image
             * represented by FDT + Images. All the information related to FIT
             * is found in FDT.
             * IVT + CSF = FIT_IMAGES_OFFSET
             * Images will start from off(IVT) + FIT_IMAGES_OFFSET.
             */
            if (idx == 1) {
                g_ivt_off_cve = search_pattern(infile_buf, g_ivt_v1, infile_size,
                                sizeof(g_ivt_v1) / sizeof(g_ivt_v1[0]), ASCENDING,
                                off + HAB_IVT_SEARCH_STEP,
                                g_ivt_v1_mask, HAB_IVT_SEARCH_STEP);
                /*
                 * Because of CVE-2023-39902 FIT structure was updated to
                 *  |FDT    (FIT)               |
                 *  |IVT    (FIT-FDT)           |
                 *  |CSF    (FIT-FDT)           |
                 *  |IVT    (uboot@1 - optional)|
                 *  |CSF    (uboot@1 - optional)|
                 *  |Images (FIT)               |
                 *  |___________________________|
                 *
                 * This requires a search for the new IVT - (uboot@1) - in
                 * order to determine the offset of  Image 0 (uboot@1).
                 * In case the vulnerability is implemented the offset of
                 * Image 0 (uboot@1) equals to g_ivt_off_cve + FIT_IMAGES_OFFSET
                 * Otherwise the offset is off (first IVT offset + FIT_IMAGES_OFFSET)
                 */
                if (g_ivt_off_cve < infile_size) {
                    DEBUG("Found uboot IVT offset due to CVE fix%lx\n", g_ivt_off_cve);
                    /* offset of the first image in FIT in case of CVE vulnerability
                     * is IVT CVE offset + FIT_IMAGES_OFFSET */
                    g_images[idx].offset = g_ivt_off_cve + FIT_IMAGES_OFFSET;
                } else {
                    /* offset of the first image in FIT in case of no CVE vulnerability
                     * is IVT offset + FIT_IMAGES_OFFSET */
                    g_images[idx].offset = off + FIT_IMAGES_OFFSET;
                }
            } else {
                g_images[idx].offset = g_images[idx - 1].offset + g_images[idx - 1].size;
            }

            /* If the FIT image number idx has no address set in the FIT
             * structure,  then its load address equals with the load address of
             * the previous image plus the size of the previous image.
             * In other words image idx comes right after image idx - 1.
             */
            if (!g_images[idx].load_addr)
                g_images[idx].load_addr = g_images[idx - 1].load_addr + g_images[idx - 1].size;

            DEBUG("Image[%d] addr 0x%08lx\n",idx, g_images[idx].load_addr);
            DEBUG("Image[%d] offset 0x%08lx\n",idx, g_images[idx].offset);
            DEBUG("Image[%d] size 0x%08lx\n",idx, g_images[idx].size);
            g_last_img_idx = idx;
        }

        err = create_csf_file_v1(g_images, loop, ofname);
        if (err) {
            errno = EFAULT;
            fprintf(stderr, "ERROR: Couldn't create csf txt file %s\n", strerror(EFAULT));
            return -E_FAILURE;
        }

        err = generate_csf_v1(loop, csf_file);
        if (err) {
            errno = EFAULT;
            fprintf(stderr, "ERROR: Couldn't generate csf bin file %s\n", strerror(EFAULT));
            return -E_FAILURE;
        }

        DEBUG("insert CSF at offset %x in file %s\n", csf_offset,
              ofname);
        /*insert CSF after IVT_OFFSET + 0x20 */
        err = insert_csf(csf_file, ofname, csf_offset);
        if (err) {
            errno = EFAULT;
            fprintf(stderr, "ERROR: Couldn't insert CSF sequence at offset %x in file %s %s\n",
                    csf_offset, ofname, strerror(EFAULT));
            return -E_FAILURE;
        }
    } else {/* there is no magic number. it means we have IVT but no FIT*/
        err = process_ivt_image(off, infile_buf, loop, infile_size, ofname);
        /* Make sure to step over the last image in FIT after processing the  IVTs inside FIT.
         * A max of 2 IVTs can be present in FIT: FDT IVT and CVE IVT.
         *
         */
        g_ivt_search_step = g_images[g_last_img_idx].offset + g_images[g_last_img_idx].size - off;
        g_ivt_search_step = ALIGN(g_ivt_search_step, HAB_IVT_SEARCH_STEP);
        if (err) {
            if (err != -ERANGE && err != -EAGAIN) {
                errno = EFAULT;
                fprintf(stderr, "ERROR: Could not find IVT at offset %lx %s\n",
                        off, strerror(EFAULT));
                return -E_FAILURE;
            } else
                return err;
        }
    }
    return E_OK;
}

/*
 * @brief       Sign HAB image
 *
 * @param[in]   infile_buf  : Input file buffer
 *              infile_size : Input file size
 *
 * @retval      -E_FAILURE  : Failure
 *              -ENOENT     : Input flash image is not a valid HAB image
 *              -E_OK       : Success
 */
static int sign_hab_image(uint8_t *infile_buf, long int infile_size,
              char *ifname_full, char *ofname)
{
    unsigned long loop = 0, off = 0, pos = g_image_offset;
    bool found = false;
    int err = -E_FAILURE;

    memset(g_images, 0, NUM_IMGS * sizeof(g_images[0]));
    /* Copy file to be signed */
    if(copy_files(ifname_full, ofname)) {
        fprintf(stderr, "ERROR: Failed to copy files: %s and %s\n", ifname_full, ofname);
        goto err_;
    }

    g_ivt_search_step = HAB_IVT_SEARCH_STEP;
    do {
        if (!IS_HAB_IMAGE(infile_buf, infile_size, g_ivt_v1, g_ivt_v1_mask, off, pos)) {
            pos = off + g_ivt_search_step;
            goto next_iteration;
        }

        if (off < infile_size) {
            found = true;
            if (!loop && !IS_FIT_IMAGE(infile_buf, off)) {/* first iteration */
                err = process_ivt_image(off, infile_buf, loop, infile_size, ofname);
                /* CSF was appended to the input image */
                if (err == -ERANGE)
                    return E_OK;

                if (err == -EAGAIN) {
                    pos = off + g_ivt_search_step;
                    continue;
                }
                if (err)
                    goto err_;

                /* step over the CSF by adding  image size with CSF size*/
                g_ivt_search_step = g_images[0].size + IVT_CSF_SIZE - off;
                g_ivt_search_step = ALIGN(g_ivt_search_step, HAB_IVT_SEARCH_STEP);
            } else {
                err = process_fdt_images(off, infile_buf, loop, infile_size, ofname);
                /* CSF was appended to the input image */
                if (err == -ERANGE)
                    return E_OK;

                if (err == -EAGAIN) {
                    pos = off + g_ivt_search_step;
                    continue;
                }
                if (err)
                    goto  err_;
            }
            pos = off + g_ivt_search_step;
        }
next_iteration:
        loop++;
    } while (off < infile_size);

    if (err == -EAGAIN)
        return err;

    if (!found) {
        fprintf(stderr, "ERROR: No IVT header found. Input file is not a valid HAB image. %s\n",
                strerror(ENOENT));
        err = -ENOENT;
        goto err_;
    }

    return E_OK;
err_:
    /* in case of an error remove the copy of the input file */
    if (remove(ofname)) {
        fprintf(stderr, "ERROR: Failed to remove  %s \n", ofname);
        return -E_FAILURE;
    }

    return err;
}

/*
 * @brief       Prints the usage information for running this application
 */
static void print_usage(void)
{
    int i = 0;
    printf("IMX Signer: IMX helper tool to auto-sign image using CST/SPSDK.\n"
        "Usage: SIG_TOOL_PATH=<sig-tool-path> SIG_DATA_PATH=<sig-data-path>./cst_signer ");
    do {
        printf("-%c <%s> ", long_opt[i].val, long_opt[i].name);
        i++;
    } while (long_opt[i + 1].name != NULL);
    printf("\n");

    i = 0;
    printf("Options:\n");
    do {
        printf("\t-%c|--%s  -->  %s\n", long_opt[i].val, long_opt[i].name, desc_opt[i]);
        i++;
    } while (long_opt[i].name != NULL && desc_opt[i] != NULL);
    puts("\nNote: Only one image can be signed at once.\n");
}

/*
 * @brief       Handle each command line option
 *
 * @param[in]   argc    : Number of input arguments
 *              argv    : Input arguments
 */
static void handle_cl_opt(int argc, char **argv)
{
    int next_opt = 0;
    int n_long_opt = 1; // Includes the command itself
    int mandatory_opt = 0;
    int i = 0;

    do {
        n_long_opt++;
        if (long_opt[i].has_arg == required_argument) {
            n_long_opt++;
        }
        i++;
    } while (long_opt[i + 1].name != NULL);

    /* Start from the first command-line option */
    optind = 0;
    /* Handle command line options*/
    do {
        next_opt = getopt_long(argc, argv, short_opt, long_opt, NULL);
        switch (next_opt)
        {
        case 'i':
        case 'c':
            mandatory_opt += 1;
            break;
        /* Display usage */
        case 'h':
            print_usage();
            exit(EXIT_SUCCESS);
            break;
        case '?':
            /* Unknown character returned */
            print_usage();
            exit(EXIT_FAILURE);
            break;
        /* At the end reach here and check if mandatory options are present */
        default:
            if (mandatory_opt != 2 && next_opt == -1) {
                fprintf(stderr, "ERROR: -i & -c option is required\n");
                print_usage();
                exit(EXIT_FAILURE);
            }
            break;
        }
    } while (next_opt != -1);
     /* Check for valid arguments */
    if (argc < 2 || argc > n_long_opt) {
        printf("Error: Incorrect number of options\n");
        print_usage();
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    char *ifname = NULL;
    char *ifname_full = NULL;
    char ofname[FILENAME_MAX_LEN] = "signed-";

    FILE *fp_in = NULL;
    
    uint8_t *ibuf = NULL;
    long int ibuf_size = 0;
    
    bool ret = -E_FAILURE;
    int next_opt = 0;

    char *sig_tool_path_buf = calloc(SYS_CMD_LEN, sizeof(char));
    if (NULL == sig_tool_path_buf || 0 == sig_tool_path_buf) {
        fprintf(stderr, "ERROR: Error allocating memory; %s\n", strerror(errno));
        goto err;
    }

    /* Get SIG_TOOL_PATH environment value. getenv is cross platform compatible */
    g_sig_tool_path = getenv("SIG_TOOL_PATH");
    if(!g_sig_tool_path || g_sig_tool_path[0] == '\0'){
        fprintf(stderr, "ERROR: Environment variable \"SIG_TOOL_PATH\" is mandatory\n");
        goto err;
    }

    /* Get SIG_DATA_PATH environment value. getenv is cross platform compatible */
    g_sig_data_path = getenv("SIG_DATA_PATH");
    if(!g_sig_data_path || g_sig_data_path[0] == '\0'){
        g_sig_data_path = g_sig_tool_path;
    }

    /* Checking if processor is available */
    if (!(system(NULL))) {
        fprintf(stderr, "ERROR: Command processor is not available. Exiting.\n");
        return -E_FAILURE;
    }

    /* Handle command line options */
    handle_cl_opt(argc, argv);

    /* Start from the first command-line option */
    optind = 0;
    /* Perform actions according to command-line option */
    do {
        next_opt = getopt_long(argc, argv, short_opt, long_opt, NULL);
        switch (next_opt)
        {
            /* Input image */
            case 'i':
                ifname_full = optarg;
                ifname = basename(optarg);
                /* Report long input filename */
                if (0 >= (int)(FILENAME_MAX_LEN - strlen(ifname) - strlen(ofname) - 1)) {
                    fprintf(stderr, "ERROR: Input filename too long: %s\n", ifname);
                    goto err;
                }
                /* Prepare output filename based on input filename */
                strncat(ofname, ifname, strlen(ifname));
                break;
            /* Image offset */
            case 'o':
                g_image_offset = strtol(optarg, NULL, BASE_HEX);
                break;
            /* Input YAML config file */
            case 'c':
                g_cfgfilename = optarg;
                break;
            /* Enable debug log */
            case 'd':
                g_debug = 1;
                break;
            /* Enable debug FDT */
            case 'f':
                g_fdt_debug = 1;
                break;
            /* Display usage */
            case 'h':
                print_usage();
                exit(EXIT_SUCCESS);
                break;
            /* Invalid Option */
            default:
                break;
        }
    } while (next_opt != -1);
    
    DEBUG("SIG_TOOL_PATH set to: \"%s\"\n", g_sig_tool_path);
    DEBUG("SIG_DATA_PATH set to: \"%s\"\n", g_sig_data_path);
    DEBUG("Input filename = %s\n", ifname);
    DEBUG("Output filename = %s\n", ofname);
    if (NULL != g_cfgfilename)
        DEBUG("Input CSF Configuration filename = %s\n", g_cfgfilename);

    /* Allocate buffer for input file */
    ibuf = alloc_buffer(fp_in, ifname_full);
    if (NULL == ibuf) {
        fprintf(stderr, "ERROR: File read error: %s\n", ifname_full);
        goto err;
    }
    
    ibuf_size = get_file_size(fp_in, ifname_full);
    DEBUG("Input filesize = %ld bytes\n", ibuf_size);
    /* Input file size should be atleast greater than image offset parameter plus word size */
    if (ibuf_size < (g_image_offset + 4)) {
        fprintf(stderr, "ERROR: File size too small: 0x%lx\n", ibuf_size);
        goto err;
    }

    unsigned long off = 0;

    /* Parse w.r.t type of IVT */
    if (IS_AHAB_IMAGE(ibuf, ibuf_size, g_ivt_v3_ahab_array, g_ivt_v3_mask, off)) {
        g_image_offset += off;
        flash_header_v3_t *hdr_v3 = (flash_header_v3_t *)(ibuf + off);

        DEBUG("IVT header = TAG:0x%02X | LEN:0x%04X | VER:0x%02X\n",
              hdr_v3->tag, hdr_v3->length, hdr_v3->version);

        if (!find_cst_tool(sig_tool_path_buf)) {
            /* If CST is found, sign with CST tool */
            ret = sign_container(ibuf, ibuf_size, ifname_full, ofname);
        } else if (!find_spsdk_tool(sig_tool_path_buf)) {
            /* If SPSDK is found, sign with SPSDK NXPIMAGE tool */
            ret = sign_container_spsdk(ifname_full, ofname);
        } else {
            fprintf(stderr, "ERROR: No signer tool found. Exiting.\n");
            goto err;
        }

    } else if (IS_HAB_IMAGE(ibuf, ibuf_size, g_ivt_v1, g_ivt_v1_mask, off, g_image_offset)) {
        g_image_offset += off;
        ivt_t *ivt = (ivt_t *)(ibuf + off);
        DEBUG("IVT header = TAG:0x%02X | LEN:0x%04X | VER:0x%02X\n",
              ivt->ivt_hdr.tag, ivt->ivt_hdr.length, ivt->ivt_hdr.version);
        if (!find_cst_tool(sig_tool_path_buf)) {
            ret = sign_hab_image(ibuf, ibuf_size, ifname_full, ofname);
        } else {
            fprintf(stderr, "ERROR: CST tool not found. Only CST tool is supported to sign HAB images\n");
            goto err;
        }
    } else {
        fprintf(stderr, "ERROR: Invalid IVT tag: 0x%x\n", (ibuf + g_image_offset)[3]);
        goto err;
    }

    if (!ret) {
        DEBUG("%s was successfully signed. %s was generated.\n", ifname_full, ofname);
        FCLOSE(fp_in);
        FREE(ibuf);
        FREE(sig_tool_path_buf);
        return E_OK;
    } else
        goto err;

    return EXIT_SUCCESS;
err:
    FCLOSE(fp_in);
    FREE(ibuf);
    FREE(sig_tool_path_buf);
    return -E_FAILURE;
}
