## IMX Signer


> **_NOTE_** Going forward, via this tool, signing HAB images (i.MX 6/7/8M)
will be supported by CST and AHAB images (i.MX 8x/8ULP/9) will be supported by SPSDK.

---

### Introduction
The IMX signer tool works in conjunction with the [Code Signing Tool (CST)](https://www.nxp.com/webapp/Download?colCode=IMX_CST_TOOL_NEW&appType=license&location=null) 
and [Secure Provisioning SDK (SPSDK)](https://spsdk.readthedocs.io/) provided by NXP.
This tool allows a way to automate the signing process in conjunction with a 
configuration file that can be populated with necessary inputs. In addition, 
this tool parses the "to be signed" image and extracts the offset and length 
information needed to sign the image, thus reducing the possible human error 
while signing.

> **_NOTE_** A lot of heavy lifting is done by SPSDK in case of AHAB devices,
thus, this tool is simply a wrapper around SPSDK.

---

### Prerequisite
This tool requires the CST/SPSDK to be present at a preset location. Provide 
the path to CST/SPSDK using the environment variable ***SIG_TOOL_PATH***.

In addition, optionally, location of keys and certificates can be provided
using the environment variable ***SIG_DATA_PATH***.

By default, the location of private keys and certificates/public keys are
expected to be available in keys and crts folder, respectively.

CST /SPSDK signing data structure:
```
<cst/spsdk folder>
|--crts
   ├── certificates
   └── public keys
|--keys
   └── private keys
```

> **_NOTE_** For SPSDK YAML configuration files, user needs to only provide the
private key in signer parameters and public keys/certificates in the srk_array
parameters. The tool auto prepends the SIG_DATA_PATH value and forms the
correct structure for both signer and srk_array parameters.

> **_NOTE_** If ***SIG_DATA_PATH*** is not provided, it assumes the path of 
***SIG_TOOL_PATH***.

---

### Build

Build this tool using `make` command.

---

### Run

To run this tool, along with CST/SPSDK, you would also need to have the CSF/
YAML config file filled with appropriate values based on the setup.

To help start the signing process, sample CSF/YAML configuration files have 
been provided as part of this package.

- **CFG file supporting HAB images:** *csf_hab4.cfg.sample* or *csf_hab4_pkcs11.cfg.sample* for PKCS#11 Support
- **CFG file supporting AHAB images:** *spsdk_ahab.yaml.sample*

Invoke the *imx_signer* executable as follows (example):
```sh
# CST Example: 
$ SIG_TOOL_PATH=<cst> SIG_DATA_PATH=<keys/crts folder> ./imx_signer -i flash.bin -c csf.cfg
# SPSDK Example:
$ SIG_TOOL_PATH=<spsdk> SIG_DATA_PATH=<keys/crts folder> ./imx_signer -i flash.bin -c spsdk.yaml
```

### PKCS#11 Support HAB
For PKCS#11-based signing with Hardware Security Modules (HSMs), configure your CSF file using the **exact format**:
```sh
csfk_file=pkcs11:token=${PKCS-TOKEN};object=CSF1_1_sha256_2048_65537_v3_usr;type=cert;pin-value=${USR_PIN}
img_file=pkcs11:token=${PKCS-TOKEN};object=IMG1_1_sha256_2048_65537_v3_usr;type=cert;pin-value=${USR_PIN}
```
**_NOTE_**: Be sure the PKCS#11 support is enabled and Token and USR_PIN environmental variables are defined.

### PKCS#11 Support AHAB
For SPSDK, please refer to [SPSDK PKCS11 Plugin](<https://github.com/nxp-mcuxpresso/spsdk_plugins/tree/main/pkcs11>) for installation details.
Simply use the format described in the plugin documentation for `signer`
parameter in the YAML configuration file.

---
### Results

This tool generates final signed binary as "**signed-\<input_filename\>**". In 
case of CST, CSF files are created and in case of SPSDK, YAML config file is 
created, which are used to generate the final signed binary.
