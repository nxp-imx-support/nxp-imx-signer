## IMX Signer


> **_NOTE_** The NXP-CST-SIGNER tool will be renamed to NXP-IMX-SIGNER in 
upcoming release. The NXP-IMX-SIGNER tool will support multiple signing tools 
i.e. CST and SPSDK.

> **_NOTE_** The CST signing support for AHAB images (i.MX 8/8x, 8ULP and 9 
family) is not being maintained going forward and will be deprecated. It will 
be replaced with SPSDK signing support. Eventually HAB images (i.MX 6/7/8M) 
will be supported by CST and AHAB images will be supported by SPSDK.

---

### Introduction
The IMX signer tool works in conjunction with the [Code Signing Tool (CST)](https://www.nxp.com/webapp/Download?colCode=IMX_CST_TOOL_NEW&appType=license&location=null) 
and [Secure Provisioning SDK (SPSDK)](https://spsdk.readthedocs.io/) provided by NXP.
This tool allows a way to automate the signing process in conjunction with a 
configuration file that can be populated with necessary inputs. In addition, 
this tool parses the "to be signed" image and extracts the offset and length 
information needed to sign the image, thus reducing the possible human error 
while signing. 

---

### Prerequisite
This tool requires the CST/SPSDK to be present at a preset location. Provide 
the path to CST/SPSDK using the environment variable ***SIG_TOOL_PATH***.

In addition, optionally, location of keys and certificates can be provided
using the environment variable ***SIG_DATA_PATH***.

By default, the location of private keys and certificates are expected to be available in keys and crts folder, respectively.

CST file structure:
```
<cst folder>
|--crts
|--keys
```

SPSDK file structure:
```
<spsdk folder>
|--crts
|--keys
```

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

- CFG file supporting HAB images: *csf_hab4.cfg.sample* or *csf_hab4_pkcs11.cfg.sample* for PKCS11 Support
- CFG file supporting AHAB images: *csf_ahab.cfg.sample*, *spsdk_ahab.cfg.sample*

**_NOTE_**: Be sure the PKCS#11 support is enabled and Token and USR_PIN environmental variables are defined.

Invoke the *imx_signer* executable as follows (example):
```sh
# CST Example: 
$ SIG_TOOL_PATH=<cst> SIG_DATA_PATH=<keys/crts folder> ./imx_signer -i flash.bin -c csf.cfg
# SPSDK Example:
$ SIG_TOOL_PATH=<spsdk> SIG_DATA_PATH=<keys/crts folder> ./imx_signer -i flash.bin -c spsdk.cfg
```
---
### Results

This tool generates final signed binary as "**signed-\<input_filename\>**". In 
case of CST, CSF files are created and in case of SPSDK, YAML config file is 
created, which are used to generate the final signed binary.
