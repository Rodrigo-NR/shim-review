Confirm the following are included in your repo, checking each box:

 - [x] completed README.md file with the necessary information
 - [x] shim.efi to be signed
 - [x] public portion of your certificate(s) embedded in shim (the file passed to VENDOR_CERT_FILE)
 - [x] binaries, for which hashes are added to vendor_db ( if you use vendor_db and have hashes allow-listed )
 - [x] any extra patches to shim via your own git tree or as files
 - [x] any extra patches to grub via your own git tree or as files
 - [x] build logs
 - [X] a Dockerfile to reproduce the build of the provided shim EFI binaries

*******************************************************************************
### What is the link to your tag in a repo cloned from rhboot/shim-review?
*******************************************************************************
https://github.com/Rodrigo-NR/shim-review/tree/lux2.0-shim-amd64_i386-20240304

*******************************************************************************
### What is the SHA256 hash of your final SHIM binary?
*******************************************************************************
	7e8e4368bb69563d5c479fe61270ceb4fe61e9dc06575e4645426713590aa9da  shimia32.efi
	c2afb5e3c305c894c299b54157a1a05891e4b7b0f6722a00696999820490e5db  shimx64.efi

*******************************************************************************
### What is the link to your previous shim review request (if any, otherwise N/A)?
*******************************************************************************
https://github.com/rhboot/shim-review/issues/308
