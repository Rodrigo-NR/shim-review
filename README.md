This repo is for review of requests for signing shim.  To create a request for review:

- clone this repo
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push that to github
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 or systemd-boot on Linux, so
asking us to endorse anything else for signing is going to require some convincing on
your part.

Check the docs directory in this repo for guidance on submission and
getting your shim signed.

Here's the template:

*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
Lenovo

*******************************************************************************
### What product or service is this for?
*******************************************************************************
LUX, a Linux distribution customized for Lenovo notebooks and desktops.

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
Although primarly built for Lenovo hardware, LUX is designed to run on any platform that supports UEFI Secure Boot and the easiest way to support the largest number of systems is to have a shim bootloader signed by Microsoft.

*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************
LUX wants to employ Secure Boot for building a trusted operating system from Shim to GRUB to the kernel to kernel modules. 
Lenovo CA will be used to sign custom kernels and video drivers, and as such needs a signed shim with our certificate so that we can sign the drivers to allow users to keep Secure Boot on.

*******************************************************************************
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.
*******************************************************************************
- Name: Igor Cunha Teixeira
- Position: Software Engineer
- Email address: igort@ipt.br
- PGP key fingerprint: A0D6 BB8D 244D FA22 512D  AD02 C44A 8E61 5304 D4B7

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Who is the secondary contact for security updates, etc.?
*******************************************************************************
Secondary contact 1:
- Name: Mauricio Maniga
- Position: Software Engineer
- Email address: mmaniga1@lenovo.com
- PGP key fingerprint: FBE7 5DC1 E9A1 2B5F 8294 5568 4F36 FA5D C084 561D

Secondary contact 2:
- Name: Rodrigo Neves Ribeiro
- Position: Software Engineer
- Email address: rodrigoneves@ipt.br
- PGP key fingerprint: 18EE 5ECA 8638 5E81 436A  9D8B 9F5E B635 FFCB 9139


(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Were these binaries created from the 15.8 shim release tar?
Please create your shim binaries starting with the 15.8 shim release tar file: https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.8 and contains the appropriate gnu-efi source.

*******************************************************************************
Yes

*******************************************************************************
### URL for a repo that contains the exact code which was built to get this binary:
*******************************************************************************
https://github.com/Rodrigo-NR/shim-review/tree/lux2.0-shim-amd64_i386-20240304

*******************************************************************************
### What patches are being applied and why:
*******************************************************************************
None

*******************************************************************************
### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

See https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522 for more details on the signing of shim without NX bit.
*******************************************************************************
It is not set.

*******************************************************************************
### If shim is loading GRUB2 bootloader what exact implementation of Secureboot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
*******************************************************************************
We use the lastest grub2 version (2.12-1) from debian trixie.

*******************************************************************************
### If shim is loading GRUB2 bootloader and your previously released shim booted a version of GRUB2 affected by any of the CVEs in the July 2020, the March 2021, the June 7th 2022, the November 15th 2022, or 3rd of October 2023 GRUB2 CVE list, have fixes for all these CVEs been applied?

* 2020 July - BootHole
  * Details: https://lists.gnu.org/archive/html/grub-devel/2020-07/msg00034.html
  * CVE-2020-10713
  * CVE-2020-14308
  * CVE-2020-14309
  * CVE-2020-14310
  * CVE-2020-14311
  * CVE-2020-15705
  * CVE-2020-15706
  * CVE-2020-15707
* March 2021
  * Details: https://lists.gnu.org/archive/html/grub-devel/2021-03/msg00007.html
  * CVE-2020-14372
  * CVE-2020-25632
  * CVE-2020-25647
  * CVE-2020-27749
  * CVE-2020-27779
  * CVE-2021-3418 (if you are shipping the shim_lock module)
  * CVE-2021-20225
  * CVE-2021-20233
* June 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-06/msg00035.html, SBAT increase to 2
  * CVE-2021-3695
  * CVE-2021-3696
  * CVE-2021-3697
  * CVE-2022-28733
  * CVE-2022-28734
  * CVE-2022-28735
  * CVE-2022-28736
  * CVE-2022-28737
* November 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-11/msg00059.html, SBAT increase to 3
  * CVE-2022-2601
  * CVE-2022-3775
* October 2023 - NTFS vulnerabilities
  * Details: https://lists.gnu.org/archive/html/grub-devel/2023-10/msg00028.html, SBAT increase to 4
  * CVE-2023-4693
  * CVE-2023-4692
*******************************************************************************
The current builds include the grub,4 fixes (version 2.12-1) from debian trixie.

*******************************************************************************
### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 4?
The entry should look similar to: `grub,4,Free Software Foundation,grub,GRUB_UPSTREAM_VERSION,https://www.gnu.org/software/grub/`
*******************************************************************************
The SBAT generation in GRUB2 binary is set to 4.

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
*******************************************************************************
Our first shim was 15.7 and it was not signed by Microsoft. Therefore the binaries never reached production.
Old binaries are prevented from booting by the sbat mechanism.

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
*******************************************************************************
All the above patches are applied to our kernel (6.6.18).

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
We include a local patch that adds the touchpad vendor ELAN4000 via acpi id in elan-i2c-ids.h and local patches to enforce kernel_lockdown when secure boot is enabled.
*******************************************************************************
### Do you use an ephemeral key for signing kernel modules?
### If not, please describe how you ensure that one kernel build does not load modules built for another kernel.
*******************************************************************************
Ephemeral key is used.

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
We do not use vendor_db.

*******************************************************************************
### If you are re-using a previously used (CA) certificate, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs to vendor_dbx in shim in order to prevent GRUB2 from being able to chainload those older GRUB2 binaries. If you are changing to a new (CA) certificate, this does not apply.
### Please describe your strategy.
*******************************************************************************
We re-use CA that never reached production. Therefore, they cannot be used to chainload older GRUB2 binaries.

*******************************************************************************
### What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as closely as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
### If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and what the differences would be.
*******************************************************************************
We include a Dockerfile.

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
build.log obtained from "docker build" command.

*******************************************************************************
### What changes were made in the distor's secure boot chain since your SHIM was last signed?
For example, signing new kernel's variants, UKI, systemd-boot, new certs, new CA, etc..
*******************************************************************************
New kernel (6.6.18), grub (2.12-1) and fwupd (1.4+1) were signed.

*******************************************************************************
### What is the SHA256 hash of your final SHIM binary?
*******************************************************************************

	7e8e4368bb69563d5c479fe61270ceb4fe61e9dc06575e4645426713590aa9da  shimia32.efi
	c2afb5e3c305c894c299b54157a1a05891e4b7b0f6722a00696999820490e5db  shimx64.efi

*******************************************************************************
### How do you manage and protect the keys used in your SHIM?
*******************************************************************************
Keys are managed and stored in a HSM.
Access is tightly controlled and operations are restricted to authorized individuals.

*******************************************************************************
### Do you use EV certificates as embedded certificates in the SHIM?
*******************************************************************************
No.

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( GRUB2, fwupd, fwupdate, systemd-boot, systemd-stub, shim + all child shim binaries )?
### Please provide exact SBAT entries for all SBAT binaries you are booting or planning to boot directly through shim.
### Where your code is only slightly modified from an upstream vendor's, please also preserve their SBAT entries to simplify revocation.
If you are using a downstream implementation of GRUB2 or systemd-boot (e.g.
from Fedora or Debian), please preserve the SBAT entry from those distributions
and only append your own. More information on how SBAT works can be found
[here](https://github.com/rhboot/shim/blob/main/SBAT.md).
*******************************************************************************

SHIM:

	sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
	shim,4,UEFI shim,shim,1,https://github.com/rhboot/shim
	shim.lux,1,LUX,shim,15.8,mail:lux@lenovo.com

GRUB:

	sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
	grub,4,Free Software Foundation,grub,2.12,https://www.gnu.org/software/grub/
	grub.debian,4,Debian,grub2,2.12-1,https://tracker.debian.org/pkg/grub2
	grub.debian13,1,Debian,grub2,2.12-1,https://tracker.debian.org/pkg/grub2
	grub.peimage,1,Canonical,grub2,2.12-1,https://salsa.debian.org/grub-team/grub/-/blob/master/debian/patches/secure-boot/efi-use-peimage-shim.patch
	grub.lux,1,LUX,grub2,2.12-1-lux,mail:lux@lenovo.com

FWUPD:

	sbat,1,UEFI shim,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
	fwupd-efi,1,Firmware update daemon,fwupd-efi,1.4,https://github.com/fwupd/fwupd-efi
	fwupd-efi.debian,1,Debian,fwupd,1:1.4-1,https://tracker.debian.org/pkg/fwupd
	fwupd-efi.lux,1,LUX,fupdw,1:1.4-1-lux,mail:lux@lenovo.com

*******************************************************************************
### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?
*******************************************************************************
all_video boot btrfs cat chain configfile cpuid cryptodisk echo efifwsetup efinet ext2 f2fs fat font gcry_arcfour gcry_blowfish gcry_camellia gcry_cast5 gcry_crc gcry_des gcry_dsa gcry_idea gcry_md4 gcry_md5 gcry_rfc2268 gcry_rijndael gcry_rmd160 gcry_rsa gcry_seed gcry_serpent gcry_sha1 gcry_sha256 gcry_sha512 gcry_tiger gcry_twofish gcry_whirlpool gettext gfxmenu gfxterm gfxterm_background gzio halt help hfsplus iso9660 jfs jpeg keystatus linux linuxefi loadenv 	loopback ls lsefi lsefimmap lsefisystab lssal luks lvm mdraid09 mdraid1x memdisk minicmd normal ntfs part_apple part_gpt part_msdos password_pbkdf2 play png probe raid5rec raid6rec reboot regexp search search_fs_file search_fs_uuid 	search_label sleep squash4 test tftp tpm true video xfs zfs zfscrypt zfsinfo

*******************************************************************************
### If you are using systemd-boot on arm64 or riscv, is the fix for [unverified Devicetree Blob loading](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c) included?
*******************************************************************************
We do not use either systemd-boot or arm64/riscv archtectures.

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?
*******************************************************************************
We use the lastest grub2 version (2.12-1) from debian trixie.

*******************************************************************************
### If your SHIM launches any other components, please provide further details on what is launched.
*******************************************************************************
Only FWUPD.

*******************************************************************************
### If your GRUB2 or systemd-boot launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
*******************************************************************************
N/A

*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
*******************************************************************************
grub2 loads the signed kernel image with the lockdown patches applied. The kernel only loads signed modules. fwupdate does not load any binaries other than UEFI updates.

*******************************************************************************
### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB2)?
*******************************************************************************
No.

*******************************************************************************
### What kernel are you using? Which patches does it includes to enforce Secure Boot?
*******************************************************************************
We are using Kernel 6.6.18 with lockdown and other patches applied to the longterm kernel.

*******************************************************************************
### Add any additional information you think we may need to validate this shim.
*******************************************************************************
Our first submission was accepted by the shim community, but we did not reach submission stage to Microsoft due to our internal development process.
The previous binaries presented never reached production.
