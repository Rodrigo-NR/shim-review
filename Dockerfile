FROM debian:bookworm
ARG CERT_FILE="LUX_CA_PUB.cer"

# dependencies
RUN apt-get -y -qq update
RUN apt-get -y -qq install gcc make bzip2 efitools curl wget git

# clone shim
WORKDIR /build
RUN wget https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2
RUN tar -jxvpf shim-15.8.tar.bz2 && rm shim-15.8.tar.bz2
WORKDIR /build/shim-15.8

# include certificate and custom sbat
ADD ${CERT_FILE} .
ADD sbat.csv .

# append sbat data to the upstream data/sbat.csv
RUN cat sbat.csv >> data/sbat.csv && cat data/sbat.csv

# build x64
RUN mkdir build-x64
RUN make -C build-x64 ARCH=x86_64 VENDOR_CERT_FILE=../${CERT_FILE} TOPDIR=.. -f ../Makefile

# build x32	
RUN mkdir build-ia32
RUN setarch linux32 make -C build-ia32 ARCH=ia32 \
VENDOR_CERT_FILE=../${CERT_FILE} TOPDIR=.. -f ../Makefile

# output
RUN mkdir /build/output
RUN cp build-x64/shimx64.efi /build/output
RUN cp build-ia32/shimia32.efi /build/output
RUN cp ${CERT_FILE} /build/output
RUN objdump -s -j .sbatlevel /build/output/shimx64.efi
RUN objdump -j .sbat -s /build/output/shimx64.efi
RUN objdump -s -j .sbatlevel /build/output/shimia32.efi
RUN objdump -j .sbat -s /build/output/shimia32.efi
RUN sha256sum /build/output/*
