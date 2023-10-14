FROM nginx:latest

RUN mkdir /files
RUN dd if=/dev/zero of=/files/small bs=1024 count=1024
RUN dd if=/dev/zero of=/files/big bs=1024 count=1024000
