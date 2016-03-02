# Base image
FROM alpine:3.3

# Maintainer info
MAINTAINER Patrick Butler Monterde <Patrick.butlermonterde@emc.com>

# Get the Required Packages
RUN apk --update add bash git python py-pip nano man drill nmap
RUN pip install --upgrade pip
RUN pip install dnspython

RUN mkdir /opt
RUN cd /opt &&\
  git clone https://github.com/pbutlerm/dnschecker &&\
  cd /opt/dnschecker/

# Set the default directory
WORKDIR /opt/dnschecker/

# Display Phython version
CMD python --version
