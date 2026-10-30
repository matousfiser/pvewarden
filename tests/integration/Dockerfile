# A minimal "guest": the distribution image plus sshd. The pvewarden client is installed by the test.
ARG IMAGE=ubuntu:24.04
FROM ${IMAGE}
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && ssh-keygen -A
COPY guest /opt/pvewarden-guest
CMD ["/usr/sbin/sshd", "-D", "-e"]
