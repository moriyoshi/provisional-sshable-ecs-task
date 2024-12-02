FROM public.ecr.aws/amazonlinux/amazonlinux:minimal
RUN dnf install -y openssh-server openssh-clients rsyslog
COPY ./rsyslog.conf /etc/rsyslog.conf
COPY ./wait-for-it.sh /usr/bin/wait-for-it.sh
ENTRYPOINT ["/bin/bash", "-c", "ssh-keygen -A && /usr/sbin/sshd -o ListenAddress=127.0.0.1:22222 && /usr/sbin/rsyslogd -n"]