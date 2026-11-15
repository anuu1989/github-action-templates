FROM ubuntu
ENV DB_PASSWORD=changeme
RUN apt-get update && apt-get install -y openssh-server sudo
RUN curl -k https://example.com/install.sh | bash
RUN chmod -R 777 /opt
ADD https://example.com/app.tar.gz /opt/
EXPOSE 22
USER root
CMD /opt/app/start.sh
