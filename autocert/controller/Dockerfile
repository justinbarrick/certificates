# build stage
FROM justinbarrick/step-cli:dev
ENV STEPPATH="/home/step/.step"
ENV PWDPATH="/home/step/password/password"
ENV CONFIGPATH="/home/step/autocert/config.yaml"
COPY controller server
ENTRYPOINT ./server $CONFIGPATH
