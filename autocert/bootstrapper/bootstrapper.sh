#!/bin/sh

# Download the root certificate and set permissions
yes |step ca certificate $COMMON_NAME $CRT $KEY
yes |step ca root $STEP_ROOT
chmod ${FILE_MODE:-644} $STEP_ROOT $CRT $KEY

if [ "$FILE_USER" != "" ]; then
  chown "$FILE_USER" $STEP_ROOT $CRT $KEY
fi

if [ "$FILE_GROUP" != "" ]; then
  chgrp "$FILE_GROUP" $STEP_ROOT $CRT $KEY
fi
