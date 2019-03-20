#!/bin/sh

# Download the root certificate and set permissions
step ca certificate $COMMON_NAME $CRT $KEY
step ca root $STEP_ROOT
chmod ${FILE_MODE:-644} $STEP_ROOT $CRT $KEY
