#!/bin/bash
python3 server.py 2>&1 | tee -a /tmp/pcontrol.log
