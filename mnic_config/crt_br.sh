#!/bin/bash

brif="siiba"

brctl addbr $brif
brctl addif $brif tap0
ip addr add 10.0.0.2/24 dev $brif

