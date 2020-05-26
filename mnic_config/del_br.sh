#!/bin/bash

brif="siiba"

ifconfig $brif down
brctl delbr $brif
