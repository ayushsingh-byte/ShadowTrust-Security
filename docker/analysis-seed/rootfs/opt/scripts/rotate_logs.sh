#!/bin/bash
find /home/deploy/projects/storefront/logs -name '*.log' -size +50M -exec gzip {} \;
