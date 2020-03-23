#!/bin/bash
#
# @(#) ratelimit - exercise PoC for ratelimit function
# @(#) $Id: ratelimit.sh,v 1.5 2020/03/12 23:42:54 bduncan Exp bduncan $
#
# Description:
#   - return OK if <= 5 within 60 seconds, or DROP otherwise
#   - just a proof of concept
#   - if 64s is ok, use bitwise and with 0x3f for modulus 64
#
#######################################################################

cat <<- EoT |
10.0.0.1 1584000000
10.0.0.1 1584000001
10.0.0.1 1584000002
10.0.0.1 1584000003
10.0.0.1 1584000004
10.0.0.1 1584000005
10.0.0.1 1584000006
10.0.0.2 1584000007
10.0.0.2 1584000007
10.0.0.2 1584000007
10.0.0.2 1584000007
10.0.0.2 1584000007
10.0.0.2 1584000007
10.0.0.2 1584000007

# within the window
10.0.0.1 1584000059
10.0.0.2 1584000059

# 60 seconds later after the first timestamp..
10.0.0.1 1584000060
10.0.0.1 1584000060
10.0.0.2 1584000060
10.0.0.1 1584000060
10.0.0.2 1584000060
10.0.0.3 1584000060
10.0.0.4 1584000060
# another 30+ seconds
10.0.0.1 1584000090
10.0.0.1 1584000090
10.0.0.1 1584000090
10.0.0.1 1584000090
10.0.0.1 1584000090
10.0.0.1 1584000090
10.0.0.2 1584000091
10.0.0.3 1584000092
10.0.0.1 1584000099
10.0.0.2 1584000099
10.0.0.3 1584000099
10.0.0.4 1584000099
10.0.0.1 1584000100
10.0.0.2 1584000101
10.0.0.3 1584000102
10.0.0.4 1584000103
10.0.0.5 1584000104
10.0.0.5 1584000105
10.0.0.6 1584000105
EoT


awk '
  BEGIN {
    OK        = 1
    DROP      = 0
    THRESHOLD = 5
    WINDOW    = 60
    # TIMESTAMPS[60] # stores actual timestamps keyed by modulus for buckets
    # IPLIST[60]     # linked list of IPs within each bucket
    # IPCOUNTS[]     # array of counts within window keyed by IP address
  }

  function ratelimit( ip, ts,     i, t, bucket, ptr ) {
    bucket = ts % WINDOW
#   printf "DEBUG: ratelimit(%s, %s)  bucket=%d\n", ip, ts, bucket

    if (TIMESTAMPS[bucket] != ts) {  # whenever we change buckets
      # ..then go through and clear all lists with timestamps < ts-WINDOW
      # ..this can obviously be improved by stopping when within window
      for (ptr in TIMESTAMPS) {   # iterate through all buckets and expire any older
        if (TIMESTAMPS[ptr] <= (ts-WINDOW)) {    # expire older than window
          split( IPLIST[ptr], t)
          for (i in t) {
            if ((t[i] in IPCOUNTS) && --IPCOUNTS[t[i]] <= 0)
              delete IPCOUNTS[t[i]]    # garbage collection
          }
          delete IPLIST[ptr]
          delete TIMESTAMPS[ptr]
        }
      }
      TIMESTAMPS[bucket] = ts   # store the actual timestamp for the bucket
    }

    if (IPCOUNTS[ip] >= THRESHOLD) {
      return DROP
    }
    else {
      ++IPCOUNTS[ip]
      IPLIST[bucket] = IPLIST[bucket] " " ip  # this would be a linked list
      return OK
    }
  }

  NF && !/^#/ {
    printf "%s %s %-7s %d\n", $1, $2, (ratelimit($1,$2) == OK ? "OK" : "DROP"),  IPCOUNTS[$1]
  }

  END {
    print "THE END"
    for (i in TIMESTAMPS)
      printf "DEBUG:  TIMESTAMPS[%s]=%s\n", i, TIMESTAMPS[i]

    for (i in IPLIST)
      printf "DEBUG:  IPLIST[%s]=%s\n", i, IPLIST[i]

    for (ip in IPCOUNTS)
      printf "DEBUG:  IPCOUNTS[%s]=%d\n", ip, IPCOUNTS[ip]
  }
'

