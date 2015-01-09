# Socks Server 5 - Monitor TLC
# Copyright (C) 2002 - 2010 by Matteo Ricchetti - <matteo.ricchetti@libero.it>

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#


#
# Log file
#
LOG_FILE=/tmp/mon.log
#MON_IP=125.46.59.156
MON_IP=g.cn
DELAY_THRESHOLD=550

#
# Command to do when conditions are matched (i.e. if delay > 100ms or 
# ping loses 3 consecutive packets)
#
cmd1 () {
  echo "Change the DEFAULT values.. "$1 >> $LOG_FILE
  # PUT HERE THE COMMAND #
}

#
# Command to do when conditions are not matched (i.e. if delay < 100ms or 
# ping doens't lose more than 2 consecutive packets). 
# DEFAULT values are restored
#
cmd2 () {
  echo "Restore to DEFAULT values.. "$1 >> $LOG_FILE
  # PUT HERE THE COMMAND #
}


#
# DELAY Monitor
#
mon_delay () {
  DELAY=0;
  
  DL=`ping $MON_IP -c 1 -W 1| awk '{if ( $2 == "packets" ) {gsub("%","",$0);gsub("ms","",$0);if ($10 > ENVIRON["DELAY_THRESHOLD"]) {print 1} else print 0} }'` 
  DELAY=`expr $DELAY + $DL`
  DL=`ping $MON_IP -c 1 -W 1| awk '{if ( $2 == "packets" ) {gsub("%","",$0);gsub("ms","",$0);if ($10 > ENVIRON["DELAY_THRESHOLD"]) {print 1} else print 0} }'` 
  DELAY=`expr $DELAY + $DL`
  DL=`ping $MON_IP -c 1 -W 1| awk '{if ( $2 == "packets" ) {gsub("%","",$0);gsub("ms","",$0);if ($10 > ENVIRON["DELAY_THRESHOLD"]) {print 1} else print 0} }'` 
  DELAY=`expr $DELAY + $DL`
  
  if [ "${DELAY}" == 3 ]; then
    if [ "${FLAG}" == 0 ]; then
      cmd1 A
      FLAG=1;
    else
      cmd1 . 
    fi
  else
    if [ "${FLAG}" == 1 ]; then
      cmd2 B
      FLAG=0;
    else
      cmd2 .
    fi
  fi
}

#
# LOSS Monitor
#
mon_loss () {
  LOSS=0;

  LS=`ping $MON_IP -c 1  -W 1 | awk '{if ( $2 == "packets" ) {gsub("%","",$0);gsub("ms","",$0);if ($6 = 100) {print 0} else print 1} }'`
  LOSS=`expr $LOSS + $LS`
  LS=`ping $MON_IP -c 1  -W 1 | awk '{if ( $2 == "packets" ) {gsub("%","",$0);gsub("ms","",$0);if ($6 = 100) {print 0} else print 1} }'`
  LOSS=`expr $LOSS + $LS`
  LS=`ping $MON_IP -c 1  -W 1 | awk '{if ( $2 == "packets" ) {gsub("%","",$0);gsub("ms","",$0);if ($6 = 100) {print 0} else print 1} }'`
  LOSS=`expr $LOSS + $LS`

  if [ "${LOSS}" == 3 ]; then
    if [ "${FLAG}" == 0 ]; then
      cmd1 C
      FLAG=1;
    else
      cmd1 .
    fi
  else
    if [ "${FLAG}" == 1 ]; then
      cmd2 D
      FLAG=0;
    else
      cmd2 .
    fi
  fi
}

# ################################################# #
# MAIN PROGRAM                                      #
#

FLAG=0;

while true; do

  mon_loss
  mon_delay

done

