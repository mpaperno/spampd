#!/bin/sh
#
# This script starts and stops the spampd daemon
#
####   NOTE   #####
#  This is a very old and outdated example!!!
#  Recommend checking the Debian version of spampd.init script,
#  in the /debian branch of the source repository
#  (https://github.com/mpaperno/spampd/tree/debian).
#
# chkconfig: 2345 80 30
#
# description: spampd is a daemon process which uses SpamAssassin to check
#              email messages for SPAM.

# Source function library.
. /etc/rc.d/init.d/functions

# Source networking configuration.
. /etc/sysconfig/network

# Check that networking is up.
[ ${NETWORKING} = "no" ] && exit 0

[ -f /usr/bin/spampd -o -f /usr/local/bin/spampd ] || exit 0
PATH=$PATH:/usr/bin:/usr/local/bin

# See how we were called.
case "$1" in
  start)
	# Start daemon.
	echo -n "Starting spampd: "
	daemon spampd --port=10025 --relayhost=127.0.0.1:25 --tagall --auto-whitelist
	RETVAL=$?
	touch /var/lock/spampd
	echo
	;;
  stop)
	# Stop daemons.
	echo -n "Shutting down spampd: "
	killproc spampd
	RETVAL=$?
	rm -f /var/lock/spampd
	echo
	;;
  restart)
	$0 stop
	$0 start
	;;
  status)
	status spampd
	;;
  *)
	echo "Usage: $0 {start|stop|restart|status}"
	exit 1
esac

exit 0
