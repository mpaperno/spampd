#!/bin/sh -e
#
# process /etc/defaults/spampd and create environment file for systemd service
#

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin

if [ -f /etc/default/spampd ]; then
	. /etc/default/spampd
fi

istrue () {
    ANS=$(echo $1 | tr A-Z a-z)
    [ "$ANS" = 'yes' -o "$ANS" = 'true' -o "$ANS" = 'enable' -o "$ANS" = '1' ]
}

# 
# Calculate commandline options
# always set PIDFile for systemd
#
ARGS="--pid=/var/run/spampd/spampd.pid"

istrue "$TAGALL" && ARGS="${ARGS} --tagall"

istrue "$AUTOWHITELIST" && ARGS="${ARGS} --auto-whitelist"

istrue "$LOCALONLY" && ARGS="${ARGS} --L"

istrue "$LOGINET" && LOGTARGET="inet" || LOGTARGET="unix"

[ -n "${LISTENPORT}" ] && ARGS="${ARGS} --port=${LISTENPORT}"

[ -n "${LISTENHOST}" ] && ARGS="${ARGS} --host=${LISTENHOST}"

[ -n "${DESTPORT}" ] && ARGS="${ARGS} --relayport=${DESTPORT}"

[ -n "${DESTHOST}" ] && ARGS="${ARGS} --relayhost=${DESTHOST}"

[ -n "${CHILDREN}" ] && ARGS="${ARGS} --children=${CHILDREN}"

[ -n "${LOGTARGET}" ] && ARGS="${ARGS} --logsock=${LOGTARGET}"

[ -n "${ADDOPTS}" ] && ARGS="${ARGS} ${ADDOPTS}"

# if USERID or GRPID are not set, set them to spampd's default
if [ -n "${USERID}" ]; then
	ARGS="${ARGS} --user=${USERID}"
else
	USERID=mail
fi

if [ -n "${GRPID}" ]; then
	ARGS="${ARGS} --group=${GRPID}"
else
	GRPID=mail
fi

[ -d /var/run/spampd ] || mkdir /var/run/spampd
chown ${USERID}.${GRPID} /var/run/spampd

echo 'SPAMPD_ARGS = "'${ARGS}'"' > /var/run/spampd/spampd.arguments

exit 0
