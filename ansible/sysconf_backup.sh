#!/usr/bin/env bash

set -euo pipefail

BACKUP="/root/system-config-backup-$(date +%F_%T).tar.gz"

FOLDER_LIST=(
    "/etc"
    "/usr/local/etc"
    "/etc/default"
    "/etc/apt"
    "/etc/systemd"
    "/etc/modprobe.d"
    "/etc/netplan"
    "/etc/ssh"
    "/etc/cron*"
    "/etc/sudoers"
    "/etc/sudoers.d"
    "/etc/ufw"
    "/etc/fail2ban"
    "/etc/nginx"
    "/etc/apache2"
    "/etc/mysql"
    "/etc/postgresql"
    "/etc/docker"
    "/etc/libvirt"
    "/etc/lvm"
    "/etc/kernel"
    "/boot/grub"
)

#remove non existing folders from the list
for i in "${!FOLDER_LIST[@]}"; do
    if [ ! -e "${FOLDER_LIST[$i]}" ]; then
        unset 'FOLDER_LIST[i]'
    fi
done

#create the backup using FOLDER_LIST
tar --numeric-owner --xattrs --acls \
    -czpf "${BACKUP}" "${FOLDER_LIST[@]}"

echo "${BACKUP}"

