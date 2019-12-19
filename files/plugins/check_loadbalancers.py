#!/usr/bin/env python3

import argparse
import nagios_plugin3
import os
import json
import openstack
import subprocess


def check_amphorae(connection):
    """check amphroae status."""

    lb_mgr = connection.load_balancer

    resp = lb_mgr.get('/v2/octavia/amphorae')
    if resp.status_code != 200:
        return

    data = json.loads(resp.content)
    items = data.get('amphorae', [])

    # raise CRITICAL for ERROR status
    bad_status_list = ('ERROR',)
    bad_items = [item for item in items if item['status'] in bad_status_list]
    if bad_items:
        items = ['amphroa {} status is {}'.format(
            item['id'], item['status']) for item in bad_items]
        output = 'CRITICAL: {}'.format(', '.join(items))
        raise nagios_plugin3.CriticalError(output)

    # raise WARNING for these status
    bad_status_list = ('PENDING_CREATE', 'PENDING_DELETE', 'BOOTING')
    bad_items = [item for item in items if item['status'] in bad_status_list]
    if bad_items:
        items = ['amphroa {} status is {}'.format(
            item['id'], item['status']) for item in bad_items]
        output = 'WARNING: {}'.format(', '.join(items))
        raise nagios_plugin3.WarnError(output)

    print('OK: Amphorae are happy')


def check_pools(connection):
    """check pools status."""
    lb_mgr = connection.load_balancer
    pools_all = lb_mgr.pools()
    pools_enabled = [pool for pool in pools_all if pool.is_admin_state_up]

    # check provisioning_status is ACTIVE for each pool
    pools = [pool for pool in pools_enabled if pool.provisioning_status != 'ACTIVE']
    if pools:
        items = ['pool {} provisioning_status is {}'.format(
            pool.id, pool.provisioning_status) for pool in pools]
        output = 'CRITICAL: {}'.format(', '.join(items))
        raise nagios_plugin3.CriticalError(output)

    # raise CRITICAL if ERROR
    pools = [pool for pool in pools_enabled if pool.operating_status == 'ERROR']
    if pools:
        items = ['pool {} operating_status is {}'.format(
            pool.id, pool.operating_status) for pool in pools]
        output = 'CRITICAL: {}'.format(', '.join(items))
        raise nagios_plugin3.CriticalError(output)

    # raise WARNING if NO_MONITOR
    pools = [pool for pool in pools_enabled if pool.operating_status == 'NO_MONITOR']
    if pools:
        items = ['pool {} operating_status is {}'.format(
            pool.id, pool.operating_status) for pool in pools]
        output = 'WARNING: {}'.format(', '.join(items))
        raise nagios_plugin3.WarnError(output)

    print('OK: Pools are happy')


def check_loadbalancers(connection):
    """check loadbalancers status."""

    lb_mgr = connection.load_balancer
    lb_all = lb_mgr.load_balancers()

    # only check enabled lbs
    lb_enabled = [lb for lb in lb_all if lb.is_admin_state_up]

    # check provisioning_status is ACTIVE for each lb
    lbs = [lb for lb in lb_enabled if lb.provisioning_status != 'ACTIVE']
    if lbs:
        items = ['loadbalancer {} provisioning_status is {}'.format(
            lb.id, lb.provisioning_status) for lb in lbs]
        output = 'CRITICAL: {}'.format(', '.join(items))
        raise nagios_plugin3.CriticalError(output)

    # check operating_status is ONLINE for each lb
    lbs = [lb for lb in lb_enabled if lb.operating_status != 'ONLINE']
    if lbs:
        items = ['loadbalancer {} operating_status is {}'.format(
            lb.id, lb.operating_status) for lb in lbs]
        output = 'CRITICAL: {}'.format(', '.join(items))
        raise nagios_plugin3.CriticalError(output)

    net_mgr = connection.network
    # check vip port exists for each lb
    lbs = []
    for lb in lb_enabled:
        try:
            net_mgr.get_port(lb.vip_port_id)
        except openstack.exceptions.NotFoundException:
            lbs.append(lb)
    if lbs:
        items = ['vip port {} for loadbalancer {} not found'.format(
            lb.vip_port_id, lb.id) for lb in lbs]
        output = 'CRITICAL: {}'.format(', '.join(items))
        raise nagios_plugin3.CriticalError(output)

    # warn about disabled lbs if no critical error found
    lb_disabled = [lb for lb in lb_all if not lb.is_admin_state_up]
    if lb_disabled:
        items = ['loadbalancer {} admin_state_up is False'.format(
            lb.id) for lb in lb_disabled]
        output = 'WARNING: {}'.format(', '.join(items))
        raise nagios_plugin3.WarnError(output)

    print('OK: Loadbalancers are happy')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check Loadbalancer status')
    parser.add_argument('--env', dest='env',
                        default='/var/lib/nagios/nagios.novarc',
                        help='Novarc file to use for this check')
    parser.add_argument('--check-loadbalancers', dest='check_loadbalancers',
                        help='check loadbalancers status',
                        action='store_true')
    parser.add_argument('--check-amphorae', dest='check_amphorae',
                        help='check amphorae status',
                        action='store_true')
    parser.add_argument('--check-pools', dest='check_pools',
                        help='check loadbalancer pools status',
                        action='store_true')
    parser.add_argument('--check-all', dest='check_all',
                        help='check above all status',
                        action='store_true')
    args = parser.parse_args()
    # grab environment vars
    command = ['/bin/bash', '-c', 'source {} && env'.format(args.env)]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    for line in proc.stdout:
        (key, _, value) = line.partition(b'=')
        os.environ[key.decode('utf-8')] = value.rstrip().decode('utf-8')
    proc.communicate()

    checks = []
    if args.check_all:
        checks = [check_pools, check_amphorae, check_loadbalancers]
    else:
        if args.check_pools:
            checks.append(check_pools)
        if args.check_amphorae:
            checks.append(check_amphorae)
        if args.check_loadbalancers:
            checks.append(check_loadbalancers)

    if not checks:
        parser.print_help()
    else:
        connection = openstack.connect(cloud='envvars')
        for check in checks:
            nagios_plugin3.try_check(check, connection)
