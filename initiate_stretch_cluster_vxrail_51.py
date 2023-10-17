from argparse import ArgumentParser, RawTextHelpFormatter
from getpass import getpass
import requests
import time
import json
import copy
import collections.abc

MASKED_KEYS = ['password']
ESXI_TYPE = 'ESXi'
REQ_VCF_VER = ['5.1']
REQ_NSX_VER_FOR_SUB_TNP = '4.1'
ENABLE_NSX_IP_POOL_VTEP = True
FEATURE_TOGGLE_VXRAIL_STRETCH_SCRIPT_IPPOOL = 'feature.vcf.vxrail.stretch.script.ippool'


def check_sddc_manager_version(sso_username, sso_password):
    sddc_json = get_request('http://localhost/v1/sddc-managers',sso_username, sso_password)
    sddc_ver = None
    for domain in sddc_json['elements']:
        sddc_ver = domain['version'].split("-")[0]
    for req_ver in REQ_VCF_VER:
        if sddc_ver is not None and sddc_ver.startswith(req_ver):
            return
    print('\033[91m Fetched VCF version is {} which is not matching with required version {}'.format(sddc_ver,REQ_VCF_VER))
    print('\033[91m Please make sure the VCF version should be {}'.format(REQ_VCF_VER))
    exit(1)

def check_nsx_version_for_subtnp(nsx_cluster_id, sso_username, sso_password):
    nsx_version = get_nsx_version(nsx_cluster_id, sso_username, sso_password)
    nsx_major_minor_version = float(nsx_version[0:3])
    return nsx_major_minor_version >= float(REQ_NSX_VER_FOR_SUB_TNP)

def is_ip_pool_feature_for_stretch_script_enabled(sso_username, sso_password):
    features = get_request('http://localhost/domainmanager/features/list',
                           sso_username,
                           sso_password)
    return FEATURE_TOGGLE_VXRAIL_STRETCH_SCRIPT_IPPOOL in features.keys() \
           and features[FEATURE_TOGGLE_VXRAIL_STRETCH_SCRIPT_IPPOOL] == "true"

def sso_inputs():
    print()
    sso_username = input("\033[95m Please enter SSO username : \033[00m")
    print()
    sso_password = getpass("\033[95m Please provide SSO password : \033[00m")
    print()
    sso_confirm_password = getpass("\033[95m Please confirm SSO password : \033[00m")
    print()
    if not sso_username or not sso_password or not sso_confirm_password:
        print('\033[91m Please provide sso usename and password. Input field cannot be empty \033[00m')
        exit(1)
    if sso_password != sso_confirm_password:
        print('\033[91m SSO password mismatch. Please enter correct password \033[00m')
        exit(1)
    return sso_username, sso_password


def get_nsx_version(nsx_cluster_id, sso_username, sso_password):
    nsxt_cluster_json = get_request('http://localhost/v1/nsxt-clusters/' + nsx_cluster_id,
                                    sso_username,
                                    sso_password)
    return nsxt_cluster_json['version']

def get_nsx_cluster_id_by_domain_id(domain_id, sso_username, sso_password):
    domain_json = get_request('http://localhost/v1/domains/' + domain_id, sso_username, sso_password)
    return domain_json['nsxtCluster']['id']

def get_network_config_of_cluster(cluster_id, sso_username, sso_password):
    criteria = {'name': 'VCENTER_NSXT_NETWORK_CONFIG'}
    response = post_request(criteria, 'http://localhost/v1/clusters/{0}/network/queries'.format(cluster_id), 
                 sso_username,
                 sso_password)
    query_id = response['queryInfo']['queryId']
    response = get_request('http://localhost/v1/clusters/{0}/network/queries/{1}'.format(cluster_id, query_id), 
                           sso_username, 
                           sso_password)
    while response['queryInfo']['status'] in ['IN_PROGRESS']:
        print('\033[92m Getting current cluster network configuration for auto-population...  \033[00m')
        time.sleep(2)
        response = get_request('http://localhost/v1/clusters/{0}/network/queries/{1}'.format(cluster_id, query_id),
                               sso_username,
                               sso_password)
    if response['queryInfo']['status'] in ['COMPLETED']:
        return response['result']['elements'][0]
    else:
        print('\033[91m Unable to fetch cluster network configuration for auto-population \033[00m')
        exit(1)

def get_domain_and_cluster_id(input_domain_name, input_cluster_name, sso_username, sso_password):
    domains_json = get_request('http://localhost/v1/domains', sso_username, sso_password)

    domain_id = None
    for domain in domains_json['elements']:
        if domain['name'] == input_domain_name:
            domain_id = domain['id']

    clusters_in_domain = [domain['clusters'] for domain in domains_json['elements'] if
                          domain['name'] == input_domain_name]
    if not clusters_in_domain:
        print('\033[91m Incorrect domain name Provided. Please provide correct domain name \033[00m')
        exit(1)
    clusters_in_domain_ids = [cluster['id'] for cluster in clusters_in_domain[0]]

    clusters_json = get_request('http://localhost/v1/clusters', sso_username, sso_password)
    cluster_ids = [cluster['id'] for cluster in clusters_json['elements'] if cluster['name'] == input_cluster_name and
                   cluster['id'] in clusters_in_domain_ids]
    if not cluster_ids:
        print('\033[91m Incorrect cluster name Provided. Please provide correct cluster name \033[00m')
        exit(1)
    return domain_id, cluster_ids[0]

def get_ip_address_pools(nsx_cluster_id, sso_username, sso_password):
    ip_address_pools = get_request('http://localhost/v1/nsxt-clusters/' + nsx_cluster_id + '/ip-address-pools',
                       sso_username, sso_password)
    return ip_address_pools['elements']

def get_ip_address_pool_input(nsx_cluster_id, sso_username, sso_password):
    ip_pool_reuse = input('\033[95m Do you want to reuse existing IP Pool (yes|no): ? \033[00m')
    print()
    if ip_pool_reuse.lower() == "yes":
        ip_address_pools = get_ip_address_pools(nsx_cluster_id, sso_username, sso_password)
        if not ip_address_pools:
            print('\033[91m No IP address pools are existing in NSX. \033[00m')
            exit(1)
        print('\033[95m Please select one static ip pool: \033[00m')
        print(
            '\033[1m -----Pool Name-------------------Subnets---------------------------Available IPs-- \033[0m')
        print(
            "\033[1m ---------------------------------------------------------------------------------- \033[0m")
        count = 0
        ip_pool_map = {}
        for ip_address_pool in ip_address_pools:
            count += 1
            pool_name = '{}) {} : '.format(count, ip_address_pool['name'])
            print('\033[1m ' +
                '{} Static/Block Subnets {}: {}'.format(pool_name, 30 * ' ',
                                                        ip_address_pool['availableIpAddresses']) + ' \033[0m')
            if ip_address_pool['staticSubnets']:
                print('\033[1m {} Static Subnets '.format(len(pool_name) * ' ') + ' \033[0m')
                print("{}\033[36m  -----CIDR-------------IP Ranges-----------".format(len(pool_name) * ' ') + ' \033[0m')
                for static_subnet in ip_address_pool['staticSubnets']:
                    ip_ranges = []
                    for ip_range in static_subnet['ipAddressPoolRanges']:
                        ip_ranges.append('{}-{}'.format(ip_range['start'], ip_range['end']))
                    print("\033[36m  {} {} : {}".format(len(pool_name) * ' ', static_subnet['cidr'], ip_ranges) + ' \033[0m')

            if 'blockSubnets' in ip_address_pool:
                print('\033[1m {} Block Subnets '.format(len(pool_name) * ' ') + ' \033[0m')
                print("{}\033[36m  -----CIDR-------------Size----------------".format(len(pool_name) * ' ') + ' \033[0m')
                for block_subnet in ip_address_pool['blockSubnets']:
                    print("\033[36m  {} {} : {}".format(len(pool_name) * ' ', block_subnet['cidr'],
                                                        block_subnet['size']) + ' \033[0m')
            ip_pool_map[str(count)] = ip_address_pool['name']
        choice = input('\033[95m Enter your choice (number): \033[00m')
        print()
        return {
            'name': ip_pool_map[choice]
        }
    else:
        ip_pool_name = input('\033[95m Please provide ip pool name: \033[00m')
        print()
        if not ip_pool_name:
            print('\033[91m Please provide ip pool name. Input field cannot be empty \033[00m')
            exit(1)
        ip_pool_name = ip_pool_name.strip()
        ip_pool_description = input('\033[95m Please provide ip pool description (optional) : \033[00m')
        print()
        ip_pool_range = input('\033[95m Please provde ip pool range (ex: 10.0.18.30-10.0.18.50) : \033[00m')
        print()
        ip_pool_start_range, ip_pool_end_range = ip_pool_range.strip().split('-')
        if not ip_pool_range and not ip_pool_start_range and not ip_pool_end_range:
            print('\033[91m Please provide valid ip pool range. \033[00m')
            exit(1)
        ip_pool_cidr = input('\033[95m Please provide cidr for the ip pool (ex: 10.0.18.0/24) : \033[00m')
        print()
        if not ip_pool_cidr:
            print('Please provide cidr for the ip pool. Input field cannot be empty')
            exit(1)
        ip_pool_cidr = ip_pool_cidr.strip()
        ip_pool_gateway = input('\033[95m Please provide gateway for the ip pool (ex: 10.0.18.253) : \033[00m')
        print()
        if not ip_pool_gateway:
            print('\033[91m Please provide gateway for the ip pool. Input field cannot be empty \033[00m')
            exit(1)
        ip_pool_gateway = ip_pool_gateway.strip()
        ip_address_pool_spec =  {
            'name': ip_pool_name,
            'subnets': [ {
                "ipAddressPoolRanges": [ {
                    'start': ip_pool_start_range,
                    'end': ip_pool_end_range
                    }
                ],
                'cidr': ip_pool_cidr,
                'gateway': ip_pool_gateway
             }
            ]
        }
        if ip_pool_description:
            ip_address_pool_spec['description'] = ip_pool_description.strip()
        return ip_address_pool_spec

def host_inputs(input_hosts_fqdn, workflow_option):
    hosts_fqdn = [x.strip() for x in input_hosts_fqdn.split(',')]
    hosts_list = []
    for host_fqdn in hosts_fqdn:
        host_password = getpass('\033[95m Please provide root user password for host %s : \033[00m' % host_fqdn)
        print()
        host_confirm_password = getpass('\033[95m Please confirm root user password for host %s : \033[00m' % host_fqdn)
        print()
        if not host_password or not host_confirm_password:
            print('\033[91m Please provide host password. Input field cannot be empty \033[00m')
            exit(1)
        if host_password != host_confirm_password:
            print('\033[91m For host %s, provided password and confirm password is not matching \033[00m' % host_fqdn)
            exit(1)
        if workflow_option == 'stretch-vsan':
            hosts_list.append([host_fqdn, host_password])
        elif workflow_option == 'expand-stretch-cluster':
            host_fault_domain = input('\033[95m Please provide fault domain for host %s : \033[00m' % host_fqdn)
            print()
            if not host_fault_domain:
                print('\033[91m Please provide host fault domain for host ' + host_fqdn +
                      '. Input field cannot be empty \033[00m')
                exit(1)
            hosts_list.append([host_fqdn, host_password, host_fault_domain])
    return hosts_list


def vsan_inputs():
    vsan_spec = []
    vsan_gateway_ip_az1 = input('\033[95m For preferred site: Please enter vSAN Gateway IP (ex: 172.18.93.1) : \033[00m')
    print()
    vsan_cidr_az1 = input('\033[95m For preferred site: Please enter vSAN CIDR (ex: 172.18.93.0/24) : \033[00m')
    print()
    if not vsan_gateway_ip_az1 or not vsan_cidr_az1:
        print('\033[91m Please provide vSAN gateway ip and vSAN CIDR for preferred site. '
              'Input field cannot be empty \033[00m')
        exit(1)
    vsan_spec.append([vsan_gateway_ip_az1, vsan_cidr_az1])
    vsan_gateway_ip_az2 = input('\033[95m For non-preferred site: Please enter vSAN Gateway IP (ex: 172.18.93.1) : '
                                '\033[00m')
    print()
    vsan_cidr_az2 = input('\033[95m For non-preferred site: Please enter vSAN CIDR (ex: 172.18.93.0/24) : \033[00m')
    print()
    if not vsan_gateway_ip_az2 or not vsan_cidr_az2:
        print('\033[91m Please provide vSAN gateway ip and vSAN CIDR for non-preferred site. Input field cannot be '
              'empty \033[00m')
        exit(1)
    vsan_spec.append([vsan_gateway_ip_az2, vsan_cidr_az2])
    return vsan_spec


def get_inputs(sc_hosts, workflow):
    input_hosts_fqdn = sc_hosts
    hosts_list = host_inputs(input_hosts_fqdn, workflow)
    vsan_spec = vsan_inputs()
    return hosts_list, vsan_spec


def main():
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.description = '''\nScript to simplify the configuration of vSAN Stretched Cluster with a VMware Cloud 
Foundation on VxRail Environment:\n\n'''
    parser.add_argument('--workflow', choices=['prepare-stretch', 'stretch-vsan', 'expand-stretch-cluster'],
                        required=True,
                        help='''Provide prepare-stretch, stretch-vsan or expand-stretch-cluster option
\nprepare-stretch: Perform vsan prepare stretch operation workflow,
should be called with following options 
--sc-domain 
--sc-cluster
Later with this option, script will prompt for following inputs
SSO username and SSO password 
\nstretch-vsan: Creates json payload for stretch vsan and executes 
workflow, should be called with following options 
-—sc-domain 
--sc-cluster 
--sc-hosts 
--witness-host-fqdn 
--witness-vsan-ip 
--witness-vsan-cidr 
Later with this option, script will prompt for following inputs
SSO username and SSO password 
ip-address and password for hosts provided with --sc-hosts option   
vSAN gateway ip and vSAN CIDR for preferred site and non-preferred site 
non-preferred site overlay vlan id
static IP pool option for TEP IP assignment(optional)
- If provided yes, option to reuse existing IP pool
- select existing IP pool if reusing existing IP pool
- provide new IP pool name, description(optional), IP pool range, CIDR and gateway for IP pool if not reusing existing IP pool(Creating new static IP pool)
confirm SSH thumbprints for hosts provided with --sc-hosts option
(Check help for supported params to be used for your environment and 
also refer Admin Guide for instructions)
\nexpand-stretch-cluster: Creates json payload for expand workflow, 
this operation is used for expansion of existing stretched cluster.
This operation must be run with 
--sc-domain 
--sc-cluster 
--sc-hosts 
--witness-host-fqdn 
--witness-vsan-ip 
--witness-vsan-cidr 
Later with this option, script will prompt for following inputs
SSO username and SSO password 
ip-address, password and fault domain for hosts provided with --sc-hosts option 
vSAN gateway ip and vSAN CIDR for preferred site and non-preferred site 
confirm SSH thumbprints for hosts provided with --sc-hosts option
(Check help for supported params to be used for your environment and 
also refer Admin Guide for instructions)\n\n''')
    parser.add_argument('--sc-domain', help='Use this domain name for vsan stretch\n\n')
    parser.add_argument('--sc-cluster', help='Use this cluster name for vsan stretch workflow\n\n')
    parser.add_argument('--sc-hosts', help='Use these hosts for vsan stretch workflow (values: should be qualified '
                                           '\ndomain names) Sample: esx1.vsphere.local,esx-2.vsphere.local\n\n')
    parser.add_argument('--witness-host-fqdn', help='Witness Host fully qualified domain name or ip address\n\n')
    parser.add_argument('--witness-vsan-ip', help='Witness Host vsan ip address\n\n')
    parser.add_argument('--witness-vsan-cidr', help='Witness Host vsan cidr')

    args = parser.parse_args()
    if args.workflow == 'prepare-stretch' and args.sc_domain and args.sc_cluster:
        sso_username, sso_password = sso_inputs()
        check_sddc_manager_version(sso_username,sso_password)
        domain_id, cluster_id = get_domain_and_cluster_id(args.sc_domain, args.sc_cluster, sso_username, sso_password)
        prepare_stretch(cluster_id, sso_username, sso_password)
    elif args.workflow == 'stretch-vsan' and args.sc_domain and args.sc_cluster and args.sc_hosts and args.witness_host_fqdn \
            and args.witness_vsan_ip and args.witness_vsan_cidr:
        sso_username, sso_password = sso_inputs()
        check_sddc_manager_version(sso_username,sso_password)
        hosts_list, vsan_spec = get_inputs(args.sc_hosts, args.workflow)
        overlay_vlan_id = input('\033[95m Please enter non-preferred site overlay vlan id : \033[00m')
        if not overlay_vlan_id:
            print('\033[91m Please provide non-preferred site overlay vlan id. Input field cannot be empty \033[00m')
        print()
        domain_id, cluster_id = get_domain_and_cluster_id(args.sc_domain, args.sc_cluster, sso_username, sso_password)
        if ENABLE_NSX_IP_POOL_VTEP and is_ip_pool_feature_for_stretch_script_enabled(sso_username, sso_password):
            nsx_cluster_id = get_nsx_cluster_id_by_domain_id(domain_id, sso_username, sso_password)
            if check_nsx_version_for_subtnp(nsx_cluster_id, sso_username, sso_password):
                ip_assignment_type_static_ip_pool = input('\033[95m Do you want Static IP Pool for TEP IP Assignment? (yes|no): \033[00m')
                print()
                if ip_assignment_type_static_ip_pool and ip_assignment_type_static_ip_pool.lower() == 'yes':
                    ip_address_pool = get_ip_address_pool_input(nsx_cluster_id, sso_username, sso_password)
                    cluster_network_config = get_network_config_of_cluster(cluster_id, sso_username, sso_password)
                    uplink_profiles = cluster_network_config['uplinkProfiles']
                    network_profiles = cluster_network_config['networkProfiles']
                    stretch_vsan_cluster_using_nsx_subtnp(sso_username, sso_password, domain_id, cluster_id, hosts_list, vsan_spec,
                                 args.witness_host_fqdn,
                                 args.witness_vsan_ip, args.witness_vsan_cidr,
                                                          overlay_vlan_id,
                                                          ip_address_pool,
                                                          uplink_profiles,
                                                          network_profiles)
                    return
        stretch_vsan_cluster(sso_username, sso_password, domain_id, cluster_id, hosts_list, vsan_spec,
                             args.witness_host_fqdn,
                             args.witness_vsan_ip, args.witness_vsan_cidr, overlay_vlan_id)
    elif args.workflow == 'expand-stretch-cluster' and args.sc_domain and args.sc_cluster and args.sc_hosts and args.witness_host_fqdn \
            and args.witness_vsan_ip and args.witness_vsan_cidr:
        sso_username, sso_password = sso_inputs()
        check_sddc_manager_version(sso_username,sso_password)
        hosts_list, vsan_spec = get_inputs(args.sc_hosts, args.workflow)
        print()
        domain_id, cluster_id = get_domain_and_cluster_id(args.sc_domain, args.sc_cluster, sso_username, sso_password)
        expand_stretch_cluster(sso_username, sso_password, domain_id, cluster_id, hosts_list, vsan_spec,
                               args.witness_host_fqdn,
                               args.witness_vsan_ip, args.witness_vsan_cidr)
    else:
        print('\033[91m Please provide required arguments for workflow execution. Use -h option for more details')


def prepare_stretch(cluster_id, username, password):
    prepare_stretch_api = 'http://localhost/v1/clusters/' + cluster_id
    prepare_stretch_spec = {"prepareForStretch": True}
    print(' Payload :')
    print(json.dumps(prepare_stretch_spec, indent=2), end='\n\n')
    response = patch_request(payload=prepare_stretch_spec, url=prepare_stretch_api, username=username,
                             password=password)
    print(' Response : {}'.format(response), end='\n\n')
    print('\033[92m Workflow triggered, please track the task status in SDDC Manager UI')


def stretch_vsan_cluster_using_nsx_subtnp(username, password, domain_id, cluster_id, hosts_list, vsan_spec, witness_host_fqdn,
                         witness_vsan_ip, witness_vsan_cidr, overlay_vlan_id, ip_address_pool, 
                                          uplink_profiles,
                                                      network_profiles):
    overlay_vds = get_overlay_vds(cluster_id, username, password)
    default_network_profile = get_default_network_profile(network_profiles)
    overlay_vds_uplink_profile_name = get_overlay_vds_uplink_profile(default_network_profile,
                                                                     overlay_vds)
    network_profile_for_stretch = get_network_profile_for_stretch(default_network_profile,
                                                                  overlay_vds,
                                                          ip_address_pool['name'],
                                                                  cluster_id)
    uplink_profiles_for_stretch = get_uplink_profiles_for_stretch(uplink_profiles,
                                                                  network_profile_for_stretch,
                                                                  overlay_vds_uplink_profile_name,
                                                                  overlay_vlan_id)
    update_network_profile_uplink_profiles_with_az2_prefix(network_profile_for_stretch)
    stretch_validation_spec = {
        "hostSpecs": [],
        "witnessSpec": {
            "vsanIp": witness_vsan_ip,
            "fqdn": witness_host_fqdn,
            "vsanCidr": witness_vsan_cidr
        },
        "vsanNetworkSpecs": [],
        "networkSpec": {
            "nsxClusterSpec": {
                "ipAddressPoolsSpec": [ip_address_pool],
                "uplinkProfiles": uplink_profiles_for_stretch
            },
            "networkProfiles": [
                network_profile_for_stretch
            ]
        }
    }
    fqdn_to_thumbprint_dict = get_ssh_thumbprints(hosts_list, domain_id, username, password)

    for h in hosts_list:
        esxi_id_dict = {'hostName': h[0], "username": "root", 'password': h[1],
                        'sshThumbprint': fqdn_to_thumbprint_dict.get(h[0]),
                        'hostNetworkSpec': {'networkProfileName': network_profile_for_stretch['name']}}
        stretch_validation_spec['hostSpecs'].append(esxi_id_dict)
    for v in vsan_spec:
        vsan_dict = {"vsanGatewayIP": v[0], "vsanCidr": v[1]}
        stretch_validation_spec['vsanNetworkSpecs'].append(vsan_dict)

    payload = {"clusterStretchSpec": stretch_validation_spec}
    payload_copy = copy.deepcopy(payload)
    maskPasswords(payload_copy)
    print(' Payload :')
    print(json.dumps(payload_copy, indent=2), end='\n\n')
    execute_workflow(payload, username, password, cluster_id, 'vSAN stretch cluster')



def stretch_vsan_cluster(username, password, domain_id, cluster_id, hosts_list, vsan_spec, witness_host_fqdn,
                         witness_vsan_ip, witness_vsan_cidr, overlay_vlan_id):
    stretch_validation_spec = {
        "hostSpecs": [],
        "witnessSpec": {
            "vsanIp": witness_vsan_ip,
            "fqdn": witness_host_fqdn,
            "vsanCidr": witness_vsan_cidr
        },
        "vsanNetworkSpecs": [],
        "secondaryAzOverlayVlanId": overlay_vlan_id
    }
    fqdn_to_thumbprint_dict = get_ssh_thumbprints(hosts_list, domain_id, username, password)

    for h in hosts_list:
        esxi_id_dict = {'hostName': h[0], "username": "root", 'password': h[1],
                        'sshThumbprint': fqdn_to_thumbprint_dict.get(h[0])}
        stretch_validation_spec['hostSpecs'].append(esxi_id_dict)
    for v in vsan_spec:
        vsan_dict = {"vsanGatewayIP": v[0], "vsanCidr": v[1]}
        stretch_validation_spec['vsanNetworkSpecs'].append(vsan_dict)

    payload = {"clusterStretchSpec": stretch_validation_spec}
    payload_copy = copy.deepcopy(payload)
    maskPasswords(payload_copy)
    print(' Payload :')
    print(json.dumps(payload_copy, indent=2), end='\n\n')
    execute_workflow(payload, username, password, cluster_id, 'vSAN stretch cluster')

def get_overlay_vds(cluster_id, username, password):
    cluster_vdses = get_request('http://localhost/v1/clusters/{0}/vdses'.format(cluster_id),
                                username,
                                password)
    for vds in cluster_vdses:
        if 'nsxtSwitchConfig' in vds.keys() and vds['nsxtSwitchConfig']:
            transport_zone_types = [transport_zone['transportType'] for transport_zone in
                                     vds['nsxtSwitchConfig']['transportZones']]
            if 'OVERLAY' in transport_zone_types:
                return vds['name']

        if 'isUsedByNsxt' in vds.keys() and vds['isUsedByNsxt']:
            return vds['name']
    print('\033[91m Unable to find VDS used for Overlay \033[00m')
    exit(1)

def get_overlay_vds_uplink_profile(network_profile, overlay_vds):
    for nsx_host_switch_config in network_profile['nsxtHostSwitchConfigs']:
        if nsx_host_switch_config['vdsName'] == overlay_vds:
            return nsx_host_switch_config['uplinkProfileName']
    print('\033[91m Unable to find uplink profile for overlay VDS \033[00m')
    exit(1)

def get_uplink_profiles_names(network_profile):
    uplinks_profile_names = []
    for nsx_host_switch_config in network_profile['nsxtHostSwitchConfigs']:
        uplinks_profile_names.append(nsx_host_switch_config['uplinkProfileName'])
    return uplinks_profile_names

def get_uplink_profiles_for_stretch(uplink_profiles, network_profile_for_stretch,
                                    overlay_vds_uplink_profile_name, overlay_vlan_id):
    uplink_profiles_for_stretch = []
    uplink_profile_names = get_uplink_profiles_names(network_profile_for_stretch)
    for uplink_profile in uplink_profiles:
        if uplink_profile['name'] in uplink_profile_names:
            uplink_profile_for_stretch = copy.deepcopy(uplink_profile)
            if uplink_profile_for_stretch['name'] == overlay_vds_uplink_profile_name:
                uplink_profile_for_stretch['transportVlan'] = overlay_vlan_id
            uplink_profile_for_stretch['name'] = 'az2_' + uplink_profile_for_stretch['name']
            del uplink_profile_for_stretch['supportedTeamingPolicies']
            uplink_profiles_for_stretch.append(uplink_profile_for_stretch)
    return uplink_profiles_for_stretch

def get_default_network_profile(network_profiles):
    for network_profile in network_profiles:
        if 'isDefault' in network_profile.keys() and \
                network_profile['isDefault']:
            return network_profile
    print("\033[91m Unable to find default network profile \033[00m")
    exit(1)
    
def get_network_profile_for_stretch(network_profile, overlay_vds,
                                    ip_address_pool_name, cluster_id):
    network_profile_for_stretch= copy.deepcopy(network_profile)
        
    network_profile_for_stretch['isDefault'] = False
    network_profile_for_stretch['name'] = 'az2-sub-transport-node-profile-' + cluster_id
    for nsxt_host_switch_config in network_profile_for_stretch['nsxtHostSwitchConfigs']:
        if nsxt_host_switch_config['vdsName'] == overlay_vds:
            nsxt_host_switch_config['ipAddressPoolName'] = ip_address_pool_name
            return network_profile_for_stretch
    print("\033[91m Unable to find nsxt host switch config details for overlay vds in network profile \033[00m")
    exit(1)

def update_network_profile_uplink_profiles_with_az2_prefix(network_profile):
    for nsx_host_switch_config in network_profile['nsxtHostSwitchConfigs']:
        nsx_host_switch_config['uplinkProfileName'] = 'az2_' + nsx_host_switch_config['uplinkProfileName']

def get_ssh_thumbprints(hosts_list, domain_id, username, password):
    post_url = 'http://localhost/domainmanager/vxrail/hosts/unmananged/fingerprint'
    payload = {
        "sshFingerprints": [],
        "domainId": domain_id
    }
    for host in hosts_list:
        payload['sshFingerprints'].append({'fqdn': host[0], 'userName': 'root', 'password': host[1], 'type': ESXI_TYPE})
    print('\033[92m Getting the thumbprints for hosts...\033[00m', end="\n\n")
    response = post_request(payload, post_url, username, password)

    get_url = 'http://localhost/domainmanager/vxrail/hosts/requests/' + response['id']
    thumbprints_response = get_poll_request_for_fingerprints(get_url, username, password)

    fqdn_to_thumbprint_dict = {}
    for thumbprint_response in thumbprints_response['sshFingerprints']:
        fqdn_to_thumbprint_dict[thumbprint_response['id']] = thumbprint_response['fingerPrint']

    display_and_confirm_ssh_thumbprints(fqdn_to_thumbprint_dict)

    return fqdn_to_thumbprint_dict


def display_and_confirm_ssh_thumbprints(fqdn_to_thumbprint_dict):
    print('\033[95m Please confirm SSH Thumbprint of Hosts :\033[00m')
    print('\033[36m -----------FQDN--------------------------Fingerprint-----------------------------')
    print('\033[36m ---------------------------------------------------------------------------------')
    for fqdn_to_thumbprint in fqdn_to_thumbprint_dict:
        print('\033[36m {} : {} \033[00m'.format(fqdn_to_thumbprint, fqdn_to_thumbprint_dict[fqdn_to_thumbprint]))
    selected_option = input("\033[95m Enter your choice ('yes' or 'no') : \033[00m")
    print('\n\n')
    if selected_option.lower() == 'no':
        print('\033[91m Fingerprints are not confirmed so exiting...\033[00m', end="\n\n\n")
        exit(1)


def execute_workflow(payload, username, password, cluster_id, workflow_name):
    url = 'http://localhost/v1/clusters/'
    validation_url = url + cluster_id + '/validations'
    print('\033[95m validation_url : \033[0m' + validation_url, end='\n\n')
    response = post_request(payload, validation_url, username, password)
    print('\033[95m Validation started for {} workflow. Validation response id : \033[0m'.format(workflow_name) + response['id'],
          end='\n\n')

    stretch_validation_poll_url = url + 'validations/' + response['id']
    print('\033[95m stretch_validation_poll_url : \033[0m' + stretch_validation_poll_url, end='\n\n')
    get_poll_request(stretch_validation_poll_url, username, password)
    print('\033[92m Validation completed successfully for {} workflow \033[0m'.format(workflow_name), end='\n\n')

    input("\033[1m Enter to continue ...\033[0m")
    print()

    print('\033[95m Triggering ' + workflow_name + ' workflow...', end='\n\n')
    execution_url = url + cluster_id
    print('\033[95m execution_url : \033[0m' + execution_url, end='\n\n')
    response = patch_request(payload, execution_url, username, password)
    print(response, end='\n\n')
    print('\033[92m Workflow triggered, please track the task status in SDDC Manager UI')


def expand_stretch_cluster(username, password, domain_id, cluster_id, hosts_list, vsan_spec, witness_host_fqdn,
                           witness_vsan_ip, witness_vsan_cidr):
    stretch_expansion_spec = {
        "hostSpecs": [],
        "witnessSpec": {
            "vsanIp": witness_vsan_ip,
            "fqdn": witness_host_fqdn,
            "vsanCidr": witness_vsan_cidr
        },
        "vsanNetworkSpecs": []
    }

    fqdn_to_thumbprint_dict = get_ssh_thumbprints(hosts_list, domain_id, username, password)

    for h in hosts_list:
        esxi_id_dict = {'hostName': h[0], "username": "root", 'password': h[1], 'azName': h[2],
                        'sshThumbprint': fqdn_to_thumbprint_dict.get(h[0])}
        stretch_expansion_spec['hostSpecs'].append(esxi_id_dict)
    for v in vsan_spec:
        vsan_dict = {"vsanGatewayIP": v[0], "vsanCidr": v[1]}
        stretch_expansion_spec['vsanNetworkSpecs'].append(vsan_dict)

    payload = {"clusterExpansionSpec": stretch_expansion_spec}
    payload_copy = copy.deepcopy(payload)
    maskPasswords(payload_copy)
    print('Payload :')
    print(json.dumps(payload_copy, indent=2), end='\n\n')
    execute_workflow(payload, username, password, cluster_id, 'expand stretch cluster')


def get_poll_request_for_fingerprints(url, username, password):
    response = get_request(url, username, password)
    while response['status'] in ['In Progress', 'IN_PROGRESS', 'Pending']:
        time.sleep(2)
        response = get_request(url, username, password)

    if response['status'] == 'COMPLETED':
        return response
    else:
        print('\033[91m Failed to get thumbprints \033[00m', end='\n\n')
        print(' Response : {}'.format(response))
        exit(1)


def get_token(username, password):
    payload = {"username": username, "password": password}
    header = {'Content-Type': 'application/json'}
    token_url = 'http://localhost/v1/tokens'
    response = requests.post(token_url, headers=header, json=payload, verify=False)
    if response.status_code in [200, 202]:
        data = json.loads(response.text)
    else:
        print("\033[91m Error reaching the server.\033[00m")
        print(response.text)
        exit(1)
    token = data['accessToken']
    header['Authorization'] = 'Bearer ' + token
    return header


def get_request(url, username, password):
    header = get_token(username, password)
    response = requests.get(url, headers=header, verify=False)
    if response.status_code == 200:
        data = json.loads(response.text)
    else:
        print("\033[91m Error reaching the server. \033[00m")
        exit(1)
    return data


def post_request(payload, url, username, password):
    header = get_token(username, password)
    response = requests.post(url, headers=header, json=payload, verify=False)
    if response.status_code in [200, 202]:
        data = json.loads(response.text)
        return data
    else:
        print("\033[91m Error reaching the server.\033[00m")
        print(response.text)
        exit(1)


def patch_request(payload, url, username, password):
    header = get_token(username, password)
    response = requests.patch(url, headers=header, json=payload, verify=False)
    if response.status_code in [200, 202]:
        data = json.loads(response.text)
        return data
    else:
        print("\033[91m Error reaching the server.\033[00m")
        print(response.text)
        exit(1)


def get_poll_request(url, username, password):
    response = get_request(url, username, password)
    while response['executionStatus'] in ['In Progress', 'IN_PROGRESS', 'Pending']:
        print('\033[36m Validation is in progress... \033[00m', end='\n\n')
        time.sleep(10)
        response = get_request(url, username, password)

    if response['executionStatus'] == 'COMPLETED' and response['resultStatus'] == 'SUCCEEDED':
        print('\033[92m Validation ended with status %s \033[00m' % response['resultStatus'], end='\n\n')
        return
    else:
        print('\033[91m Validation ended with status %s' % response['resultStatus'], end='\n\n')
        print('\033[91m Validation Failed \033[00m')
        print_response(response)
        exit(1)


def print_response(response):
    for s in response['validationChecks']:
        if s['resultStatus'] == 'FAILED':
            if 'description' and 'errorResponse' in s:
                if 'errorCode' in s['errorResponse']:
                    print(' Validation is failed in task : "%s" with ErrorCode : "%s"' % (
                        s['description'], s['errorResponse']['errorCode']))
            if 'description' in s and 'errorResponse' not in s:
                print(' Validation is failed in task : "%s"' % s['description'])
            if 'errorResponse' in s:
                if 'message' in s['errorResponse']:
                    print('message : %s' % s['errorResponse']['message'])


def maskPasswords(obj):
    if isinstance(obj, str):
        return obj
    for k, v in obj.items():
        if isinstance(v, collections.abc.Mapping):
            obj[k] = maskPasswords(v)
        elif isinstance(v, list):
            for elem in v:
                maskPasswords(elem)
        elif k in MASKED_KEYS:
            obj[k] = '*******'
        else:
            obj[k] = v
    return obj


if __name__ == "__main__":
    main()
